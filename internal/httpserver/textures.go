// SPDX-License-Identifier: Apache-2.0

// Package httpserver: this file contains the skin and cape texture upload,
// URL-fetch, and delete handlers for the management API.
package httpserver

import (
	"errors"
	"image"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/achetronic/minecrauth/internal/accounts"
	"github.com/achetronic/minecrauth/internal/textures"
)

// ownerCheck fetches the player and verifies it belongs to the authenticated user.
// On success it returns the player ID to use. On any failure it writes the appropriate
// HTTP error response and returns false so the caller can return immediately.
func (mh *managementHandler) ownerCheck(w http.ResponseWriter, r *http.Request) (playerID string, ok bool) {
	user, _ := userFromContext(r.Context())
	playerID = r.PathValue("id")

	player, err := mh.svc.GetPlayer(r.Context(), playerID)
	if err != nil {
		if errors.Is(err, accounts.ErrNotFound) {
			writeErrorJSON(w, http.StatusNotFound, "NotFound", "player not found")
			return "", false
		}
		slog.Error("ownerCheck: getting player", "id", playerID, "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return "", false
	}
	if player.UserID != user.ID {
		// Return 404 rather than 403 to avoid leaking the existence of another user's player.
		writeErrorJSON(w, http.StatusNotFound, "NotFound", "player not found")
		return "", false
	}
	return playerID, true
}

// handleUploadSkin handles PUT /me/players/{id}/skin.
// The request body must be raw PNG bytes. Query param ?model=classic|slim (default: classic).
// @Summary      Upload player skin
// @Description  Uploads a new PNG skin file for the player profile. (Requires AllowSkins config flag to be true)
// @Tags         Skins
// @Accept       image/png
// @Produce      json
// @Param        id path string true "Player ID"
// @Param        model query string false "Skin model (classic or slim)"
// @Success      200 {object} store.Player
// @Failure      400 {object} APIError
// @Failure      401 {object} APIError
// @Failure      403 {object} APIError
// @Failure      404 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /api/me/players/{id}/skin [put]
func (mh *managementHandler) handleUploadSkin(w http.ResponseWriter, r *http.Request) {
	if mh.cfg == nil || !mh.cfg.AllowSkins {
		writeErrorJSON(w, http.StatusForbidden, "Forbidden", "skin uploads are disabled")
		return
	}
	if mh.textures == nil {
		writeErrorJSON(w, http.StatusServiceUnavailable, "Unavailable", "texture storage not configured")
		return
	}

	playerID, ok := mh.ownerCheck(w, r)
	if !ok {
		return
	}

	model := r.URL.Query().Get("model")
	if model != "" && model != "classic" && model != "slim" {
		writeErrorJSON(w, http.StatusBadRequest, "BadRequest", "model must be classic or slim")
		return
	}

	pngBytes, img, readOK := readAndDecodePNG(w, r.Body)
	if !readOK {
		return
	}
	if err := textures.ValidateSkin(img, mh.cfg.SkinSizeLimit); err != nil {
		writeErrorJSON(w, http.StatusBadRequest, "BadRequest", err.Error())
		return
	}
	// When the client does not specify a model, detect it from the texture.
	if model == "" {
		model = textures.DetectModel(img)
	}

	hash, err := mh.textures.Put(pngBytes)
	if err != nil {
		slog.Error("handleUploadSkin: storing texture", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}

	if err := mh.svc.SetPlayerSkin(r.Context(), playerID, hash, model); err != nil {
		slog.Error("handleUploadSkin: setting skin", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}

	player, err := mh.svc.GetPlayer(r.Context(), playerID)
	if err != nil {
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, player)
}

// handleUploadSkinURL handles PUT /me/players/{id}/skin/url.
// Body: {"url":"...","model":"classic|slim"}. Requires AllowTextureFromURL config flag.
// @Summary      Upload player skin from URL
// @Description  Downloads a PNG skin file from the specified URL and sets it for the player profile. (Requires AllowSkins config flag to be true)
// @Tags         Skins
// @Accept       json
// @Produce      json
// @Param        id path string true "Player ID"
// @Param        request body SkinURLRequest true "Skin URL configuration"
// @Success      200 {object} store.Player
// @Failure      400 {object} APIError
// @Failure      401 {object} APIError
// @Failure      403 {object} APIError
// @Failure      404 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /api/me/players/{id}/skin/url [put]
func (mh *managementHandler) handleUploadSkinURL(w http.ResponseWriter, r *http.Request) {
	if mh.cfg == nil || !mh.cfg.AllowSkins {
		writeErrorJSON(w, http.StatusForbidden, "Forbidden", "skin uploads are disabled")
		return
	}
	if mh.cfg == nil || !mh.cfg.AllowTextureFromURL {
		writeErrorJSON(w, http.StatusForbidden, "Forbidden", "texture upload by URL is disabled")
		return
	}
	if mh.textures == nil {
		writeErrorJSON(w, http.StatusServiceUnavailable, "Unavailable", "texture storage not configured")
		return
	}

	playerID, ok := mh.ownerCheck(w, r)
	if !ok {
		return
	}

	var req SkinURLRequest
	if !decodeRequest(w, r, &req) {
		return
	}
	if req.URL == "" {
		writeErrorJSON(w, http.StatusBadRequest, "BadRequest", "url is required")
		return
	}
	if req.Model != "" && req.Model != "classic" && req.Model != "slim" {
		writeErrorJSON(w, http.StatusBadRequest, "BadRequest", "model must be classic or slim")
		return
	}

	pngBytes, img, fetchOK := fetchURL(w, req.URL, mh.cfg.BodyLimitBytes)
	if !fetchOK {
		return
	}
	if err := textures.ValidateSkin(img, mh.cfg.SkinSizeLimit); err != nil {
		writeErrorJSON(w, http.StatusBadRequest, "BadRequest", err.Error())
		return
	}
	if req.Model == "" {
		req.Model = textures.DetectModel(img)
	}

	hash, err := mh.textures.Put(pngBytes)
	if err != nil {
		slog.Error("handleUploadSkinURL: storing texture", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}

	if err := mh.svc.SetPlayerSkin(r.Context(), playerID, hash, req.Model); err != nil {
		slog.Error("handleUploadSkinURL: setting skin", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}

	player, err := mh.svc.GetPlayer(r.Context(), playerID)
	if err != nil {
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, player)
}

// handleDeleteSkin handles DELETE /me/players/{id}/skin. Clears the player's skin.
// @Summary      Delete player skin
// @Description  Clears the skin for the player profile.
// @Tags         Skins
// @Produce      json
// @Param        id path string true "Player ID"
// @Success      200 {object} store.Player
// @Failure      401 {object} APIError
// @Failure      403 {object} APIError
// @Failure      404 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /api/me/players/{id}/skin [delete]
func (mh *managementHandler) handleDeleteSkin(w http.ResponseWriter, r *http.Request) {
	if mh.cfg == nil || !mh.cfg.AllowSkins {
		writeErrorJSON(w, http.StatusForbidden, "Forbidden", "skin management is disabled")
		return
	}
	playerID, ok := mh.ownerCheck(w, r)
	if !ok {
		return
	}
	if err := mh.svc.ClearPlayerSkin(r.Context(), playerID); err != nil {
		if errors.Is(err, accounts.ErrNotFound) {
			writeErrorJSON(w, http.StatusNotFound, "NotFound", "player not found")
			return
		}
		slog.Error("handleDeleteSkin: clearing skin", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleSetSkinModel handles PUT /me/players/{id}/skin/model.
// Body: {"model":"classic|slim"}. Changes only the arm model of an existing skin.
// @Summary      Set player skin model
// @Description  Overrides the arm model (classic or slim) of the player's existing skin without re-uploading.
// @Tags         Skins
// @Accept       json
// @Produce      json
// @Param        id path string true "Player ID"
// @Param        request body SetSkinModelRequest true "Skin model"
// @Success      200 {object} store.Player
// @Failure      400 {object} APIError
// @Failure      401 {object} APIError
// @Failure      404 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /api/me/players/{id}/skin/model [put]
func (mh *managementHandler) handleSetSkinModel(w http.ResponseWriter, r *http.Request) {
	playerID, ok := mh.ownerCheck(w, r)
	if !ok {
		return
	}
	var req SetSkinModelRequest
	if !decodeRequest(w, r, &req) {
		return
	}
	if req.Model != "classic" && req.Model != "slim" {
		writeErrorJSON(w, http.StatusBadRequest, "BadRequest", "model must be classic or slim")
		return
	}
	if err := mh.svc.SetPlayerSkinModel(r.Context(), playerID, req.Model); err != nil {
		if errors.Is(err, accounts.ErrNotFound) {
			writeErrorJSON(w, http.StatusNotFound, "NotFound", "player or skin not found")
			return
		}
		slog.Error("handleSetSkinModel: setting model", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	player, err := mh.svc.GetPlayer(r.Context(), playerID)
	if err != nil {
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, player)
}

// handleUploadCape handles PUT /me/players/{id}/cape.
// The request body must be raw PNG bytes (capes have no model parameter).
// @Summary      Upload player cape
// @Description  Uploads a new PNG cape file for the player profile. (Requires AllowCapes config flag to be true)
// @Tags         Capes
// @Accept       image/png
// @Produce      json
// @Param        id path string true "Player ID"
// @Success      200 {object} store.Player
// @Failure      400 {object} APIError
// @Failure      401 {object} APIError
// @Failure      403 {object} APIError
// @Failure      404 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /api/me/players/{id}/cape [put]
func (mh *managementHandler) handleUploadCape(w http.ResponseWriter, r *http.Request) {
	if mh.cfg == nil || !mh.cfg.AllowCapes {
		writeErrorJSON(w, http.StatusForbidden, "Forbidden", "cape uploads are disabled")
		return
	}
	if mh.textures == nil {
		writeErrorJSON(w, http.StatusServiceUnavailable, "Unavailable", "texture storage not configured")
		return
	}

	playerID, ok := mh.ownerCheck(w, r)
	if !ok {
		return
	}

	pngBytes, img, readOK := readAndDecodePNG(w, r.Body)
	if !readOK {
		return
	}
	if err := textures.ValidateCape(img); err != nil {
		writeErrorJSON(w, http.StatusBadRequest, "BadRequest", err.Error())
		return
	}

	hash, err := mh.textures.Put(pngBytes)
	if err != nil {
		slog.Error("handleUploadCape: storing texture", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}

	if err := mh.svc.SetPlayerCape(r.Context(), playerID, hash); err != nil {
		slog.Error("handleUploadCape: setting cape", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}

	player, err := mh.svc.GetPlayer(r.Context(), playerID)
	if err != nil {
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, player)
}

// handleUploadCapeURL handles PUT /me/players/{id}/cape/url.
// Body: {"url":"..."}. Requires AllowTextureFromURL config flag.
// @Summary      Upload player cape from URL
// @Description  Downloads a PNG cape file from the specified URL and sets it for the player profile. (Requires AllowCapes config flag to be true)
// @Tags         Capes
// @Accept       json
// @Produce      json
// @Param        id path string true "Player ID"
// @Param        request body CapeURLRequest true "Cape URL configuration"
// @Success      200 {object} store.Player
// @Failure      400 {object} APIError
// @Failure      401 {object} APIError
// @Failure      403 {object} APIError
// @Failure      404 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /api/me/players/{id}/cape/url [put]
func (mh *managementHandler) handleUploadCapeURL(w http.ResponseWriter, r *http.Request) {
	if mh.cfg == nil || !mh.cfg.AllowCapes {
		writeErrorJSON(w, http.StatusForbidden, "Forbidden", "cape uploads are disabled")
		return
	}
	if mh.cfg == nil || !mh.cfg.AllowTextureFromURL {
		writeErrorJSON(w, http.StatusForbidden, "Forbidden", "texture upload by URL is disabled")
		return
	}
	if mh.textures == nil {
		writeErrorJSON(w, http.StatusServiceUnavailable, "Unavailable", "texture storage not configured")
		return
	}

	playerID, ok := mh.ownerCheck(w, r)
	if !ok {
		return
	}

	var req CapeURLRequest
	if !decodeRequest(w, r, &req) {
		return
	}
	if req.URL == "" {
		writeErrorJSON(w, http.StatusBadRequest, "BadRequest", "url is required")
		return
	}

	pngBytes, img, fetchOK := fetchURL(w, req.URL, mh.cfg.BodyLimitBytes)
	if !fetchOK {
		return
	}
	if err := textures.ValidateCape(img); err != nil {
		writeErrorJSON(w, http.StatusBadRequest, "BadRequest", err.Error())
		return
	}

	hash, err := mh.textures.Put(pngBytes)
	if err != nil {
		slog.Error("handleUploadCapeURL: storing texture", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}

	if err := mh.svc.SetPlayerCape(r.Context(), playerID, hash); err != nil {
		slog.Error("handleUploadCapeURL: setting cape", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}

	player, err := mh.svc.GetPlayer(r.Context(), playerID)
	if err != nil {
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, player)
}

// handleDeleteCape handles DELETE /me/players/{id}/cape. Clears the player's cape.
// @Summary      Delete player cape
// @Description  Clears the cape for the player profile.
// @Tags         Capes
// @Produce      json
// @Param        id path string true "Player ID"
// @Success      200 {object} store.Player
// @Failure      401 {object} APIError
// @Failure      403 {object} APIError
// @Failure      404 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /api/me/players/{id}/cape [delete]
func (mh *managementHandler) handleDeleteCape(w http.ResponseWriter, r *http.Request) {
	if mh.cfg == nil || !mh.cfg.AllowCapes {
		writeErrorJSON(w, http.StatusForbidden, "Forbidden", "cape management is disabled")
		return
	}
	playerID, ok := mh.ownerCheck(w, r)
	if !ok {
		return
	}
	if err := mh.svc.ClearPlayerCape(r.Context(), playerID); err != nil {
		if errors.Is(err, accounts.ErrNotFound) {
			writeErrorJSON(w, http.StatusNotFound, "NotFound", "player not found")
			return
		}
		slog.Error("handleDeleteCape: clearing cape", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// readAndDecodePNG reads the entire body, validates and sanitizes it as a PNG image.
// The body is already capped by the bodyLimit middleware upstream.
// On error it writes the appropriate HTTP error response and returns false.
// On success it returns the sanitized PNG bytes and the decoded image.
func readAndDecodePNG(w http.ResponseWriter, body io.Reader) ([]byte, image.Image, bool) {
	data, err := io.ReadAll(body)
	if err != nil {
		writeErrorJSON(w, http.StatusBadRequest, "BadRequest", "failed to read request body")
		return nil, nil, false
	}
	sanitized, img, err := textures.DecodeAndSanitize(data)
	if err != nil {
		writeErrorJSON(w, http.StatusBadRequest, "BadRequest", "request body is not a valid PNG image: "+err.Error())
		return nil, nil, false
	}
	return sanitized, img, true
}

// fetchURL fetches a PNG from rawURL with a 30-second timeout, caps the body to
// limitBytes bytes, and decodes it as a PNG image.
// On any error it writes an HTTP error response and returns false.
func fetchURL(w http.ResponseWriter, rawURL string, limitBytes int) ([]byte, image.Image, bool) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(rawURL) //nolint:noctx
	if err != nil {
		writeErrorJSON(w, http.StatusBadRequest, "BadRequest", "failed to fetch texture URL")
		return nil, nil, false
	}
	defer func() { _ = resp.Body.Close() }()

	cap := int64(limitBytes)
	if cap <= 0 {
		cap = 1 << 20 // 1 MiB safety cap when no limit is configured
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, cap))
	if err != nil {
		writeErrorJSON(w, http.StatusBadRequest, "BadRequest", "failed to read texture from URL")
		return nil, nil, false
	}

	sanitized, img, err := textures.DecodeAndSanitize(data)
	if err != nil {
		writeErrorJSON(w, http.StatusBadRequest, "BadRequest", "texture URL did not return a valid PNG image: "+err.Error())
		return nil, nil, false
	}
	return sanitized, img, true
}
