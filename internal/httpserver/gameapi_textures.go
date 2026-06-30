// SPDX-License-Identifier: Apache-2.0

// Package httpserver: this file implements the authlib-injector game-facing texture API
// (Bearer-authenticated upload and clear), mounted under the Yggdrasil API prefix.
package httpserver

import (
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/achetronic/minecrauth/internal/textures"
)

// dashUUID inserts the canonical 8-4-4-4-12 hyphens into a 32-hex-character UUID string.
// authlib-injector sends profile UUIDs unhyphenated on the wire while players are stored in
// canonical dashed form. If the input length is not 32 it is returned unchanged.
func dashUUID(hex string) string {
	if len(hex) != 32 {
		return hex
	}
	return hex[0:8] + "-" + hex[8:12] + "-" + hex[12:16] + "-" + hex[16:20] + "-" + hex[20:32]
}

// bearerUserID extracts and validates the Bearer access token, returning the owning user ID.
// On any failure it writes a 401 response and returns ok=false.
func (mh *managementHandler) bearerUserID(w http.ResponseWriter, r *http.Request) (string, bool) {
	const prefix = "Bearer "
	authz := r.Header.Get("Authorization")
	if !strings.HasPrefix(authz, prefix) {
		writeErrorJSON(w, http.StatusUnauthorized, "Unauthorized", "missing or malformed Authorization header")
		return "", false
	}
	accessToken := strings.TrimSpace(strings.TrimPrefix(authz, prefix))
	if accessToken == "" {
		writeErrorJSON(w, http.StatusUnauthorized, "Unauthorized", "empty access token")
		return "", false
	}
	tok, err := mh.tokens.Lookup(r.Context(), accessToken)
	if err != nil {
		writeErrorJSON(w, http.StatusUnauthorized, "Unauthorized", "invalid access token")
		return "", false
	}
	return tok.UserID, true
}

// gameProfileOwner resolves the path uuid to a local player and verifies it belongs to userID.
// On failure it writes a 404 (to avoid leaking other users' players) and returns ok=false.
func (mh *managementHandler) gameProfileOwner(w http.ResponseWriter, r *http.Request, userID string) (string, bool) {
	player, err := mh.svc.GetPlayerByUUID(r.Context(), dashUUID(r.PathValue("uuid")))
	if err != nil {
		writeErrorJSON(w, http.StatusNotFound, "NotFound", "profile not found")
		return "", false
	}
	if player.UserID != userID {
		writeErrorJSON(w, http.StatusNotFound, "NotFound", "profile not found")
		return "", false
	}
	return player.ID, true
}

// handleGameUploadTexture handles PUT {yggprefix}/api/user/profile/{uuid}/{textureType}.
// Bearer-authenticated, multipart/form-data body with a PNG "file" and (for skins) a "model".
func (mh *managementHandler) handleGameUploadTexture(w http.ResponseWriter, r *http.Request) {
	textureType := r.PathValue("textureType")
	if textureType != "skin" && textureType != "cape" {
		writeErrorJSON(w, http.StatusBadRequest, "BadRequest", "textureType must be skin or cape")
		return
	}
	if mh.textures == nil {
		writeErrorJSON(w, http.StatusServiceUnavailable, "Unavailable", "texture storage not configured")
		return
	}
	if textureType == "skin" && (mh.cfg == nil || !mh.cfg.AllowSkins) {
		writeErrorJSON(w, http.StatusForbidden, "Forbidden", "skin uploads are disabled")
		return
	}
	if textureType == "cape" && (mh.cfg == nil || !mh.cfg.AllowCapes) {
		writeErrorJSON(w, http.StatusForbidden, "Forbidden", "cape uploads are disabled")
		return
	}

	userID, ok := mh.bearerUserID(w, r)
	if !ok {
		return
	}
	playerID, ok := mh.gameProfileOwner(w, r, userID)
	if !ok {
		return
	}

	// The total body size is already capped by the bodyLimit middleware.
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		writeErrorJSON(w, http.StatusBadRequest, "BadRequest", "failed to parse multipart form")
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		writeErrorJSON(w, http.StatusBadRequest, "BadRequest", "missing file part")
		return
	}
	defer func() { _ = file.Close() }()

	data, err := io.ReadAll(file)
	if err != nil {
		writeErrorJSON(w, http.StatusBadRequest, "BadRequest", "failed to read file part")
		return
	}

	sanitized, img, err := textures.DecodeAndSanitize(data)
	if err != nil {
		writeErrorJSON(w, http.StatusBadRequest, "BadRequest", "file is not a valid PNG image: "+err.Error())
		return
	}

	if textureType == "cape" {
		if err := textures.ValidateCape(img); err != nil {
			writeErrorJSON(w, http.StatusBadRequest, "BadRequest", err.Error())
			return
		}
		hash, err := mh.textures.Put(sanitized)
		if err != nil {
			slog.Error("handleGameUploadTexture: storing cape", "error", err)
			writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
			return
		}
		if err := mh.svc.SetPlayerCape(r.Context(), playerID, hash); err != nil {
			slog.Error("handleGameUploadTexture: setting cape", "error", err)
			writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// skin
	if err := textures.ValidateSkin(img, mh.cfg.SkinSizeLimit); err != nil {
		writeErrorJSON(w, http.StatusBadRequest, "BadRequest", err.Error())
		return
	}
	// Per the spec the model field is "slim" or empty; empty means the normal (classic) model.
	model := strings.TrimSpace(r.FormValue("model"))
	switch model {
	case "":
		model = "classic"
	case "slim":
		// keep as-is
	default:
		writeErrorJSON(w, http.StatusBadRequest, "BadRequest", "model must be slim or empty")
		return
	}
	hash, err := mh.textures.Put(sanitized)
	if err != nil {
		slog.Error("handleGameUploadTexture: storing skin", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	if err := mh.svc.SetPlayerSkin(r.Context(), playerID, hash, model); err != nil {
		slog.Error("handleGameUploadTexture: setting skin", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleGameDeleteTexture handles DELETE {yggprefix}/api/user/profile/{uuid}/{textureType}.
// Bearer-authenticated; clears the skin or cape so it reverts to default.
func (mh *managementHandler) handleGameDeleteTexture(w http.ResponseWriter, r *http.Request) {
	textureType := r.PathValue("textureType")
	if textureType != "skin" && textureType != "cape" {
		writeErrorJSON(w, http.StatusBadRequest, "BadRequest", "textureType must be skin or cape")
		return
	}
	userID, ok := mh.bearerUserID(w, r)
	if !ok {
		return
	}
	playerID, ok := mh.gameProfileOwner(w, r, userID)
	if !ok {
		return
	}
	var err error
	if textureType == "skin" {
		err = mh.svc.ClearPlayerSkin(r.Context(), playerID)
	} else {
		err = mh.svc.ClearPlayerCape(r.Context(), playerID)
	}
	if err != nil {
		slog.Error("handleGameDeleteTexture: clearing texture", "type", textureType, "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
