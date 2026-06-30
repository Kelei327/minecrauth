// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

package httpserver

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image/color"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/achetronic/minecrauth/internal/accounts"
	"github.com/achetronic/minecrauth/internal/auth"
	"github.com/achetronic/minecrauth/internal/backup"
	"github.com/achetronic/minecrauth/internal/config"
	"github.com/achetronic/minecrauth/internal/mailer"
	"github.com/achetronic/minecrauth/internal/store"
	"github.com/achetronic/minecrauth/internal/textures"
	"github.com/skip2/go-qrcode"
)

// APIError is the JSON envelope for all management API error responses.
type APIError struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// writeErrorJSON writes a JSON error response with the given HTTP status code.
func writeErrorJSON(w http.ResponseWriter, status int, errCode, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(APIError{Error: errCode, Message: message})
}

// writeJSON writes v as a JSON response with the given HTTP status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("writeJSON: encoding response", "error", err)
	}
}

// decodeRequest decodes the JSON request body into v. Returns false and writes an
// appropriate error response when decoding fails. Distinguishes body-too-large errors
// (*http.MaxBytesError) from malformed-JSON errors so callers get the right status code.
func decodeRequest(w http.ResponseWriter, r *http.Request, v any) bool {
	err := json.NewDecoder(r.Body).Decode(v)
	if err == nil {
		return true
	}
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		writeErrorJSON(w, http.StatusRequestEntityTooLarge, "TooLarge", "request body exceeds size limit")
		return false
	}
	writeErrorJSON(w, http.StatusBadRequest, "BadRequest", "malformed request body")
	return false
}

// managementHandler holds the domain services shared by all management API handlers.
// None of the handler methods import or reference net/http outside this file, following
// the principle that domain logic must not depend on transport.
type managementHandler struct {
	svc         *accounts.Service
	authn       auth.Authenticator
	cfg         *config.Config
	textures    *textures.TextureStore
	sessions    *auth.SessionManager
	tokens      *auth.TokenService
	st          store.Store
	oidcBrowser *auth.OIDCBrowserFlow
	mailer      mailer.Mailer
	configPath  string
}

func newManagementHandler(
	svc *accounts.Service,
	authn auth.Authenticator,
	cfg *config.Config,
	ts *textures.TextureStore,
	sessions *auth.SessionManager,
	tokens *auth.TokenService,
	st store.Store,
	oidcBrowser *auth.OIDCBrowserFlow,
	ml mailer.Mailer,
	configPath string,
) *managementHandler {
	return &managementHandler{
		svc:         svc,
		authn:       authn,
		cfg:         cfg,
		textures:    ts,
		sessions:    sessions,
		tokens:      tokens,
		st:          st,
		oidcBrowser: oidcBrowser,
		mailer:      ml,
		configPath:  configPath,
	}
}

// buildAPIMux builds the sub-mux for the public management API (mounted under ApiPrefix).
// The POST /register route is intentionally unauthenticated. All other routes require
// session or HTTP Basic auth via sessionOrBasicAuth(false).
func (mh *managementHandler) buildAPIMux() http.Handler {
	mux := http.NewServeMux()

	// Unauthenticated: self-service registration and password reset.
	mux.HandleFunc("POST /register", mh.handleRegister)
	mux.HandleFunc("POST /reset-password", mh.handleResetPassword)
	mux.HandleFunc("POST /forgot-password", mh.handleForgotPassword)
	mux.HandleFunc("POST /verify-email", mh.handleVerifyEmail)
	mux.HandleFunc("POST /resend-verification", mh.handleResendVerification)

	// Authenticated routes (non-admin).
	authed := sessionOrBasicAuth(mh.authn, mh.sessions, mh.svc, false)
	mux.Handle("GET /me", authed(http.HandlerFunc(mh.handleGetMe)))
	mux.Handle("PUT /me/email", authed(http.HandlerFunc(mh.handleUpdateEmail)))
	mux.Handle("PUT /me/password", authed(http.HandlerFunc(mh.handleUpdatePassword)))
	mux.Handle("PUT /me/game-password", authed(http.HandlerFunc(mh.handleSetGamePassword)))
	mux.Handle("DELETE /me/game-password", authed(http.HandlerFunc(mh.handleClearGamePassword)))
	mux.Handle("POST /me/totp/setup", authed(http.HandlerFunc(mh.handleTOTPSetup)))
	mux.Handle("POST /me/totp/confirm", authed(http.HandlerFunc(mh.handleTOTPConfirm)))
	mux.Handle("POST /me/totp/disable", authed(http.HandlerFunc(mh.handleTOTPDisable)))
	mux.Handle("DELETE /me", authed(http.HandlerFunc(mh.handleDeleteMe)))
	mux.Handle("GET /me/players", authed(http.HandlerFunc(mh.handleListPlayers)))
	mux.Handle("POST /me/players", authed(http.HandlerFunc(mh.handleCreatePlayer)))
	mux.Handle("PATCH /me/players/{id}", authed(http.HandlerFunc(mh.handleRenamePlayer)))
	mux.Handle("PUT /me/players/{id}/uuid", authed(http.HandlerFunc(mh.handleChangePlayerUUID)))
	mux.Handle("DELETE /me/players/{id}", authed(http.HandlerFunc(mh.handleDeletePlayer)))

	// Skin management (requires AllowSkins config flag to be true).
	mux.Handle("PUT /me/players/{id}/skin", authed(http.HandlerFunc(mh.handleUploadSkin)))
	mux.Handle("PUT /me/players/{id}/skin/model", authed(http.HandlerFunc(mh.handleSetSkinModel)))
	mux.Handle("PUT /me/players/{id}/skin/url", authed(http.HandlerFunc(mh.handleUploadSkinURL)))
	mux.Handle("DELETE /me/players/{id}/skin", authed(http.HandlerFunc(mh.handleDeleteSkin)))

	// Cape management (requires AllowCapes config flag to be true).
	mux.Handle("PUT /me/players/{id}/cape", authed(http.HandlerFunc(mh.handleUploadCape)))
	mux.Handle("PUT /me/players/{id}/cape/url", authed(http.HandlerFunc(mh.handleUploadCapeURL)))
	mux.Handle("DELETE /me/players/{id}/cape", authed(http.HandlerFunc(mh.handleDeleteCape)))

	return mux
}

// buildAdminMux builds the sub-mux for the admin management API (mounted under AdminPrefix).
// The entire mux is wrapped with sessionOrBasicAuth(requireAdmin=true) by buildRootHandler.
func (mh *managementHandler) buildAdminMux() http.Handler {
	mux := http.NewServeMux()

	// User management
	mux.HandleFunc("GET /users", mh.handleListUsers)
	mux.HandleFunc("POST /users", mh.handleAdminCreateUser)
	mux.HandleFunc("GET /users/{id}", mh.handleAdminGetUser)
	mux.HandleFunc("DELETE /users/{id}", mh.handleAdminDeleteUser)
	mux.HandleFunc("PUT /users/{id}/admin", mh.handleAdminSetAdmin)
	mux.HandleFunc("PUT /users/{id}/blocked", mh.handleAdminSetBlocked)
	mux.HandleFunc("POST /users/{id}/impersonate", mh.handleAdminImpersonate)
	mux.HandleFunc("POST /users/{id}/reset-token", mh.handleAdminCreateResetToken)

	// Admin player management for another user.
	mux.HandleFunc("GET /users/{id}/players", mh.handleAdminListPlayers)
	mux.HandleFunc("POST /users/{id}/players", mh.handleAdminCreatePlayer)
	mux.HandleFunc("PATCH /users/{id}/players/{pid}", mh.handleAdminRenamePlayer)
	mux.HandleFunc("PUT /users/{id}/players/{pid}/uuid", mh.handleAdminChangePlayerUUID)
	mux.HandleFunc("DELETE /users/{id}/players/{pid}", mh.handleAdminDeletePlayer)

	// Admin texture management (admin bypasses AllowSkins/AllowCapes flags).
	mux.HandleFunc("PUT /users/{id}/players/{pid}/skin", mh.handleAdminUploadSkin)
	mux.HandleFunc("PUT /users/{id}/players/{pid}/skin/url", mh.handleAdminUploadSkinURL)
	mux.HandleFunc("DELETE /users/{id}/players/{pid}/skin", mh.handleAdminDeleteSkin)
	mux.HandleFunc("PUT /users/{id}/players/{pid}/cape", mh.handleAdminUploadCape)
	mux.HandleFunc("PUT /users/{id}/players/{pid}/cape/url", mh.handleAdminUploadCapeURL)
	mux.HandleFunc("DELETE /users/{id}/players/{pid}/cape", mh.handleAdminDeleteCape)

	// Invite management
	mux.HandleFunc("GET /invites", mh.handleListInvites)
	mux.HandleFunc("POST /invites", mh.handleCreateInvite)
	mux.HandleFunc("DELETE /invites/{code}", mh.handleDeleteInvite)

	// Backup & Restore
	mux.HandleFunc("GET /backup", mh.handleAdminBackup)
	mux.HandleFunc("POST /restore", mh.handleAdminRestore)

	return mux
}

// adminPlayerCheck loads a player by id (from {pid} path value) and verifies it belongs
// to the user identified by {id} in the URL path (not the authenticated admin).
// Returns the player on success; writes an HTTP error and returns nil on failure.
func (mh *managementHandler) adminPlayerCheck(w http.ResponseWriter, r *http.Request) *store.Player {
	targetUserID := r.PathValue("id")
	playerID := r.PathValue("pid")

	player, err := mh.svc.GetPlayer(r.Context(), playerID)
	if err != nil {
		if errors.Is(err, accounts.ErrNotFound) {
			writeErrorJSON(w, http.StatusNotFound, "NotFound", "player not found")
			return nil
		}
		slog.Error("adminPlayerCheck: getting player", "id", playerID, "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return nil
	}
	if player.UserID != targetUserID {
		// 404 to avoid leaking the existence of another user's player.
		writeErrorJSON(w, http.StatusNotFound, "NotFound", "player not found")
		return nil
	}
	return player
}

// Public API handlers

// handleRegister processes POST /register (after prefix strip).
// This is the only unauthenticated management endpoint. It maps domain errors to their
// HTTP equivalents: ErrEmailTaken->409, ErrWeakPassword->400, ErrInvalidInvite->403.
// @Summary      Self-service registration
// @Description  Create a new user account. Required if require_invite is enabled.
// @Tags         Accounts
// @Accept       json
// @Produce      json
// @Param        request body RegisterRequest true "Registration data"
// @Success      201 {object} store.User
// @Failure      400 {object} APIError
// @Failure      403 {object} APIError
// @Failure      409 {object} APIError
// @Router       /api/register [post]
func (mh *managementHandler) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if !decodeRequest(w, r, &req) {
		return
	}

	user, err := mh.svc.Register(r.Context(), req.Email, req.Password, req.InviteCode)
	if err != nil {
		switch {
		case errors.Is(err, accounts.ErrEmailTaken):
			writeErrorJSON(w, http.StatusConflict, "Conflict", "email already taken")
		case errors.Is(err, accounts.ErrWeakPassword):
			writeErrorJSON(w, http.StatusBadRequest, "WeakPassword", err.Error())
		case errors.Is(err, accounts.ErrInvalidInvite):
			writeErrorJSON(w, http.StatusForbidden, "InvalidInvite", "invalid, expired, or already used invite code")
		default:
			slog.Error("handleRegister: registering user", "email", req.Email, "error", err)
			writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		}
		return
	}

	if !user.EmailVerified {
		plaintext, err := mh.svc.CreateEmailVerifyToken(r.Context(), user.ID, 24*time.Hour)
		if err != nil {
			slog.Error("handleRegister: creating email verification token", "userID", user.ID, "error", err)
		} else {
			link := mh.cfg.BaseURL + "/verify?token=" + url.QueryEscape(plaintext)
			subject, body := mailer.RenderActionEmail(mailer.ActionEmailData{
				Title:       "Verify your email",
				Intro:       "Welcome to " + mh.cfg.ServerName + "! Confirm your email address to activate your account.",
				ButtonLabel: "Verify Email",
				ButtonURL:   link,
				Footer:      "You will not be able to sign in until your email is verified.",
				ServerName:  mh.cfg.ServerName,
			})
			if err := mh.mailer.Send(r.Context(), user.Email, subject, body); err != nil {
				slog.Error("handleRegister: sending verification email", "email", user.Email, "error", err)
			}
		}
	}

	writeJSON(w, http.StatusCreated, user)
}

// handleGetMe processes GET /me. Returns the authenticated user's own profile.
// @Summary      Get current user
// @Description  Returns the authenticated user's account.
// @Tags         Accounts
// @Produce      json
// @Success      200 {object} store.User
// @Failure      401 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /api/me [get]
func (mh *managementHandler) handleGetMe(w http.ResponseWriter, r *http.Request) {
	user, _ := userFromContext(r.Context())
	writeJSON(w, http.StatusOK, user)
}

// handleUpdateEmail processes PUT /me/email.
// @Summary      Update email
// @Description  Updates the authenticated user's email address.
// @Tags         Accounts
// @Accept       json
// @Produce      json
// @Param        request body UpdateEmailRequest true "New email address"
// @Success      200 {object} store.User
// @Failure      400 {object} APIError
// @Failure      401 {object} APIError
// @Failure      409 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /api/me/email [put]
func (mh *managementHandler) handleUpdateEmail(w http.ResponseWriter, r *http.Request) {
	user, _ := userFromContext(r.Context())
	var req UpdateEmailRequest
	if !decodeRequest(w, r, &req) {
		return
	}

	if err := mh.svc.UpdateUserEmail(r.Context(), user.ID, req.Email); err != nil {
		switch {
		case errors.Is(err, accounts.ErrEmailTaken):
			writeErrorJSON(w, http.StatusConflict, "Conflict", "email already taken")
		case errors.Is(err, accounts.ErrNotFound):
			writeErrorJSON(w, http.StatusNotFound, "NotFound", "user not found")
		default:
			slog.Error("handleUpdateEmail: updating email", "error", err)
			writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		}
		return
	}

	// Re-fetch to include the updated email in the response.
	updated, err := mh.svc.GetUser(r.Context(), user.ID)
	if err != nil {
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

// handleUpdatePassword processes PUT /me/password.
// @Summary      Update password
// @Description  Updates the authenticated user's password.
// @Tags         Accounts
// @Accept       json
// @Produce      json
// @Param        request body UpdatePasswordRequest true "New password"
// @Success      204 "No Content"
// @Failure      400 {object} APIError
// @Failure      401 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /api/me/password [put]
func (mh *managementHandler) handleUpdatePassword(w http.ResponseWriter, r *http.Request) {
	user, _ := userFromContext(r.Context())
	var req UpdatePasswordRequest
	if !decodeRequest(w, r, &req) {
		return
	}

	if err := mh.svc.ChangePassword(r.Context(), user.ID, req.Password); err != nil {
		switch {
		case errors.Is(err, accounts.ErrWeakPassword):
			writeErrorJSON(w, http.StatusBadRequest, "WeakPassword", err.Error())
		case errors.Is(err, accounts.ErrNotFound):
			writeErrorJSON(w, http.StatusNotFound, "NotFound", "user not found")
		default:
			slog.Error("handleUpdatePassword: changing password", "error", err)
			writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleSetGamePassword processes PUT /me/game-password.
// @Summary      Set dedicated game password
// @Description  Sets or changes the authenticated user's dedicated game password used by the Minecraft launcher (Yggdrasil).
// @Tags         Accounts
// @Accept       json
// @Produce      json
// @Param        request body SetGamePasswordRequest true "New game password"
// @Success      200 {object} map[string]string "Success status"
// @Failure      400 {object} APIError
// @Failure      401 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /api/me/game-password [put]
func (mh *managementHandler) handleSetGamePassword(w http.ResponseWriter, r *http.Request) {
	user, _ := userFromContext(r.Context())
	var req SetGamePasswordRequest
	if !decodeRequest(w, r, &req) {
		return
	}

	if err := mh.svc.SetGamePassword(r.Context(), user.ID, req.Password); err != nil {
		switch {
		case errors.Is(err, accounts.ErrWeakPassword):
			writeErrorJSON(w, http.StatusBadRequest, "WeakPassword", err.Error())
		case errors.Is(err, accounts.ErrNotFound):
			writeErrorJSON(w, http.StatusNotFound, "NotFound", "user not found")
		default:
			slog.Error("handleSetGamePassword: setting game password", "error", err)
			writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		}
		return
	}

	if mh.tokens != nil {
		if err := mh.tokens.InvalidateAllByUser(r.Context(), user.ID); err != nil {
			slog.Warn("handleSetGamePassword: invalidating tokens", "id", user.ID, "error", err)
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleClearGamePassword processes DELETE /me/game-password.
// @Summary      Clear dedicated game password
// @Description  Removes the authenticated user's dedicated game password, falling back to using the account password.
// @Tags         Accounts
// @Accept       json
// @Produce      json
// @Success      200 {object} map[string]string "Success status"
// @Failure      401 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /api/me/game-password [delete]
func (mh *managementHandler) handleClearGamePassword(w http.ResponseWriter, r *http.Request) {
	user, _ := userFromContext(r.Context())

	if err := mh.svc.ClearGamePassword(r.Context(), user.ID); err != nil {
		switch {
		case errors.Is(err, accounts.ErrNotFound):
			writeErrorJSON(w, http.StatusNotFound, "NotFound", "user not found")
		default:
			slog.Error("handleClearGamePassword: clearing game password", "error", err)
			writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		}
		return
	}

	if mh.tokens != nil {
		if err := mh.tokens.InvalidateAllByUser(r.Context(), user.ID); err != nil {
			slog.Warn("handleClearGamePassword: invalidating tokens", "id", user.ID, "error", err)
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleTOTPSetup processes POST /me/totp/setup.
// @Summary      Begin TOTP setup
// @Description  Generates a new TOTP secret and returns the otpauth:// URL and base32 secret.
// @Tags         Accounts
// @Produce      json
// @Success      200 {object} map[string]string "OTP auth URL and secret"
// @Failure      401 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /api/me/totp/setup [post]
func (mh *managementHandler) handleTOTPSetup(w http.ResponseWriter, r *http.Request) {
	user, _ := userFromContext(r.Context())

	otpauthURL, secret, err := mh.svc.BeginTOTPSetup(r.Context(), user.ID)
	if err != nil {
		slog.Error("handleTOTPSetup: beginning TOTP setup", "user_id", user.ID, "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}

	// Render the otpauth URL as a QR PNG server-side (pure Go, no external service)
	// in the Minecraft palette: dark stone on cream. High contrast so it still scans.
	qrDataURI, qrErr := totpQRDataURI(otpauthURL)
	if qrErr != nil {
		slog.Error("handleTOTPSetup: rendering QR", "user_id", user.ID, "error", qrErr)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"otpauthUrl": otpauthURL,
		"secret":     secret,
		"qrPng":      qrDataURI,
	})
}

// totpQRDataURI renders an otpauth URL into a base64 data URI PNG QR code,
// coloured in the Minecraft palette (dark stone modules on a cream background).
// The contrast is kept high so authenticator apps still scan it reliably.
func totpQRDataURI(otpauthURL string) (string, error) {
	qr, err := qrcode.New(otpauthURL, qrcode.Medium)
	if err != nil {
		return "", fmt.Errorf("creating QR code: %w", err)
	}
	qr.ForegroundColor = color.RGBA{R: 0x2b, G: 0x2b, B: 0x2b, A: 0xff} // stone/panel dark
	qr.BackgroundColor = color.RGBA{R: 0xe9, G: 0xe9, B: 0xe9, A: 0xff} // cream/text light
	png, err := qr.PNG(256)
	if err != nil {
		return "", fmt.Errorf("encoding QR PNG: %w", err)
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), nil
}

// handleTOTPConfirm processes POST /me/totp/confirm.
// @Summary      Confirm TOTP setup
// @Description  Validates a TOTP code, enables TOTP for the user, and returns recovery codes.
// @Tags         Accounts
// @Accept       json
// @Produce      json
// @Param        request body TOTPConfirmRequest true "TOTP setup confirmation code"
// @Success      200 {object} map[string]any "Plaintext recovery codes"
// @Failure      400 {object} APIError
// @Failure      401 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /api/me/totp/confirm [post]
func (mh *managementHandler) handleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	user, _ := userFromContext(r.Context())

	var req TOTPConfirmRequest
	if !decodeRequest(w, r, &req) {
		return
	}

	recoveryCodes, err := mh.svc.ConfirmTOTP(r.Context(), user.ID, req.Code)
	if err != nil {
		switch {
		case errors.Is(err, accounts.ErrTOTPNotPending):
			writeErrorJSON(w, http.StatusBadRequest, "TOTPNotPending", "TOTP setup has not been initiated")
		case errors.Is(err, accounts.ErrInvalidTOTP):
			writeErrorJSON(w, http.StatusBadRequest, "InvalidTOTP", "invalid authentication code")
		default:
			slog.Error("handleTOTPConfirm: confirming TOTP", "user_id", user.ID, "error", err)
			writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"recoveryCodes": recoveryCodes,
	})
}

// handleTOTPDisable processes POST /me/totp/disable.
// @Summary      Disable TOTP
// @Description  Disables TOTP 2FA for the user. Requires a valid current TOTP code or a recovery code, unless performed by an impersonating admin.
// @Tags         Accounts
// @Accept       json
// @Produce      json
// @Param        request body TOTPDisableRequest true "TOTP disable verification"
// @Success      200 {object} map[string]string "Success status"
// @Failure      400 {object} APIError
// @Failure      401 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /api/me/totp/disable [post]
func (mh *managementHandler) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	user, _ := userFromContext(r.Context())

	var req TOTPDisableRequest
	if !decodeRequest(w, r, &req) {
		return
	}

	// Check if this is an impersonating admin session
	isImpersonated := false
	if session, ok := sessionFromContext(r.Context()); ok {
		if session.ImpersonatedBy != nil {
			isImpersonated = true
		}
	}

	if isImpersonated {
		if err := mh.svc.AdminDisableTOTP(r.Context(), user.ID); err != nil {
			slog.Error("handleTOTPDisable: admin force disabling TOTP", "user_id", user.ID, "error", err)
			writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
			return
		}
	} else {
		if err := mh.svc.DisableTOTP(r.Context(), user.ID, req.Code); err != nil {
			switch {
			case errors.Is(err, accounts.ErrTOTPNotEnabled):
				writeErrorJSON(w, http.StatusBadRequest, "TOTPNotEnabled", "TOTP is not enabled for this user")
			case errors.Is(err, accounts.ErrInvalidTOTP):
				writeErrorJSON(w, http.StatusBadRequest, "InvalidTOTP", "invalid authentication code")
			default:
				slog.Error("handleTOTPDisable: disabling TOTP", "user_id", user.ID, "error", err)
				writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
			}
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleDeleteMe processes DELETE /me. Deletes the authenticated user's own account.
// @Summary      Delete current user
// @Description  Deletes the authenticated user's account and all associated player profiles and textures.
// @Tags         Accounts
// @Produce      json
// @Success      204 "No Content"
// @Failure      401 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /api/me [delete]
func (mh *managementHandler) handleDeleteMe(w http.ResponseWriter, r *http.Request) {
	user, _ := userFromContext(r.Context())
	if err := mh.svc.DeleteUser(r.Context(), user.ID); err != nil {
		if errors.Is(err, accounts.ErrNotFound) {
			writeErrorJSON(w, http.StatusNotFound, "NotFound", "user not found")
			return
		}
		slog.Error("handleDeleteMe: deleting user", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleListPlayers processes GET /me/players.
// @Summary      List current user's players
// @Description  Returns a list of all player profiles owned by the authenticated user.
// @Tags         Players
// @Produce      json
// @Success      200 {array} store.Player
// @Failure      401 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /api/me/players [get]
func (mh *managementHandler) handleListPlayers(w http.ResponseWriter, r *http.Request) {
	user, _ := userFromContext(r.Context())
	players, err := mh.svc.ListPlayersByUser(r.Context(), user.ID)
	if err != nil {
		slog.Error("handleListPlayers: listing players", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	// Return an empty array instead of null when there are no players.
	if players == nil {
		players = []*store.Player{}
	}
	writeJSON(w, http.StatusOK, players)
}

// handleCreatePlayer processes POST /me/players.
// @Summary      Create player profile
// @Description  Creates a new Minecraft player profile for the authenticated user.
// @Tags         Players
// @Accept       json
// @Produce      json
// @Param        request body CreatePlayerRequest true "Player creation data"
// @Success      201 {object} store.Player
// @Failure      400 {object} APIError
// @Failure      401 {object} APIError
// @Failure      409 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /api/me/players [post]
func (mh *managementHandler) handleCreatePlayer(w http.ResponseWriter, r *http.Request) {
	user, _ := userFromContext(r.Context())
	var req CreatePlayerRequest
	if !decodeRequest(w, r, &req) {
		return
	}

	player, err := mh.svc.CreatePlayer(r.Context(), user.ID, req.Name, req.UUID)
	if err != nil {
		switch {
		case errors.Is(err, accounts.ErrPlayerLimitReached):
			writeErrorJSON(w, http.StatusConflict, "PlayerLimitReached", "player limit per user reached")
		case errors.Is(err, accounts.ErrInvalidPlayerName):
			writeErrorJSON(w, http.StatusBadRequest, "InvalidPlayerName", "player name does not match the required pattern")
		case errors.Is(err, accounts.ErrPlayerNameTaken):
			writeErrorJSON(w, http.StatusConflict, "Conflict", "player name already taken")
		case errors.Is(err, accounts.ErrPlayerUUIDTaken):
			writeErrorJSON(w, http.StatusConflict, "Conflict", "player UUID already taken")
		case errors.Is(err, accounts.ErrInvalidPlayerUUID):
			writeErrorJSON(w, http.StatusBadRequest, "InvalidUUID", "player UUID is not a valid UUID")
		default:
			slog.Error("handleCreatePlayer: creating player", "error", err)
			writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		}
		return
	}
	writeJSON(w, http.StatusCreated, player)
}

// handleRenamePlayer processes PATCH /me/players/{id}.
// The authenticated user must own the player; a mismatch returns 404 to avoid leaking existence.
// @Summary      Rename player profile
// @Description  Changes the username of a player profile owned by the authenticated user.
// @Tags         Players
// @Accept       json
// @Produce      json
// @Param        id path string true "Player ID"
// @Param        request body RenamePlayerRequest true "New player name"
// @Success      200 {object} store.Player
// @Failure      400 {object} APIError
// @Failure      401 {object} APIError
// @Failure      404 {object} APIError
// @Failure      409 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /api/me/players/{id} [patch]
func (mh *managementHandler) handleRenamePlayer(w http.ResponseWriter, r *http.Request) {
	user, _ := userFromContext(r.Context())
	playerID := r.PathValue("id")

	player, err := mh.svc.GetPlayer(r.Context(), playerID)
	if err != nil {
		if errors.Is(err, accounts.ErrNotFound) {
			writeErrorJSON(w, http.StatusNotFound, "NotFound", "player not found")
			return
		}
		slog.Error("handleRenamePlayer: getting player", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	if player.UserID != user.ID {
		writeErrorJSON(w, http.StatusNotFound, "NotFound", "player not found")
		return
	}

	var req RenamePlayerRequest
	if !decodeRequest(w, r, &req) {
		return
	}

	if err := mh.svc.RenamePlayer(r.Context(), playerID, req.Name); err != nil {
		switch {
		case errors.Is(err, accounts.ErrInvalidPlayerName):
			writeErrorJSON(w, http.StatusBadRequest, "InvalidPlayerName", "player name does not match the required pattern")
		case errors.Is(err, accounts.ErrPlayerNameTaken):
			writeErrorJSON(w, http.StatusConflict, "Conflict", "player name already taken")
		case errors.Is(err, accounts.ErrNotFound):
			writeErrorJSON(w, http.StatusNotFound, "NotFound", "player not found")
		default:
			slog.Error("handleRenamePlayer: renaming", "error", err)
			writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		}
		return
	}

	updated, err := mh.svc.GetPlayer(r.Context(), playerID)
	if err != nil {
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

// handleChangePlayerUUID processes PUT /me/players/{id}/uuid.
// The authenticated user must own the player; a mismatch returns 404 to avoid leaking existence.
// @Summary      Change player profile UUID
// @Description  Sets a new profile UUID for a player owned by the authenticated user. An empty uuid regenerates one per the server policy. Warning: a player's UUID is its identity on Minecraft servers (inventories, permissions, progress are keyed by it), so changing it makes the player a different identity to any server it has joined.
// @Tags         Players
// @Accept       json
// @Produce      json
// @Param        id path string true "Player ID"
// @Param        request body ChangePlayerUUIDRequest true "New UUID (empty to regenerate)"
// @Success      200 {object} store.Player
// @Failure      400 {object} APIError
// @Failure      401 {object} APIError
// @Failure      404 {object} APIError
// @Failure      409 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /api/me/players/{id}/uuid [put]
func (mh *managementHandler) handleChangePlayerUUID(w http.ResponseWriter, r *http.Request) {
	user, _ := userFromContext(r.Context())
	playerID := r.PathValue("id")

	player, err := mh.svc.GetPlayer(r.Context(), playerID)
	if err != nil {
		if errors.Is(err, accounts.ErrNotFound) {
			writeErrorJSON(w, http.StatusNotFound, "NotFound", "player not found")
			return
		}
		slog.Error("handleChangePlayerUUID: getting player", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	if player.UserID != user.ID {
		writeErrorJSON(w, http.StatusNotFound, "NotFound", "player not found")
		return
	}

	var req ChangePlayerUUIDRequest
	if !decodeRequest(w, r, &req) {
		return
	}

	updated, err := mh.svc.ChangePlayerUUID(r.Context(), playerID, req.UUID)
	if err != nil {
		switch {
		case errors.Is(err, accounts.ErrInvalidPlayerUUID):
			writeErrorJSON(w, http.StatusBadRequest, "InvalidUUID", "player UUID is not a valid UUID")
		case errors.Is(err, accounts.ErrPlayerUUIDTaken):
			writeErrorJSON(w, http.StatusConflict, "Conflict", "player UUID already taken")
		case errors.Is(err, accounts.ErrNotFound):
			writeErrorJSON(w, http.StatusNotFound, "NotFound", "player not found")
		default:
			slog.Error("handleChangePlayerUUID: changing uuid", "error", err)
			writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		}
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

// handleDeletePlayer processes DELETE /me/players/{id}.
// @Summary      Delete player profile
// @Description  Deletes a player profile owned by the authenticated user.
// @Tags         Players
// @Produce      json
// @Param        id path string true "Player ID"
// @Success      204 "No Content"
// @Failure      401 {object} APIError
// @Failure      404 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /api/me/players/{id} [delete]
func (mh *managementHandler) handleDeletePlayer(w http.ResponseWriter, r *http.Request) {
	user, _ := userFromContext(r.Context())
	playerID := r.PathValue("id")

	player, err := mh.svc.GetPlayer(r.Context(), playerID)
	if err != nil {
		if errors.Is(err, accounts.ErrNotFound) {
			writeErrorJSON(w, http.StatusNotFound, "NotFound", "player not found")
			return
		}
		slog.Error("handleDeletePlayer: getting player", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	if player.UserID != user.ID {
		writeErrorJSON(w, http.StatusNotFound, "NotFound", "player not found")
		return
	}

	if err := mh.svc.DeletePlayer(r.Context(), playerID); err != nil {
		if errors.Is(err, accounts.ErrNotFound) {
			writeErrorJSON(w, http.StatusNotFound, "NotFound", "player not found")
			return
		}
		slog.Error("handleDeletePlayer: deleting", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Admin API handlers

// handleListUsers processes GET /users (admin).
// @Summary      List all users (Admin only)
// @Description  Returns a list of all user accounts in the system.
// @Tags         Admin
// @Produce      json
// @Success      200 {array} store.User
// @Failure      401 {object} APIError
// @Failure      403 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /admin/users [get]
func (mh *managementHandler) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := mh.svc.ListUsers(r.Context())
	if err != nil {
		slog.Error("handleListUsers: listing", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	if users == nil {
		users = []*store.User{}
	}
	writeJSON(w, http.StatusOK, users)
}

// handleAdminCreateUser processes POST /users (admin).
// @Summary      Create user (Admin only)
// @Description  Creates a new user account (admin bypasses self-registration restrictions).
// @Tags         Admin
// @Accept       json
// @Produce      json
// @Param        request body AdminCreateUserRequest true "User creation data"
// @Success      201 {object} store.User
// @Failure      400 {object} APIError
// @Failure      401 {object} APIError
// @Failure      403 {object} APIError
// @Failure      409 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /admin/users [post]
func (mh *managementHandler) handleAdminCreateUser(w http.ResponseWriter, r *http.Request) {
	var req AdminCreateUserRequest
	if !decodeRequest(w, r, &req) {
		return
	}

	user, err := mh.svc.AdminCreateUser(r.Context(), req.Email, req.Password, req.IsAdmin)
	if err != nil {
		switch {
		case errors.Is(err, accounts.ErrEmailTaken):
			writeErrorJSON(w, http.StatusConflict, "Conflict", "email already taken")
		case errors.Is(err, accounts.ErrWeakPassword):
			writeErrorJSON(w, http.StatusBadRequest, "WeakPassword", err.Error())
		default:
			slog.Error("handleAdminCreateUser: creating", "email", req.Email, "error", err)
			writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		}
		return
	}
	writeJSON(w, http.StatusCreated, user)
}

// handleAdminGetUser processes GET /users/{id} (admin).
// @Summary      Get user by ID (Admin only)
// @Description  Returns details of a specific user account.
// @Tags         Admin
// @Produce      json
// @Param        id path string true "User ID"
// @Success      200 {object} store.User
// @Failure      401 {object} APIError
// @Failure      403 {object} APIError
// @Failure      404 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /admin/users/{id} [get]
func (mh *managementHandler) handleAdminGetUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	user, err := mh.svc.GetUser(r.Context(), id)
	if err != nil {
		if errors.Is(err, accounts.ErrNotFound) {
			writeErrorJSON(w, http.StatusNotFound, "NotFound", "user not found")
			return
		}
		slog.Error("handleAdminGetUser: getting", "id", id, "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, user)
}

// handleAdminDeleteUser processes DELETE /users/{id} (admin).
// @Summary      Delete user (Admin only)
// @Description  Deletes a user account and all associated player profiles and textures.
// @Tags         Admin
// @Produce      json
// @Param        id path string true "User ID"
// @Success      204 "No Content"
// @Failure      401 {object} APIError
// @Failure      403 {object} APIError
// @Failure      404 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /admin/users/{id} [delete]
func (mh *managementHandler) handleAdminDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := mh.svc.DeleteUser(r.Context(), id); err != nil {
		if errors.Is(err, accounts.ErrNotFound) {
			writeErrorJSON(w, http.StatusNotFound, "NotFound", "user not found")
			return
		}
		slog.Error("handleAdminDeleteUser: deleting", "id", id, "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleAdminSetAdmin processes PUT /users/{id}/admin (admin).
// @Summary      Set user admin status (Admin only)
// @Description  Promotes or demotes a user's admin privilege level.
// @Tags         Admin
// @Accept       json
// @Produce      json
// @Param        id path string true "User ID"
// @Param        request body SetAdminRequest true "Admin status data"
// @Success      200 {object} store.User
// @Failure      400 {object} APIError
// @Failure      401 {object} APIError
// @Failure      403 {object} APIError
// @Failure      404 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /admin/users/{id}/admin [put]
func (mh *managementHandler) handleAdminSetAdmin(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req SetAdminRequest
	if !decodeRequest(w, r, &req) {
		return
	}

	if err := mh.svc.SetAdmin(r.Context(), id, req.IsAdmin); err != nil {
		if errors.Is(err, accounts.ErrNotFound) {
			writeErrorJSON(w, http.StatusNotFound, "NotFound", "user not found")
			return
		}
		slog.Error("handleAdminSetAdmin: setting admin", "id", id, "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}

	user, err := mh.svc.GetUser(r.Context(), id)
	if err != nil {
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, user)
}

// handleAdminSetBlocked processes PUT /users/{id}/blocked (admin).
// @Summary      Set user blocked status (Admin only)
// @Description  Blocks or unblocks a user account. Blocking a user immediately revokes all of their active sessions and tokens.
// @Tags         Admin
// @Accept       json
// @Produce      json
// @Param        id path string true "User ID"
// @Param        request body SetBlockedRequest true "Blocked status data"
// @Success      200 {object} store.User
// @Failure      400 {object} APIError
// @Failure      401 {object} APIError
// @Failure      403 {object} APIError
// @Failure      404 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /admin/users/{id}/blocked [put]
func (mh *managementHandler) handleAdminSetBlocked(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req SetBlockedRequest
	if !decodeRequest(w, r, &req) {
		return
	}

	if err := mh.svc.SetBlocked(r.Context(), id, req.Blocked); err != nil {
		if errors.Is(err, accounts.ErrNotFound) {
			writeErrorJSON(w, http.StatusNotFound, "NotFound", "user not found")
			return
		}
		slog.Error("handleAdminSetBlocked: setting blocked", "id", id, "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}

	// When blocking a user, forcibly revoke all their active sessions and tokens
	// so they are ejected immediately without waiting for natural expiry.
	if req.Blocked {
		if mh.sessions != nil {
			if err := mh.sessions.RevokeAllByUser(r.Context(), id); err != nil {
				slog.Warn("handleAdminSetBlocked: revoking sessions", "id", id, "error", err)
			}
		}
		if mh.tokens != nil {
			if err := mh.tokens.InvalidateAllByUser(r.Context(), id); err != nil {
				slog.Warn("handleAdminSetBlocked: invalidating tokens", "id", id, "error", err)
			}
		}
	}

	user, err := mh.svc.GetUser(r.Context(), id)
	if err != nil {
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, user)
}

// handleAdminImpersonate processes POST /users/{id}/impersonate (admin).
// @Summary      Impersonate user (Admin only)
// @Description  Creates an impersonated browser session for the specified user, returning a new session cookie.
// @Tags         Admin
// @Produce      json
// @Param        id path string true "User ID"
// @Success      200 {object} store.User
// @Failure      401 {object} APIError
// @Failure      403 {object} APIError
// @Failure      404 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /admin/users/{id}/impersonate [post]
func (mh *managementHandler) handleAdminImpersonate(w http.ResponseWriter, r *http.Request) {
	admin, ok := userFromContext(r.Context())
	if !ok {
		writeErrorJSON(w, http.StatusUnauthorized, "Unauthorized", "authentication required")
		return
	}

	targetID := r.PathValue("id")
	targetUser, err := mh.svc.GetUser(r.Context(), targetID)
	if err != nil {
		if errors.Is(err, accounts.ErrNotFound) {
			writeErrorJSON(w, http.StatusNotFound, "NotFound", "user not found")
			return
		}
		slog.Error("handleAdminImpersonate: getting target user", "id", targetID, "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}

	adminID := admin.ID
	sess, err := mh.sessions.Create(r.Context(), targetID, &adminID)
	if err != nil {
		slog.Error("handleAdminImpersonate: creating session", "user_id", targetID, "admin_id", adminID, "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}

	mh.setSessionCookie(w, sess.Token, sess.ExpiresAt)

	writeJSON(w, http.StatusOK, map[string]any{
		"user":      targetUser,
		"csrfToken": sess.CSRFToken,
	})
}

// handleAdminListPlayers processes GET /users/{id}/players (admin).
// @Summary      List user's players (Admin only)
// @Description  Returns a list of player profiles owned by the specified user.
// @Tags         Admin
// @Produce      json
// @Param        id path string true "User ID"
// @Success      200 {array} store.Player
// @Failure      401 {object} APIError
// @Failure      403 {object} APIError
// @Failure      404 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /admin/users/{id}/players [get]
func (mh *managementHandler) handleAdminListPlayers(w http.ResponseWriter, r *http.Request) {
	targetUserID := r.PathValue("id")
	players, err := mh.svc.ListPlayersByUser(r.Context(), targetUserID)
	if err != nil {
		slog.Error("handleAdminListPlayers: listing", "user_id", targetUserID, "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	if players == nil {
		players = []*store.Player{}
	}
	writeJSON(w, http.StatusOK, players)
}

// handleAdminCreatePlayer processes POST /users/{id}/players (admin).
// @Summary      Create player profile for user (Admin only)
// @Description  Creates a new Minecraft player profile for the specified user.
// @Tags         Admin
// @Accept       json
// @Produce      json
// @Param        id path string true "User ID"
// @Param        request body CreatePlayerRequest true "Player creation data"
// @Success      201 {object} store.Player
// @Failure      400 {object} APIError
// @Failure      401 {object} APIError
// @Failure      403 {object} APIError
// @Failure      404 {object} APIError
// @Failure      409 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /admin/users/{id}/players [post]
func (mh *managementHandler) handleAdminCreatePlayer(w http.ResponseWriter, r *http.Request) {
	targetUserID := r.PathValue("id")
	var req CreatePlayerRequest
	if !decodeRequest(w, r, &req) {
		return
	}

	player, err := mh.svc.CreatePlayer(r.Context(), targetUserID, req.Name, req.UUID)
	if err != nil {
		switch {
		case errors.Is(err, accounts.ErrPlayerLimitReached):
			writeErrorJSON(w, http.StatusConflict, "PlayerLimitReached", "player limit per user reached")
		case errors.Is(err, accounts.ErrInvalidPlayerName):
			writeErrorJSON(w, http.StatusBadRequest, "InvalidPlayerName", "player name does not match the required pattern")
		case errors.Is(err, accounts.ErrPlayerNameTaken):
			writeErrorJSON(w, http.StatusConflict, "Conflict", "player name already taken")
		case errors.Is(err, accounts.ErrPlayerUUIDTaken):
			writeErrorJSON(w, http.StatusConflict, "Conflict", "player UUID already taken")
		case errors.Is(err, accounts.ErrInvalidPlayerUUID):
			writeErrorJSON(w, http.StatusBadRequest, "InvalidUUID", "player UUID is not a valid UUID")
		case errors.Is(err, accounts.ErrNotFound):
			writeErrorJSON(w, http.StatusNotFound, "NotFound", "user not found")
		default:
			slog.Error("handleAdminCreatePlayer: creating", "user_id", targetUserID, "error", err)
			writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		}
		return
	}
	writeJSON(w, http.StatusCreated, player)
}

// handleAdminRenamePlayer processes PATCH /users/{id}/players/{pid} (admin).
// @Summary      Rename user's player profile (Admin only)
// @Description  Renames a player profile owned by the specified user.
// @Tags         Admin
// @Accept       json
// @Produce      json
// @Param        id path string true "User ID"
// @Param        pid path string true "Player ID"
// @Param        request body RenamePlayerRequest true "New player name"
// @Success      200 {object} store.Player
// @Failure      400 {object} APIError
// @Failure      401 {object} APIError
// @Failure      403 {object} APIError
// @Failure      404 {object} APIError
// @Failure      409 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /admin/users/{id}/players/{pid} [patch]
func (mh *managementHandler) handleAdminRenamePlayer(w http.ResponseWriter, r *http.Request) {
	player := mh.adminPlayerCheck(w, r)
	if player == nil {
		return
	}

	var req RenamePlayerRequest
	if !decodeRequest(w, r, &req) {
		return
	}

	if err := mh.svc.RenamePlayer(r.Context(), player.ID, req.Name); err != nil {
		switch {
		case errors.Is(err, accounts.ErrInvalidPlayerName):
			writeErrorJSON(w, http.StatusBadRequest, "InvalidPlayerName", "player name does not match the required pattern")
		case errors.Is(err, accounts.ErrPlayerNameTaken):
			writeErrorJSON(w, http.StatusConflict, "Conflict", "player name already taken")
		case errors.Is(err, accounts.ErrNotFound):
			writeErrorJSON(w, http.StatusNotFound, "NotFound", "player not found")
		default:
			slog.Error("handleAdminRenamePlayer: renaming", "error", err)
			writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		}
		return
	}

	updated, err := mh.svc.GetPlayer(r.Context(), player.ID)
	if err != nil {
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

// handleAdminChangePlayerUUID processes PUT /users/{id}/players/{pid}/uuid (admin).
// @Summary      Change user's player profile UUID (Admin only)
// @Description  Sets a new profile UUID for a player owned by the specified user. An empty uuid regenerates one per the server policy.
// @Tags         Admin
// @Accept       json
// @Produce      json
// @Param        id path string true "User ID"
// @Param        pid path string true "Player ID"
// @Param        request body ChangePlayerUUIDRequest true "New UUID (empty to regenerate)"
// @Success      200 {object} store.Player
// @Failure      400 {object} APIError
// @Failure      401 {object} APIError
// @Failure      403 {object} APIError
// @Failure      404 {object} APIError
// @Failure      409 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /admin/users/{id}/players/{pid}/uuid [put]
func (mh *managementHandler) handleAdminChangePlayerUUID(w http.ResponseWriter, r *http.Request) {
	player := mh.adminPlayerCheck(w, r)
	if player == nil {
		return
	}

	var req ChangePlayerUUIDRequest
	if !decodeRequest(w, r, &req) {
		return
	}

	updated, err := mh.svc.ChangePlayerUUID(r.Context(), player.ID, req.UUID)
	if err != nil {
		switch {
		case errors.Is(err, accounts.ErrInvalidPlayerUUID):
			writeErrorJSON(w, http.StatusBadRequest, "InvalidUUID", "player UUID is not a valid UUID")
		case errors.Is(err, accounts.ErrPlayerUUIDTaken):
			writeErrorJSON(w, http.StatusConflict, "Conflict", "player UUID already taken")
		case errors.Is(err, accounts.ErrNotFound):
			writeErrorJSON(w, http.StatusNotFound, "NotFound", "player not found")
		default:
			slog.Error("handleAdminChangePlayerUUID: changing uuid", "error", err)
			writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		}
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

// handleAdminDeletePlayer processes DELETE /users/{id}/players/{pid} (admin).
// @Summary      Delete user's player profile (Admin only)
// @Description  Deletes a player profile owned by the specified user.
// @Tags         Admin
// @Produce      json
// @Param        id path string true "User ID"
// @Param        pid path string true "Player ID"
// @Success      204 "No Content"
// @Failure      401 {object} APIError
// @Failure      403 {object} APIError
// @Failure      404 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /admin/users/{id}/players/{pid} [delete]
func (mh *managementHandler) handleAdminDeletePlayer(w http.ResponseWriter, r *http.Request) {
	player := mh.adminPlayerCheck(w, r)
	if player == nil {
		return
	}

	if err := mh.svc.DeletePlayer(r.Context(), player.ID); err != nil {
		if errors.Is(err, accounts.ErrNotFound) {
			writeErrorJSON(w, http.StatusNotFound, "NotFound", "player not found")
			return
		}
		slog.Error("handleAdminDeletePlayer: deleting", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Admin texture handlers — admins bypass AllowSkins/AllowCapes config flags.

// handleAdminUploadSkin processes PUT /users/{id}/players/{pid}/skin (admin).
// @Summary      Upload player skin (Admin only)
// @Description  Uploads a new PNG skin file for the specified user's player.
// @Tags         Admin
// @Accept       image/png
// @Produce      json
// @Param        id path string true "User ID"
// @Param        pid path string true "Player ID"
// @Param        model query string false "Skin model (classic or slim)"
// @Success      200 {object} store.Player
// @Failure      400 {object} APIError
// @Failure      401 {object} APIError
// @Failure      403 {object} APIError
// @Failure      404 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /admin/users/{id}/players/{pid}/skin [put]
func (mh *managementHandler) handleAdminUploadSkin(w http.ResponseWriter, r *http.Request) {
	if mh.textures == nil {
		writeErrorJSON(w, http.StatusServiceUnavailable, "Unavailable", "texture storage not configured")
		return
	}
	player := mh.adminPlayerCheck(w, r)
	if player == nil {
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
	skinSizeLimit := 0
	if mh.cfg != nil {
		skinSizeLimit = mh.cfg.SkinSizeLimit
	}
	if err := textures.ValidateSkin(img, skinSizeLimit); err != nil {
		writeErrorJSON(w, http.StatusBadRequest, "BadRequest", err.Error())
		return
	}
	if model == "" {
		model = textures.DetectModel(img)
	}

	hash, err := mh.textures.Put(pngBytes)
	if err != nil {
		slog.Error("handleAdminUploadSkin: storing texture", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	if err := mh.svc.SetPlayerSkin(r.Context(), player.ID, hash, model); err != nil {
		slog.Error("handleAdminUploadSkin: setting skin", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	updated, err := mh.svc.GetPlayer(r.Context(), player.ID)
	if err != nil {
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

// handleAdminUploadSkinURL processes PUT /users/{id}/players/{pid}/skin/url (admin).
// @Summary      Upload player skin from URL (Admin only)
// @Description  Downloads a PNG skin file from the specified URL and sets it for the user's player.
// @Tags         Admin
// @Accept       json
// @Produce      json
// @Param        id path string true "User ID"
// @Param        pid path string true "Player ID"
// @Param        request body SkinURLRequest true "Skin URL configuration"
// @Success      200 {object} store.Player
// @Failure      400 {object} APIError
// @Failure      401 {object} APIError
// @Failure      403 {object} APIError
// @Failure      404 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /admin/users/{id}/players/{pid}/skin/url [put]
func (mh *managementHandler) handleAdminUploadSkinURL(w http.ResponseWriter, r *http.Request) {
	if mh.textures == nil {
		writeErrorJSON(w, http.StatusServiceUnavailable, "Unavailable", "texture storage not configured")
		return
	}
	if mh.cfg == nil || !mh.cfg.AllowTextureFromURL {
		writeErrorJSON(w, http.StatusForbidden, "Forbidden", "texture upload by URL is disabled")
		return
	}
	player := mh.adminPlayerCheck(w, r)
	if player == nil {
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

	limitBytes := 0
	if mh.cfg != nil {
		limitBytes = mh.cfg.BodyLimitBytes
	}
	pngBytes, img, fetchOK := fetchURL(w, req.URL, limitBytes)
	if !fetchOK {
		return
	}
	skinSizeLimit := 0
	if mh.cfg != nil {
		skinSizeLimit = mh.cfg.SkinSizeLimit
	}
	if err := textures.ValidateSkin(img, skinSizeLimit); err != nil {
		writeErrorJSON(w, http.StatusBadRequest, "BadRequest", err.Error())
		return
	}
	if req.Model == "" {
		req.Model = textures.DetectModel(img)
	}

	hash, err := mh.textures.Put(pngBytes)
	if err != nil {
		slog.Error("handleAdminUploadSkinURL: storing texture", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	if err := mh.svc.SetPlayerSkin(r.Context(), player.ID, hash, req.Model); err != nil {
		slog.Error("handleAdminUploadSkinURL: setting skin", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	updated, err := mh.svc.GetPlayer(r.Context(), player.ID)
	if err != nil {
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

// handleAdminDeleteSkin processes DELETE /users/{id}/players/{pid}/skin (admin).
// @Summary      Delete player skin (Admin only)
// @Description  Clears the skin for the specified user's player.
// @Tags         Admin
// @Produce      json
// @Param        id path string true "User ID"
// @Param        pid path string true "Player ID"
// @Success      200 {object} store.Player
// @Failure      401 {object} APIError
// @Failure      403 {object} APIError
// @Failure      404 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /admin/users/{id}/players/{pid}/skin [delete]
func (mh *managementHandler) handleAdminDeleteSkin(w http.ResponseWriter, r *http.Request) {
	player := mh.adminPlayerCheck(w, r)
	if player == nil {
		return
	}
	if err := mh.svc.ClearPlayerSkin(r.Context(), player.ID); err != nil {
		if errors.Is(err, accounts.ErrNotFound) {
			writeErrorJSON(w, http.StatusNotFound, "NotFound", "player not found")
			return
		}
		slog.Error("handleAdminDeleteSkin: clearing skin", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleAdminUploadCape processes PUT /users/{id}/players/{pid}/cape (admin).
// @Summary      Upload player cape (Admin only)
// @Description  Uploads a new PNG cape file for the specified user's player.
// @Tags         Admin
// @Accept       image/png
// @Produce      json
// @Param        id path string true "User ID"
// @Param        pid path string true "Player ID"
// @Success      200 {object} store.Player
// @Failure      400 {object} APIError
// @Failure      401 {object} APIError
// @Failure      403 {object} APIError
// @Failure      404 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /admin/users/{id}/players/{pid}/cape [put]
func (mh *managementHandler) handleAdminUploadCape(w http.ResponseWriter, r *http.Request) {
	if mh.textures == nil {
		writeErrorJSON(w, http.StatusServiceUnavailable, "Unavailable", "texture storage not configured")
		return
	}
	player := mh.adminPlayerCheck(w, r)
	if player == nil {
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
		slog.Error("handleAdminUploadCape: storing texture", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	if err := mh.svc.SetPlayerCape(r.Context(), player.ID, hash); err != nil {
		slog.Error("handleAdminUploadCape: setting cape", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	updated, err := mh.svc.GetPlayer(r.Context(), player.ID)
	if err != nil {
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

// handleAdminUploadCapeURL processes PUT /users/{id}/players/{pid}/cape/url (admin).
// @Summary      Upload player cape from URL (Admin only)
// @Description  Downloads a PNG cape file from the specified URL and sets it for the user's player.
// @Tags         Admin
// @Accept       json
// @Produce      json
// @Param        id path string true "User ID"
// @Param        pid path string true "Player ID"
// @Param        request body CapeURLRequest true "Cape URL configuration"
// @Success      200 {object} store.Player
// @Failure      400 {object} APIError
// @Failure      401 {object} APIError
// @Failure      403 {object} APIError
// @Failure      404 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /admin/users/{id}/players/{pid}/cape/url [put]
func (mh *managementHandler) handleAdminUploadCapeURL(w http.ResponseWriter, r *http.Request) {
	if mh.textures == nil {
		writeErrorJSON(w, http.StatusServiceUnavailable, "Unavailable", "texture storage not configured")
		return
	}
	if mh.cfg == nil || !mh.cfg.AllowTextureFromURL {
		writeErrorJSON(w, http.StatusForbidden, "Forbidden", "texture upload by URL is disabled")
		return
	}
	player := mh.adminPlayerCheck(w, r)
	if player == nil {
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

	limitBytes := 0
	if mh.cfg != nil {
		limitBytes = mh.cfg.BodyLimitBytes
	}
	pngBytes, img, fetchOK := fetchURL(w, req.URL, limitBytes)
	if !fetchOK {
		return
	}
	if err := textures.ValidateCape(img); err != nil {
		writeErrorJSON(w, http.StatusBadRequest, "BadRequest", err.Error())
		return
	}

	hash, err := mh.textures.Put(pngBytes)
	if err != nil {
		slog.Error("handleAdminUploadCapeURL: storing texture", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	if err := mh.svc.SetPlayerCape(r.Context(), player.ID, hash); err != nil {
		slog.Error("handleAdminUploadCapeURL: setting cape", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	updated, err := mh.svc.GetPlayer(r.Context(), player.ID)
	if err != nil {
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

// handleAdminDeleteCape processes DELETE /users/{id}/players/{pid}/cape (admin).
// @Summary      Delete player cape (Admin only)
// @Description  Clears the cape for the specified user's player.
// @Tags         Admin
// @Produce      json
// @Param        id path string true "User ID"
// @Param        pid path string true "Player ID"
// @Success      200 {object} store.Player
// @Failure      401 {object} APIError
// @Failure      403 {object} APIError
// @Failure      404 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /admin/users/{id}/players/{pid}/cape [delete]
func (mh *managementHandler) handleAdminDeleteCape(w http.ResponseWriter, r *http.Request) {
	player := mh.adminPlayerCheck(w, r)
	if player == nil {
		return
	}
	if err := mh.svc.ClearPlayerCape(r.Context(), player.ID); err != nil {
		if errors.Is(err, accounts.ErrNotFound) {
			writeErrorJSON(w, http.StatusNotFound, "NotFound", "player not found")
			return
		}
		slog.Error("handleAdminDeleteCape: clearing cape", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleListInvites processes GET /invites (admin).
// @Summary      List invites (Admin only)
// @Description  Returns a list of all active or used registration invite codes.
// @Tags         Admin
// @Produce      json
// @Success      200 {array} store.Invite
// @Failure      401 {object} APIError
// @Failure      403 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /admin/invites [get]
func (mh *managementHandler) handleListInvites(w http.ResponseWriter, r *http.Request) {
	invites, err := mh.svc.ListInvites(r.Context())
	if err != nil {
		slog.Error("handleListInvites: listing", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	if invites == nil {
		invites = []*store.Invite{}
	}
	writeJSON(w, http.StatusOK, invites)
}

// handleCreateInvite processes POST /invites (admin).
// Optional body: {"ttlSeconds": 3600}. Creates an invite using the authenticated admin's ID.
// @Summary      Create invite code (Admin only)
// @Description  Generates a new registration invite code with an optional TTL.
// @Tags         Admin
// @Accept       json
// @Produce      json
// @Param        request body CreateInviteRequest false "Invite settings"
// @Success      201 {object} store.Invite
// @Failure      401 {object} APIError
// @Failure      403 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /admin/invites [post]
func (mh *managementHandler) handleCreateInvite(w http.ResponseWriter, r *http.Request) {
	adminUser, _ := userFromContext(r.Context())

	var req CreateInviteRequest
	// Body is optional for invite creation; ignore decode errors gracefully.
	_ = json.NewDecoder(r.Body).Decode(&req)

	var ttl time.Duration
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}

	inv, err := mh.svc.CreateInvite(r.Context(), adminUser.ID, ttl)
	if err != nil {
		switch {
		case errors.Is(err, accounts.ErrNotAdmin):
			writeErrorJSON(w, http.StatusForbidden, "Forbidden", "admin access required")
		case errors.Is(err, accounts.ErrNotFound):
			writeErrorJSON(w, http.StatusNotFound, "NotFound", "admin user not found")
		default:
			slog.Error("handleCreateInvite: creating", "error", err)
			writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		}
		return
	}
	writeJSON(w, http.StatusCreated, inv)
}

// handleDeleteInvite processes DELETE /invites/{code} (admin).
// @Summary      Delete invite code (Admin only)
// @Description  Deletes/revokes a specific registration invite code.
// @Tags         Admin
// @Produce      json
// @Param        code path string true "Invite Code"
// @Success      204 "No Content"
// @Failure      401 {object} APIError
// @Failure      403 {object} APIError
// @Failure      404 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /admin/invites/{code} [delete]
func (mh *managementHandler) handleDeleteInvite(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	if err := mh.svc.DeleteInvite(r.Context(), code); err != nil {
		if errors.Is(err, accounts.ErrNotFound) {
			writeErrorJSON(w, http.StatusNotFound, "NotFound", fmt.Sprintf("invite %q not found", code))
			return
		}
		slog.Error("handleDeleteInvite: deleting", "code", code, "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

const resetTokenTTL = time.Hour

// handleAdminCreateResetToken processes POST /users/{id}/reset-token (admin).
// @Summary      Create password reset token (Admin only)
// @Description  Generates a single-use password reset link for the given user, returning it directly to the admin without sending any emails.
// @Tags         Admin
// @Produce      json
// @Param        id path string true "User ID"
// @Success      200 {object} ResetTokenResponse
// @Failure      404 {object} APIError
// @Failure      500 {object} APIError
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /admin/users/{id}/reset-token [post]
func (mh *managementHandler) handleAdminCreateResetToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	plaintext, err := mh.svc.CreatePasswordResetToken(r.Context(), id, resetTokenTTL)
	if err != nil {
		if errors.Is(err, accounts.ErrNotFound) {
			writeErrorJSON(w, http.StatusNotFound, "NotFound", "user not found")
			return
		}
		slog.Error("handleAdminCreateResetToken: creating", "id", id, "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}

	baseURL := strings.TrimSuffix(mh.cfg.BaseURL, "/")
	resetURL := baseURL + "/reset?token=" + url.QueryEscape(plaintext)

	resp := ResetTokenResponse{
		ResetURL:         resetURL,
		ExpiresInSeconds: int(resetTokenTTL.Seconds()),
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleResetPassword processes POST /reset-password (public).
// @Summary      Reset password via token
// @Description  Consumes a single-use password reset token and sets a new password. If successful, all active browser sessions and Yggdrasil tokens for the user are immediately revoked.
// @Tags         Account
// @Accept       json
// @Produce      json
// @Param        request body ResetPasswordRequest true "Reset password data"
// @Success      200 {object} map[string]string
// @Failure      400 {object} APIError
// @Failure      500 {object} APIError
// @Router       /reset-password [post]
func (mh *managementHandler) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	var req ResetPasswordRequest
	if !decodeRequest(w, r, &req) {
		return
	}

	userID, err := mh.svc.ResetPassword(r.Context(), req.Token, req.Password)
	if err != nil {
		if errors.Is(err, accounts.ErrInvalidToken) {
			writeErrorJSON(w, http.StatusBadRequest, "InvalidToken", "invalid, expired or already used token")
			return
		}
		if errors.Is(err, accounts.ErrWeakPassword) {
			writeErrorJSON(w, http.StatusBadRequest, "WeakPassword", err.Error())
			return
		}
		slog.Error("handleResetPassword: resetting password", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}

	// Forcibly revoke browser sessions and invalidate Yggdrasil tokens so old credentials stop working.
	if mh.sessions != nil {
		if err := mh.sessions.RevokeAllByUser(r.Context(), userID); err != nil {
			slog.Warn("handleResetPassword: revoking sessions", "id", userID, "error", err)
		}
	}
	if mh.tokens != nil {
		if err := mh.tokens.InvalidateAllByUser(r.Context(), userID); err != nil {
			slog.Warn("handleResetPassword: invalidating tokens", "id", userID, "error", err)
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleForgotPassword processes POST /forgot-password (public).
// @Summary      Request password reset email
// @Description  Initiates the password reset flow. Always returns 200 "ok" even if the email does not exist to prevent user enumeration. If the user exists, a password reset link is emailed.
// @Tags         Account
// @Accept       json
// @Produce      json
// @Param        request body ForgotPasswordRequest true "Forgot password data"
// @Success      200 {object} map[string]string
// @Failure      400 {object} APIError
// @Failure      500 {object} APIError
// @Router       /forgot-password [post]
func (mh *managementHandler) handleForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req ForgotPasswordRequest
	if !decodeRequest(w, r, &req) {
		return
	}

	// Always return 200 {"status": "ok"} to prevent user enumeration.
	defer writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})

	ctx := r.Context()
	u, err := mh.svc.GetUserByEmail(ctx, req.Email)
	if err != nil {
		slog.Warn("handleForgotPassword: user lookup failed", "email", req.Email, "error", err)
		return
	}

	plaintext, err := mh.svc.CreatePasswordResetToken(ctx, u.ID, time.Hour)
	if err != nil {
		slog.Warn("handleForgotPassword: creating reset token failed", "userID", u.ID, "error", err)
		return
	}

	link := mh.cfg.BaseURL + "/reset?token=" + url.QueryEscape(plaintext)
	subject, body := mailer.RenderActionEmail(mailer.ActionEmailData{
		Title:       "Reset your password",
		Intro:       "Confirm your identity to reset your password.",
		ButtonLabel: "Reset Password",
		ButtonURL:   link,
		Footer:      "If you did not request this, ignore this email.",
		ServerName:  mh.cfg.ServerName,
	})

	if err := mh.mailer.Send(ctx, u.Email, subject, body); err != nil {
		slog.Warn("handleForgotPassword: sending reset email failed", "email", u.Email, "error", err)
		return
	}
}

// handleVerifyEmail processes POST /verify-email (public).
// @Summary      Verify email address
// @Description  Consumes a single-use verification token to mark the user's email address as verified.
// @Tags         Account
// @Accept       json
// @Produce      json
// @Param        request body VerifyEmailRequest true "Verify email data"
// @Success      200 {object} map[string]string
// @Failure      400 {object} APIError
// @Failure      500 {object} APIError
// @Router       /verify-email [post]
func (mh *managementHandler) handleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	var req VerifyEmailRequest
	if !decodeRequest(w, r, &req) {
		return
	}

	_, err := mh.svc.VerifyEmail(r.Context(), req.Token)
	if err != nil {
		if errors.Is(err, accounts.ErrInvalidToken) {
			writeErrorJSON(w, http.StatusBadRequest, "InvalidToken", "invalid, expired or already used token")
			return
		}
		slog.Error("handleVerifyEmail: verifying email", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleResendVerification processes POST /resend-verification (public).
// @Summary      Resend email verification
// @Description  Resends the email verification link to the user if they are not yet verified. Always returns 200 "ok" even if the email does not exist.
// @Tags         Account
// @Accept       json
// @Produce      json
// @Param        request body ResendVerificationRequest true "Resend verification data"
// @Success      200 {object} map[string]string
// @Failure      400 {object} APIError
// @Failure      500 {object} APIError
// @Router       /resend-verification [post]
func (mh *managementHandler) handleResendVerification(w http.ResponseWriter, r *http.Request) {
	var req ResendVerificationRequest
	if !decodeRequest(w, r, &req) {
		return
	}

	// Always return 200 {"status": "ok"} to prevent user enumeration.
	defer writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})

	ctx := r.Context()
	u, err := mh.svc.GetUserByEmail(ctx, req.Email)
	if err != nil {
		slog.Warn("handleResendVerification: user lookup failed", "email", req.Email, "error", err)
		return
	}

	if u.EmailVerified {
		slog.Warn("handleResendVerification: user already verified", "userID", u.ID)
		return
	}

	plaintext, err := mh.svc.CreateEmailVerifyToken(ctx, u.ID, 24*time.Hour)
	if err != nil {
		slog.Warn("handleResendVerification: creating email verification token failed", "userID", u.ID, "error", err)
		return
	}

	link := mh.cfg.BaseURL + "/verify?token=" + url.QueryEscape(plaintext)
	subject, body := mailer.RenderActionEmail(mailer.ActionEmailData{
		Title:       "Verify your email",
		Intro:       "Welcome to " + mh.cfg.ServerName + "! Confirm your email address to activate your account.",
		ButtonLabel: "Verify Email",
		ButtonURL:   link,
		Footer:      "You will not be able to sign in until your email is verified.",
		ServerName:  mh.cfg.ServerName,
	})

	if err := mh.mailer.Send(ctx, u.Email, subject, body); err != nil {
		slog.Warn("handleResendVerification: sending verification email failed", "email", u.Email, "error", err)
		return
	}
}

// handleAdminBackup godoc
// @Summary      Download a complete backup archive
// @Description  Creates a consistent SQLite snapshot, bundles it with the signing key, textures, and config, and streams a .tar.gz archive.
// @Tags         Admin
// @Produce      application/gzip
// @Success      200 {file} file "backup archive"
// @Failure      500 {object} APIError "Internal server error"
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /admin/backup [get]
func (mh *managementHandler) handleAdminBackup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	tmpDir, err := os.MkdirTemp("", "minecrauth-backup-*")
	if err != nil {
		slog.Error("failed to create temporary directory for backup", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "failed to create backup")
		return
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	snapshotPath := filepath.Join(tmpDir, "snapshot.db")
	if err := mh.st.BackupTo(ctx, snapshotPath); err != nil {
		slog.Error("failed to create consistent database snapshot", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "failed to create consistent database snapshot")
		return
	}

	filename := fmt.Sprintf("minecrauth-backup-%s.tar.gz", time.Now().UTC().Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	w.WriteHeader(http.StatusOK)

	// Stream the archive
	if err := backup.CreateArchive(w, mh.cfg.StateDir, snapshotPath, mh.configPath); err != nil {
		slog.Error("error during streaming backup archive creation", "error", err)
		// We cannot change HTTP status because 200 was already written. Just log it.
		return
	}
}

// handleAdminRestore godoc
// @Summary      Upload a backup archive to stage for restore
// @Description  Reads a .tar.gz archive, validates its structure, and stages it to be applied at next startup.
// @Tags         Admin
// @Accept       application/x-gzip
// @Accept       application/octet-stream
// @Produce      application/json
// @Success      200 {object} map[string]string "restore staged successfully"
// @Failure      400 {object} APIError "Invalid backup file"
// @Failure      500 {object} APIError "Internal server error"
// @Security     BasicAuth
// @Security     CSRFToken
// @Router       /admin/restore [post]
func (mh *managementHandler) handleAdminRestore(w http.ResponseWriter, r *http.Request) {
	// 1. Read raw request body up to 512 MiB into a temp file
	limitReader := http.MaxBytesReader(w, r.Body, 512*1024*1024)
	defer func() { _ = limitReader.Close() }()

	tmpDir, err := os.MkdirTemp("", "minecrauth-restore-*")
	if err != nil {
		slog.Error("failed to create temporary directory for restore", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "failed to create restore temporary space")
		return
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	tempFile := filepath.Join(tmpDir, "upload.tar.gz")
	f, err := os.OpenFile(tempFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		slog.Error("failed to create restore upload file", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "failed to create upload file")
		return
	}

	if _, err := io.Copy(f, limitReader); err != nil {
		_ = f.Close()
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeErrorJSON(w, http.StatusRequestEntityTooLarge, "TooLarge", "restore archive exceeds 512 MiB limit")
			return
		}
		slog.Error("failed to copy uploaded restore archive to temp file", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "failed to write uploaded archive")
		return
	}
	_ = f.Close()

	// 2. Validate
	fOpen, err := os.Open(tempFile)
	if err != nil {
		slog.Error("failed to open temp restore file for validation", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "failed to read backup file for validation")
		return
	}
	defer func() { _ = fOpen.Close() }()

	if err := backup.ValidateArchive(fOpen); err != nil {
		slog.Warn("uploaded restore archive validation failed", "error", err)
		writeErrorJSON(w, http.StatusBadRequest, "InvalidBackup", fmt.Sprintf("invalid backup archive: %v", err))
		return
	}

	// 3. Move/copy the validated archive to .restore-pending.tar.gz in StateDir
	pendingPath := filepath.Join(mh.cfg.StateDir, ".restore-pending.tar.gz")

	// Ensure StateDir exists
	if err := os.MkdirAll(mh.cfg.StateDir, 0o755); err != nil {
		slog.Error("failed to ensure state directory exists for staging", "path", mh.cfg.StateDir, "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "failed to stage restore")
		return
	}

	if err := moveOrCopyFile(tempFile, pendingPath); err != nil {
		slog.Error("failed to stage restore archive", "from", tempFile, "to", pendingPath, "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "failed to stage backup file")
		return
	}

	// 4. Respond 200 JSON
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"message": "restore staged; restart the server to apply",
	})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	if _, err = io.Copy(out, in); err != nil {
		return err
	}
	return nil
}

func moveOrCopyFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	return copyFile(src, dst)
}
