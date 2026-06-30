// Copyright 2025 - Alby Hernández and the minecrauth contributors
// SPDX-License-Identifier: Apache-2.0

// Package httpserver: web.go contains the browser Web UI API handlers.
// Routes are mounted under /web/api and are used exclusively by the Vue 3 Web UI.
// All routes return JSON; session state is carried in an HttpOnly cookie.
package httpserver

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/achetronic/minecrauth/internal/accounts"
	"github.com/achetronic/minecrauth/internal/auth"
)

// webAPIPrefix is the path under which all Web UI API routes are mounted.
const webAPIPrefix = "/web/api"

// setSessionCookie writes the session cookie.
func (mh *managementHandler) setSessionCookie(w http.ResponseWriter, token string, expires time.Time) {
	secure := strings.HasPrefix(mh.cfg.BaseURL, "https")
	ttl := int(time.Until(expires).Seconds())
	if ttl < 0 {
		ttl = 0
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   ttl,
	})
}

// clearSessionCookie removes the session cookie.
func (mh *managementHandler) clearSessionCookie(w http.ResponseWriter) {
	secure := strings.HasPrefix(mh.cfg.BaseURL, "https")
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// buildWebAPIMux returns the sub-mux for the browser Web UI API.
// It is mounted at /web/api in buildRootHandler.
func (mh *managementHandler) buildWebAPIMux() http.Handler {
	mux := http.NewServeMux()

	// POST /web/api/login — exchange email+password for a session cookie.
	mux.HandleFunc("POST /login", mh.handleWebLogin)

	// POST /web/api/login-totp — complete two-step login using TOTP.
	mux.HandleFunc("POST /login-totp", mh.handleWebLoginTOTP)

	// POST /web/api/logout — revoke the current session (CSRF-protected).
	mux.HandleFunc("POST /logout", mh.handleWebLogout)

	// GET /web/api/session — return current session user + CSRF token.
	mux.HandleFunc("GET /session", mh.handleWebSession)

	// GET /web/api/config — return public server config flags.
	mux.HandleFunc("GET /config", mh.handleWebConfig)

	// POST /web/api/stop-impersonation — stop impersonating a user.
	mux.HandleFunc("POST /stop-impersonation", mh.handleWebStopImpersonation)

	return mux
}

// handleWebLogin processes POST /web/api/login.
// @Summary      Web login
// @Description  Authenticates the user and sets a session cookie.
// @Tags         Session
// @Accept       json
// @Produce      json
// @Param        request body LoginRequest true "Login credentials"
// @Success      200 {object} map[string]any "Session details including user profile and csrfToken"
// @Failure      401 {object} APIError
// @Router       /web/api/login [post]
func (mh *managementHandler) handleWebLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if !decodeRequest(w, r, &req) {
		return
	}

	user, err := mh.authn.Authenticate(r.Context(), req.Email, req.Password)
	if err != nil {
		if errors.Is(err, auth.ErrEmailNotVerified) {
			writeErrorJSON(w, http.StatusForbidden, "EmailNotVerified", "please verify your email address before signing in")
			return
		}
		if errors.Is(err, auth.ErrInvalidCredentials) {
			writeErrorJSON(w, http.StatusUnauthorized, "Unauthorized", "invalid credentials")
			return
		}
		slog.Error("handleWebLogin: authenticating", "email", req.Email, "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}

	if user.TOTPEnabled {
		token, err := mh.svc.CreateTOTPPendingToken(r.Context(), user.ID, 5*time.Minute)
		if err != nil {
			slog.Error("handleWebLogin: creating TOTP pending token", "user_id", user.ID, "error", err)
			writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"totpRequired": true,
			"totpToken":    token,
		})
		return
	}

	sess, err := mh.sessions.Create(r.Context(), user.ID, nil)
	if err != nil {
		slog.Error("handleWebLogin: creating session", "user_id", user.ID, "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}

	mh.setSessionCookie(w, sess.Token, sess.ExpiresAt)

	writeJSON(w, http.StatusOK, map[string]any{
		"user":      user,
		"csrfToken": sess.CSRFToken,
	})
}

// handleWebLoginTOTP processes POST /web/api/login-totp.
// @Summary      Web TOTP login
// @Description  Completes two-step login using a TOTP token and code, then sets a session cookie.
// @Tags         Session
// @Accept       json
// @Produce      json
// @Param        request body LoginTOTPRequest true "Login TOTP request"
// @Success      200 {object} map[string]any "Session details including user profile and csrfToken"
// @Failure      401 {object} APIError
// @Router       /web/api/login-totp [post]
func (mh *managementHandler) handleWebLoginTOTP(w http.ResponseWriter, r *http.Request) {
	var req LoginTOTPRequest
	if !decodeRequest(w, r, &req) {
		return
	}

	userID, err := mh.svc.ValidateTOTPPendingToken(r.Context(), req.TotpToken)
	if err != nil {
		writeErrorJSON(w, http.StatusUnauthorized, "Unauthorized", "invalid or expired authentication token")
		return
	}

	if err := mh.svc.VerifyTOTP(r.Context(), userID, req.Code); err != nil {
		if errors.Is(err, accounts.ErrInvalidTOTP) {
			writeErrorJSON(w, http.StatusUnauthorized, "InvalidTOTP", "invalid authentication code")
			return
		}
		slog.Error("handleWebLoginTOTP: verifying TOTP", "user_id", userID, "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}

	// Consume the pending token on successful verification
	if err := mh.svc.ConsumeTOTPPendingToken(r.Context(), req.TotpToken); err != nil {
		slog.Error("handleWebLoginTOTP: consuming TOTP pending token", "user_id", userID, "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}

	// load the user and check if blocked
	user, err := mh.svc.GetUser(r.Context(), userID)
	if err != nil {
		if errors.Is(err, accounts.ErrNotFound) {
			writeErrorJSON(w, http.StatusUnauthorized, "Unauthorized", "user not found")
			return
		}
		slog.Error("handleWebLoginTOTP: getting user", "user_id", userID, "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}

	if user.Blocked {
		writeErrorJSON(w, http.StatusUnauthorized, "Unauthorized", "user account is blocked")
		return
	}

	sess, err := mh.sessions.Create(r.Context(), user.ID, nil)
	if err != nil {
		slog.Error("handleWebLoginTOTP: creating session", "user_id", user.ID, "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}

	mh.setSessionCookie(w, sess.Token, sess.ExpiresAt)

	writeJSON(w, http.StatusOK, map[string]any{
		"user":      user,
		"csrfToken": sess.CSRFToken,
	})
}

// handleWebLogout processes POST /web/api/logout.
// @Summary      Web logout
// @Description  Revokes and clears the current browser session.
// @Tags         Session
// @Produce      json
// @Success      204 "No Content"
// @Failure      403 {object} APIError
// @Router       /web/api/logout [post]
func (mh *managementHandler) handleWebLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil && cookie.Value != "" {
		sess, err := mh.sessions.Validate(r.Context(), cookie.Value)
		if err == nil {
			provided := r.Header.Get("X-CSRF-Token")
			if !auth.ValidCSRF(sess.CSRFToken, provided) {
				writeErrorJSON(w, http.StatusForbidden, "Forbidden", "missing or invalid CSRF token")
				return
			}
			_ = mh.sessions.Revoke(r.Context(), sess.Token)
		}
	}
	mh.clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

// handleWebSession processes GET /web/api/session.
// @Summary      Get current web session
// @Description  Validates the session cookie and returns current session details including the user profile and csrfToken.
// @Tags         Session
// @Produce      json
// @Success      200 {object} map[string]any "Session status and details"
// @Failure      401 {object} APIError
// @Router       /web/api/session [get]
func (mh *managementHandler) handleWebSession(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		writeErrorJSON(w, http.StatusUnauthorized, "Unauthorized", "no session")
		return
	}

	sess, err := mh.sessions.Validate(r.Context(), cookie.Value)
	if err != nil {
		mh.clearSessionCookie(w)
		writeErrorJSON(w, http.StatusUnauthorized, "Unauthorized", "invalid session")
		return
	}

	user, err := mh.svc.GetUser(r.Context(), sess.UserID)
	if err != nil {
		mh.clearSessionCookie(w)
		writeErrorJSON(w, http.StatusUnauthorized, "Unauthorized", "invalid session")
		return
	}
	if user.Blocked {
		_ = mh.sessions.Revoke(r.Context(), sess.Token)
		mh.clearSessionCookie(w)
		writeErrorJSON(w, http.StatusUnauthorized, "Unauthorized", "invalid session")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"user":          user,
		"csrfToken":     sess.CSRFToken,
		"impersonating": sess.ImpersonatedBy != nil,
	})
}

// handleWebConfig processes GET /web/api/config.
// @Summary      Get server UI config
// @Description  Returns configuration flags that control the Web UI features (e.g. OIDC, Skin/Cape options, invite requirements).
// @Tags         Session
// @Produce      json
// @Success      200 {object} map[string]any "UI configuration parameters"
// @Router       /web/api/config [get]
func (mh *managementHandler) handleWebConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		// oidcEnabled is true only when the browser OIDC flow is configured and active.
		// This gates the UI "Login with OIDC" button.
		"oidcEnabled":              mh.oidcBrowser != nil,
		"allowSkins":               mh.cfg.AllowSkins,
		"allowCapes":               mh.cfg.AllowCapes,
		"allowTextureFromURL":      mh.cfg.AllowTextureFromURL,
		"requireInvite":            mh.cfg.RequireInvite,
		"requireEmailVerification": mh.cfg.RequireEmailVerification,
		"smtpEnabled":              mh.cfg.SMTPHost != "",
	})
}

// handleWebStopImpersonation processes POST /web/api/stop-impersonation.
// @Summary      Stop impersonation
// @Description  Reverts an impersonated session back to the admin session.
// @Tags         Session
// @Produce      json
// @Success      200 {object} map[string]any "Restored admin session details"
// @Failure      400 {object} APIError
// @Failure      401 {object} APIError
// @Failure      403 {object} APIError
// @Router       /web/api/stop-impersonation [post]
func (mh *managementHandler) handleWebStopImpersonation(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		writeErrorJSON(w, http.StatusUnauthorized, "Unauthorized", "no session")
		return
	}

	sess, err := mh.sessions.Validate(r.Context(), cookie.Value)
	if err != nil {
		mh.clearSessionCookie(w)
		writeErrorJSON(w, http.StatusUnauthorized, "Unauthorized", "invalid session")
		return
	}

	// CSRF check
	provided := r.Header.Get("X-CSRF-Token")
	if !auth.ValidCSRF(sess.CSRFToken, provided) {
		writeErrorJSON(w, http.StatusForbidden, "Forbidden", "missing or invalid CSRF token")
		return
	}

	if sess.ImpersonatedBy == nil {
		writeErrorJSON(w, http.StatusBadRequest, "BadRequest", "not impersonating")
		return
	}

	adminID := *sess.ImpersonatedBy

	// Revoke current impersonation session
	_ = mh.sessions.Revoke(r.Context(), sess.Token)

	// Create fresh session for admin
	newSess, err := mh.sessions.Create(r.Context(), adminID, nil)
	if err != nil {
		mh.clearSessionCookie(w)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}

	adminUser, err := mh.svc.GetUser(r.Context(), adminID)
	if err != nil {
		mh.clearSessionCookie(w)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "internal server error")
		return
	}

	mh.setSessionCookie(w, newSess.Token, newSess.ExpiresAt)

	writeJSON(w, http.StatusOK, map[string]any{
		"user":      adminUser,
		"csrfToken": newSess.CSRFToken,
	})
}
