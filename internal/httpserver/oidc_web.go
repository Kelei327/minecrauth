// Copyright 2025 - Alby Hernández and the minecrauth contributors
// SPDX-License-Identifier: Apache-2.0

package httpserver

import (
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strings"

	"github.com/achetronic/minecrauth/internal/auth"
)

const (
	oidcStateCookie    = "oidc_state"
	oidcVerifierCookie = "oidc_verifier"
)

// handleOAuthLogin starts the OIDC browser flow.
// @Summary      OIDC browser login
// @Description  Initiates OIDC login flow by redirecting the browser to the Identity Provider.
// @Tags         OIDC
// @Produce      json
// @Success      302 "Redirect to Identity Provider"
// @Failure      404 {object} APIError
// @Router       /oauth/login [get]
func (mh *managementHandler) handleOAuthLogin(w http.ResponseWriter, r *http.Request) {
	if mh.oidcBrowser == nil {
		writeErrorJSON(w, http.StatusNotFound, "NotFound", "OIDC browser flow not configured")
		return
	}

	state, err := auth.GenerateState()
	if err != nil {
		slog.Error("handleOAuthLogin: generating state", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "failed to start authorization")
		return
	}

	verifier, challenge, err := auth.GeneratePKCE()
	if err != nil {
		slog.Error("handleOAuthLogin: generating PKCE", "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "failed to start authorization")
		return
	}

	secure := strings.HasPrefix(mh.cfg.BaseURL, "https")

	http.SetCookie(w, &http.Cookie{
		Name:     oidcStateCookie,
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     oidcVerifierCookie,
		Value:    verifier,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})

	http.Redirect(w, r, mh.oidcBrowser.AuthCodeURL(state, challenge), http.StatusFound)
}

// handleOAuthCallback completes the flow.
// @Summary      OIDC callback
// @Description  Handles the callback from OIDC Identity Provider, exchanges code for token, starts session, and redirects to /players.
// @Tags         OIDC
// @Produce      json
// @Param        code query string false "Auth code from provider"
// @Param        state query string false "State for CSRF validation"
// @Success      302 "Redirect to /players"
// @Failure      400 {object} APIError
// @Router       /oauth/callback [get]
func (mh *managementHandler) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	if mh.oidcBrowser == nil {
		writeErrorJSON(w, http.StatusNotFound, "NotFound", "OIDC browser flow not configured")
		return
	}

	secure := strings.HasPrefix(mh.cfg.BaseURL, "https")

	clearTempCookie := func(name string) {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
		})
	}

	if errStr := r.URL.Query().Get("error"); errStr != "" {
		slog.Warn("handleOAuthCallback: IdP returned error", "error", errStr)
		clearTempCookie(oidcStateCookie)
		clearTempCookie(oidcVerifierCookie)
		http.Redirect(w, r, "/login?error=oidc", http.StatusFound)
		return
	}

	stateParam := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	stateCookie, err1 := r.Cookie(oidcStateCookie)
	verifierCookie, err2 := r.Cookie(oidcVerifierCookie)

	if err1 != nil || err2 != nil {
		slog.Warn("handleOAuthCallback: missing oidc cookies", "stateErr", err1, "verifierErr", err2)
		writeErrorJSON(w, http.StatusBadRequest, "BadRequest", "missing oidc state")
		return
	}

	clearTempCookie(oidcStateCookie)
	clearTempCookie(oidcVerifierCookie)

	if len(stateParam) == 0 || len(stateCookie.Value) == 0 || len(stateParam) != len(stateCookie.Value) ||
		subtle.ConstantTimeCompare([]byte(stateParam), []byte(stateCookie.Value)) != 1 {
		slog.Warn("handleOAuthCallback: state mismatch")
		writeErrorJSON(w, http.StatusBadRequest, "BadRequest", "state mismatch")
		return
	}

	user, err := mh.oidcBrowser.Exchange(r.Context(), code, verifierCookie.Value)
	if err != nil {
		slog.Warn("handleOAuthCallback: code exchange failed", "error", err)
		http.Redirect(w, r, "/login?error=oidc", http.StatusFound)
		return
	}

	sess, err := mh.sessions.Create(r.Context(), user.ID, nil)
	if err != nil {
		slog.Error("handleOAuthCallback: creating session", "user_id", user.ID, "error", err)
		writeErrorJSON(w, http.StatusInternalServerError, "InternalError", "failed to create session")
		return
	}

	mh.setSessionCookie(w, sess.Token, sess.ExpiresAt)
	http.Redirect(w, r, "/players", http.StatusFound)
}
