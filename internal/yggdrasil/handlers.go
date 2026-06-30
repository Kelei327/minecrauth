// SPDX-License-Identifier: Apache-2.0

package yggdrasil

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/achetronic/minecrauth/internal/accounts"
	"github.com/achetronic/minecrauth/internal/auth"
	"github.com/achetronic/minecrauth/internal/fallback"
	"github.com/achetronic/minecrauth/internal/signing"
	"github.com/achetronic/minecrauth/internal/store"
)

// Handler holds all dependencies for the Yggdrasil protocol endpoints.
// It is the single point of assembly for the protocol layer.
type Handler struct {
	tokens       *auth.TokenService
	authn        auth.Authenticator
	accounts     *accounts.Service
	keys         *signing.KeyManager
	serverName   string
	domain       string
	baseURL      string
	cache        *joinCache
	fallback     *fallback.Client // nil when fallback is not configured
	forwardSkins bool             // inject fallback skin when local player has none
	offlineSkins bool             // resolve offline UUIDs to local players
	allowSkins   bool             // advertise skin upload capability in profiles
	allowCapes   bool             // advertise cape upload capability in profiles
	version      string           // implementation version advertised in metadata (build-stamped)
}

// NewHandler constructs a ready-to-use Handler. serverName is the human-readable name
// advertised in the authlib-injector metadata; domain is the skin domain listed there;
// baseURL is the external root URL used to form texture URLs in profile responses.
//
// fb may be nil, in which case all fallback features are disabled and behavior is
// identical to a vanilla minecrauth install. forwardSkins and offlineSkins are ignored
// when fb is nil (they require a fallback server to be useful for skins, but OfflineSkins
// works locally via the offline-UUID scan so it is honored regardless).
func NewHandler(
	tokens *auth.TokenService,
	authn auth.Authenticator,
	accs *accounts.Service,
	keys *signing.KeyManager,
	serverName string,
	domain string,
	baseURL string,
	fb *fallback.Client,
	forwardSkins bool,
	offlineSkins bool,
	allowSkins bool,
	allowCapes bool,
	version string,
) *Handler {
	return &Handler{
		tokens:       tokens,
		authn:        authn,
		accounts:     accs,
		keys:         keys,
		serverName:   serverName,
		domain:       domain,
		baseURL:      baseURL,
		cache:        newJoinCache(),
		fallback:     fb,
		forwardSkins: forwardSkins,
		offlineSkins: offlineSkins,
		allowSkins:   allowSkins,
		allowCapes:   allowCapes,
		version:      version,
	}
}

// Routes returns an http.ServeMux with all Yggdrasil protocol routes registered.
// The method+path patterns require Go 1.22 or later.
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()

	// Metadata root: authlib-injector fetches this first.
	mux.HandleFunc("GET /{$}", h.handleMetadata)

	// Auth server endpoints.
	mux.HandleFunc("POST /authserver/authenticate", h.handleAuthenticate)
	mux.HandleFunc("POST /authserver/refresh", h.handleRefresh)
	mux.HandleFunc("POST /authserver/validate", h.handleValidate)
	mux.HandleFunc("POST /authserver/invalidate", h.handleInvalidate)
	mux.HandleFunc("POST /authserver/signout", h.handleSignout)

	// Session server endpoints.
	mux.HandleFunc("POST /sessionserver/session/minecraft/join", h.handleJoin)
	mux.HandleFunc("GET /sessionserver/session/minecraft/hasJoined", h.handleHasJoined)
	mux.HandleFunc("GET /sessionserver/session/minecraft/profile/{id}", h.handleProfile)

	// Mojang-compatible bulk name-to-UUID lookup.
	mux.HandleFunc("POST /api/profiles/minecraft", h.handleProfilesBulk)

	// Minecraft 1.19+ signed-chat player certificates.
	mux.HandleFunc("POST /minecraftservices/player/certificates", h.handlePlayerCertificates)

	return mux
}

// handleMetadata serves the authlib-injector metadata document at GET /.
// @Summary      Yggdrasil Metadata
// @Description  Serves the authlib-injector metadata document including implementation version and public signing keys.
// @Tags         Yggdrasil
// @Produce      json
// @Success      200 {object} MetadataResponse
// @Router       /authlib-injector/ [get]
func (h *Handler) handleMetadata(w http.ResponseWriter, r *http.Request) {
	resp := MetadataResponse{
		Meta: metaMeta{
			ServerName:            h.serverName,
			ImplementationName:    "minecrauth",
			ImplementationVersion: h.version,
			Links: &metaLinks{
				Homepage: h.baseURL,
				Register: h.baseURL + "/login",
			},
			EnableProfileKey: true,
		},
		SkinDomains:        []string{h.domain},
		SignaturePublickey: h.keys.PublicKeyPEM(),
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleAuthenticate processes POST /authserver/authenticate.
// @Summary      Authenticate player
// @Description  Authenticates a player using username/password, issues access and client tokens.
// @Tags         Yggdrasil
// @Accept       json
// @Produce      json
// @Param        request body AuthenticateRequest true "Authentication credentials"
// @Success      200 {object} AuthenticateResponse
// @Failure      403 {object} YggError "ForbiddenOperationException: invalid credentials"
// @Router       /authlib-injector/authserver/authenticate [post]
func (h *Handler) handleAuthenticate(w http.ResponseWriter, r *http.Request) {
	var req AuthenticateRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	ctx := r.Context()

	user, err := h.authn.Authenticate(ctx, req.Username, req.Password)
	if err != nil {
		if errors.Is(err, auth.ErrEmailNotVerified) {
			writeYggError(w, http.StatusForbidden, "ForbiddenOperationException",
				"Email address not verified. Check your inbox for a verification link.", "")
			return
		}
		if errors.Is(err, auth.ErrInvalidCredentials) {
			writeYggError(w, http.StatusForbidden, "ForbiddenOperationException",
				"Invalid credentials. Invalid username or password.", "")
			return
		}
		slog.Error("authenticate: authenticating user", "error", err)
		writeYggError(w, http.StatusInternalServerError, "InternalServerError", "Internal server error.", "")
		return
	}

	players, err := h.accounts.ListPlayersByUser(ctx, user.ID)
	if err != nil {
		slog.Error("authenticate: listing players", "error", err)
		writeYggError(w, http.StatusInternalServerError, "InternalServerError", "Internal server error.", "")
		return
	}

	available := make([]ProfileStub, 0, len(players))
	for _, p := range players {
		available = append(available, ProfileStub{ID: undash(p.UUID), Name: p.Name})
	}

	// Auto-select the sole player; if there are zero or more than one, leave unset.
	var selectedProfile *ProfileStub
	var playerID *string
	if len(players) == 1 {
		stub := ProfileStub{ID: undash(players[0].UUID), Name: players[0].Name}
		selectedProfile = &stub
		playerID = &players[0].ID
	}

	tok, err := h.tokens.Issue(ctx, user.ID, playerID, req.ClientToken)
	if err != nil {
		slog.Error("authenticate: issuing token", "error", err)
		writeYggError(w, http.StatusInternalServerError, "InternalServerError", "Internal server error.", "")
		return
	}

	resp := AuthenticateResponse{
		AccessToken:       tok.AccessToken,
		ClientToken:       tok.ClientToken,
		AvailableProfiles: available,
		SelectedProfile:   selectedProfile,
	}
	if req.RequestUser {
		resp.User = &UserResponse{ID: user.ID, Properties: []UserProperty{}}
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleRefresh processes POST /authserver/refresh.
// @Summary      Refresh token
// @Description  Rotates the access token and optionally client token, returning new ones.
// @Tags         Yggdrasil
// @Accept       json
// @Produce      json
// @Param        request body RefreshRequest true "Refresh request parameters"
// @Success      200 {object} RefreshResponse
// @Failure      403 {object} YggError "ForbiddenOperationException: invalid token"
// @Router       /authlib-injector/authserver/refresh [post]
func (h *Handler) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req RefreshRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	ctx := r.Context()

	// When a user owns several players, the launcher re-issues refresh with the
	// chosen profile in the body so the token gets bound to it. Resolve it to an
	// internal player id; ownership is enforced inside tokens.Refresh.
	var selectedPlayerID *string
	if req.SelectedProfile != nil {
		dashedUUID := redash(req.SelectedProfile.ID)
		player, perr := h.accounts.GetPlayerByUUID(ctx, dashedUUID)
		if perr != nil {
			writeYggError(w, http.StatusForbidden, "ForbiddenOperationException", "Invalid profile.", "")
			return
		}
		selectedPlayerID = &player.ID
	}

	newTok, err := h.tokens.Refresh(ctx, req.AccessToken, req.ClientToken, selectedPlayerID)
	if err != nil {
		if errors.Is(err, auth.ErrTokenInvalid) || errors.Is(err, auth.ErrTokenExpired) || errors.Is(err, auth.ErrProfileNotOwned) {
			writeYggError(w, http.StatusForbidden, "ForbiddenOperationException", "Invalid token.", "")
			return
		}
		slog.Error("refresh: refreshing token", "error", err)
		writeYggError(w, http.StatusInternalServerError, "InternalServerError", "Internal server error.", "")
		return
	}

	resp := RefreshResponse{
		AccessToken: newTok.AccessToken,
		ClientToken: newTok.ClientToken,
	}

	if newTok.PlayerID != nil {
		player, err := h.accounts.GetPlayer(ctx, *newTok.PlayerID)
		if err == nil {
			stub := ProfileStub{ID: undash(player.UUID), Name: player.Name}
			resp.SelectedProfile = &stub
		}
	}

	if req.RequestUser {
		user, err := h.accounts.GetUser(ctx, newTok.UserID)
		if err == nil {
			resp.User = &UserResponse{ID: user.ID, Properties: []UserProperty{}}
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleValidate processes POST /authserver/validate.
// @Summary      Validate token
// @Description  Validates the provided accessToken.
// @Tags         Yggdrasil
// @Accept       json
// @Produce      json
// @Param        request body ValidateRequest true "Validate request parameters"
// @Success      204 "Token is valid"
// @Failure      403 {object} YggError "ForbiddenOperationException: invalid token"
// @Router       /authlib-injector/authserver/validate [post]
func (h *Handler) handleValidate(w http.ResponseWriter, r *http.Request) {
	var req ValidateRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	if err := h.tokens.Validate(r.Context(), req.AccessToken, req.ClientToken); err != nil {
		writeYggError(w, http.StatusForbidden, "ForbiddenOperationException", "Invalid token.", "")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleInvalidate processes POST /authserver/invalidate.
// @Summary      Invalidate token
// @Description  Invalidates/revokes the provided accessToken (idempotent).
// @Tags         Yggdrasil
// @Accept       json
// @Produce      json
// @Param        request body InvalidateRequest true "Invalidate request parameters"
// @Success      204 "Token invalidated"
// @Router       /authlib-injector/authserver/invalidate [post]
func (h *Handler) handleInvalidate(w http.ResponseWriter, r *http.Request) {
	var req InvalidateRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	// Errors are intentionally swallowed: the spec mandates idempotency.
	_ = h.tokens.Invalidate(r.Context(), req.AccessToken, req.ClientToken)
	w.WriteHeader(http.StatusNoContent)
}

// handleSignout processes POST /authserver/signout.
// @Summary      Sign out user
// @Description  Authenticates and invalidates all active tokens for the user.
// @Tags         Yggdrasil
// @Accept       json
// @Produce      json
// @Param        request body SignoutRequest true "Signout request parameters"
// @Success      204 "User signed out and all tokens invalidated"
// @Failure      403 {object} YggError "ForbiddenOperationException: invalid credentials"
// @Router       /authlib-injector/authserver/signout [post]
func (h *Handler) handleSignout(w http.ResponseWriter, r *http.Request) {
	var req SignoutRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	ctx := r.Context()

	user, err := h.authn.Authenticate(ctx, req.Username, req.Password)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			writeYggError(w, http.StatusForbidden, "ForbiddenOperationException",
				"Invalid credentials. Invalid username or password.", "")
			return
		}
		slog.Error("signout: authenticating user", "error", err)
		writeYggError(w, http.StatusInternalServerError, "InternalServerError", "Internal server error.", "")
		return
	}

	if err := h.tokens.InvalidateAllByUser(ctx, user.ID); err != nil {
		slog.Error("signout: invalidating all tokens", "error", err)
		writeYggError(w, http.StatusInternalServerError, "InternalServerError", "Internal server error.", "")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleJoin processes POST /sessionserver/session/minecraft/join.
// @Summary      Join server
// @Description  Informs the sessionserver that a player is joining a multiplayer server.
// @Tags         Yggdrasil
// @Accept       json
// @Produce      json
// @Param        request body JoinRequest true "Join request parameters"
// @Success      204 "Join recorded"
// @Failure      403 {object} YggError "ForbiddenOperationException: invalid token or profile"
// @Router       /authlib-injector/sessionserver/session/minecraft/join [post]
func (h *Handler) handleJoin(w http.ResponseWriter, r *http.Request) {
	var req JoinRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	ctx := r.Context()

	if err := h.tokens.Validate(ctx, req.AccessToken, ""); err != nil {
		writeYggError(w, http.StatusForbidden, "ForbiddenOperationException", "Invalid token.", "")
		return
	}

	// Convert the wire-format undashed UUID to the canonical dashed form for store lookup.
	dashedUUID := redash(req.SelectedProfile)
	player, err := h.accounts.GetPlayerByUUID(ctx, dashedUUID)
	if err != nil {
		writeYggError(w, http.StatusForbidden, "ForbiddenOperationException", "Invalid profile.", "")
		return
	}

	h.cache.set(req.ServerID, player.Name, player.UUID)
	w.WriteHeader(http.StatusNoContent)
}

// handleHasJoined processes GET /sessionserver/session/minecraft/hasJoined.
//
// Local path: looks up the pending join by serverId; if the stored player name matches
// the username query parameter, returns the full signed profile.
//
// Mixed-auth path (fallback configured): if the local join cache has no matching entry,
// each configured fallback server (with EnableAuthentication=true) is queried in order.
// The first 200 response wins. DenyUnknownUsers on a fallback server acts as a
// whitelist: the profile is returned only when a local player with that username also
// exists on this instance. Without DenyUnknownUsers any player authenticated by that
// fallback may join.
//
// Returns 204 (empty body) on any failure, which is how vanilla signals "not joined".
// @Summary      Has joined server
// @Description  Queries the sessionserver to verify if a player has joined a multiplayer server.
// @Tags         Yggdrasil
// @Produce      json
// @Param        username query string true "Minecraft player username"
// @Param        serverId query string true "Server ID generated by the client"
// @Param        ip query string false "Player's IP address"
// @Success      200 {object} FullProfile
// @Success      204 "Player has not joined"
// @Router       /authlib-injector/sessionserver/session/minecraft/hasJoined [get]
func (h *Handler) handleHasJoined(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	serverID := r.URL.Query().Get("serverId")

	if username == "" || serverID == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	ctx := r.Context()

	// Local join cache lookup.
	entry, ok := h.cache.get(serverID)
	if ok && entry.profileName == username {
		player, err := h.accounts.GetPlayerByUUID(ctx, entry.profileUUID)
		if err != nil {
			slog.Error("hasJoined: looking up player", "uuid", entry.profileUUID, "error", err)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.writeLocalProfile(ctx, w, player, true)
		return
	}

	// Mixed-auth path: query fallback servers when local lookup failed.
	if h.fallback != nil {
		ip := r.URL.Query().Get("ip")
		fbProfile, srvIdx, err := h.fallback.HasJoined(ctx, username, serverID, ip)
		if err != nil {
			slog.Error("hasJoined: querying fallback servers", "error", err)
		}
		if fbProfile != nil {
			srv := h.fallback.ServerAt(srvIdx)
			if srv.DenyUnknownUsers {
				// Whitelist mode: only allow if a local player exists with this name.
				// This lets operators use a fallback (e.g. Mojang) for authentication
				// while still controlling who may join via their local player registry.
				_, localErr := h.accounts.GetPlayerByName(ctx, username)
				if localErr != nil {
					// No local player with this name -> deny (204 = not joined).
					w.WriteHeader(http.StatusNoContent)
					return
				}
			}
			// Return the fallback's profile verbatim (signed by the fallback's key).
			writeJSON(w, http.StatusOK, rawFullProfile{
				ID:         fbProfile.ID,
				Name:       fbProfile.Name,
				Properties: fbProfile.Properties,
			})
			return
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleProfile processes GET /sessionserver/session/minecraft/profile/{id}.
//
// Local path: looks up the player by UUID and returns a full (optionally signed)
// profile. When ForwardSkins is enabled and the player has no skin, the profile's
// texture properties are replaced with those from the fallback server verbatim
// (see rawFullProfile for the signing implication).
//
// OfflineSkins path: if the UUID is not found locally and OfflineSkins is enabled,
// a scan is performed over all local players to find one whose Minecraft offline UUID
// (deterministic from name) matches the requested UUID.
//
// Fallback path: if the UUID is still unknown after the above, each configured fallback
// server is queried. The first successful response is returned verbatim.
//
// Returns 204 with empty body if the profile cannot be found by any path.
// @Summary      Get player profile
// @Description  Returns the full profile for a player including skin/cape properties and optional signatures.
// @Tags         Yggdrasil
// @Produce      json
// @Param        id path string true "Player ID (undashed UUID)"
// @Param        unsigned query boolean false "Whether to exclude signatures (default: false)"
// @Success      200 {object} FullProfile
// @Success      204 "Profile not found"
// @Router       /authlib-injector/sessionserver/session/minecraft/profile/{id} [get]
func (h *Handler) handleProfile(w http.ResponseWriter, r *http.Request) {
	idHex := r.PathValue("id")
	dashedUUID := redash(idHex)
	unsigned := r.URL.Query().Get("unsigned") == "true"
	signed := !unsigned

	ctx := r.Context()

	// Local lookup by the exact stored UUID.
	player, err := h.accounts.GetPlayerByUUID(ctx, dashedUUID)
	if err == nil {
		h.writeLocalProfile(ctx, w, player, signed)
		return
	}
	if !errors.Is(err, accounts.ErrNotFound) {
		slog.Error("profile: looking up player by UUID", "uuid", dashedUUID, "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// OfflineSkins: scan local players to find one whose offline UUID matches.
	if h.offlineSkins {
		offlinePlayer, offlineErr := h.accounts.GetPlayerByOfflineUUID(ctx, dashedUUID)
		if offlineErr == nil {
			h.writeLocalProfile(ctx, w, offlinePlayer, signed)
			return
		}
		if !errors.Is(offlineErr, accounts.ErrNotFound) {
			slog.Error("profile: offline UUID scan", "uuid", dashedUUID, "error", offlineErr)
		}
	}

	// Fallback path: UUID unknown locally; proxy to a configured upstream server.
	if h.fallback != nil {
		fbProfile, fbErr := h.fallback.ProfileByUUID(ctx, idHex)
		if fbErr != nil {
			slog.Error("profile: querying fallback servers", "uuid", idHex, "error", fbErr)
		}
		if fbProfile != nil {
			writeJSON(w, http.StatusOK, rawFullProfile{
				ID:         fbProfile.ID,
				Name:       fbProfile.Name,
				Properties: fbProfile.Properties,
			})
			return
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleProfilesBulk processes POST /api/profiles/minecraft.
// Accepts a JSON array of player names (capped at 100) and returns an array of
// {id (undashed), name} for names that exist; unknown names are silently skipped.
//
// When a fallback client is configured, names not found locally are resolved via
// fallback.NameToUUID and included in the response.
// @Summary      Bulk name-to-UUID lookup
// @Description  Resolves a batch of player names to their undashed UUIDs.
// @Tags         Yggdrasil
// @Accept       json
// @Produce      json
// @Param        names body []string true "List of player names to lookup (max 100)"
// @Success      200 {array} ProfileStub
// @Router       /authlib-injector/api/profiles/minecraft [post]
func (h *Handler) handleProfilesBulk(w http.ResponseWriter, r *http.Request) {
	var names []string
	if !decodeJSON(w, r, &names) {
		return
	}

	const maxNames = 100
	if len(names) > maxNames {
		names = names[:maxNames]
	}

	ctx := r.Context()
	result := make([]ProfileStub, 0, len(names))
	for _, name := range names {
		player, err := h.accounts.GetPlayerByName(ctx, name)
		if err == nil {
			result = append(result, ProfileStub{ID: undash(player.UUID), Name: player.Name})
			continue
		}
		// For names not found locally, try fallback NameToUUID when configured.
		if h.fallback != nil {
			id, ok, fbErr := h.fallback.NameToUUID(ctx, name)
			if fbErr != nil {
				slog.Warn("profilesBulk: fallback nameToUUID", "name", name, "error", fbErr)
			}
			if ok && id != "" {
				result = append(result, ProfileStub{ID: id, Name: name})
			}
		}
	}

	writeJSON(w, http.StatusOK, result)
}

// writeLocalProfile builds and writes a profile response for a locally known player.
// When ForwardSkins is enabled and the player has no skin, it attempts to splice in
// the fallback server's texture properties verbatim. If the fallback call fails or
// returns no properties, the local profile (with empty textures) is returned instead.
func (h *Handler) writeLocalProfile(ctx context.Context, w http.ResponseWriter, player *store.Player, signed bool) {

	// ForwardSkins: inject fallback textures when the player has no local skin.
	// The injected properties are signed by the fallback's key, not ours.
	// See rawFullProfile for the full signing implication comment.
	if h.forwardSkins && !playerHasSkin(player) && h.fallback != nil {
		fbProfile, err := h.fallback.ProfileByUUID(ctx, undash(player.UUID))
		if err != nil {
			slog.Warn("writeLocalProfile: fallback skin fetch failed",
				"uuid", player.UUID, "error", err)
		}
		if fbProfile != nil && len(fbProfile.Properties) > 0 {
			writeJSON(w, http.StatusOK, rawFullProfile{
				ID:         undash(player.UUID),
				Name:       player.Name,
				Properties: fbProfile.Properties,
			})
			return
		}
	}

	profile, err := buildProfile(player, h.keys, signed, h.baseURL, uploadableTexturesValue(h.allowSkins, h.allowCapes))
	if err != nil {
		slog.Error("writeLocalProfile: building profile", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, profile)
}

// writeJSON sets Content-Type, writes the status code, and JSON-encodes v into w.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("writeJSON: encoding response", "error", err)
	}
}

// decodeJSON decodes the JSON request body into v. On failure it writes a 400 Yggdrasil
// error and returns false so the caller can return immediately.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeYggError(w, http.StatusBadRequest, "IllegalArgumentException", "Malformed request body.", "")
		return false
	}
	return true
}

// writeYggError writes a Yggdrasil-formatted JSON error body with the given HTTP status.
func writeYggError(w http.ResponseWriter, status int, errName, message, cause string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(YggError{Error: errName, ErrorMessage: message, Cause: cause})
}
