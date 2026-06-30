// Copyright 2025 - Alby Hernández and the minecrauth contributors
// SPDX-License-Identifier: Apache-2.0

// Package httpserver_test: web_session_test.go covers the /web/api routes,
// sessionOrBasicAuth middleware (cookie + Basic fallback), CSRF protection,
// User.Blocked flow, admin player/texture management routes, and /web/api/config.
package httpserver_test

import (
	"bytes"
	"context"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/achetronic/minecrauth/internal/accounts"
	"github.com/achetronic/minecrauth/internal/auth"
	"github.com/achetronic/minecrauth/internal/config"
	"github.com/achetronic/minecrauth/internal/httpserver"
	sqlitestore "github.com/achetronic/minecrauth/internal/store/sqlite"
	"github.com/achetronic/minecrauth/internal/textures"
	"github.com/achetronic/minecrauth/internal/yggdrasil"
	"github.com/pquerna/otp/totp"
)

// webStack holds the components of a wired test stack for web/session tests.
type webStack struct {
	Server     *httptest.Server
	Svc        *accounts.Service
	Store      *sqlitestore.Store
	SessionMgr *auth.SessionManager
}

// newWebTestStack wires the full stack against an in-memory SQLite database and
// returns a ready-to-use httptest.Server together with the key components.
func newWebTestStack(t *testing.T, cfg *config.Config) (*webStack, *http.Client) {
	t.Helper()

	st, err := sqlitestore.New(":memory:")
	if err != nil {
		t.Fatalf("newWebTestStack: creating store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("newWebTestStack: migrating: %v", err)
	}

	km := newTestKeyManager(t)
	tokenSvc := auth.NewTokenService(st, 0, nil)
	authn := auth.NewPasswordAuthenticator(st)

	nameRegex := regexp.MustCompile(cfg.PlayerNameRegex)
	svc := accounts.NewService(st, accounts.Policy{
		MinPasswordLength: cfg.MinPasswordLength,
		MaxPlayersPerUser: cfg.MaxPlayersPerUser,
		PlayerNameRegex:   nameRegex,
		UUIDGeneration:    cfg.UUIDGeneration,
	})

	yggH := yggdrasil.NewHandler(tokenSvc, authn, svc, km, cfg.ServerName, cfg.Domain, cfg.BaseURL, nil, false, false, true, true, "0.0.0-test")

	textureDir := t.TempDir()
	textureSt, err := textures.New(textureDir)
	if err != nil {
		t.Fatalf("newWebTestStack: texture store: %v", err)
	}

	sessionTTL := time.Duration(cfg.SessionTTLSeconds) * time.Second
	sessionMgr := auth.NewSessionManager(st, sessionTTL, nil)

	srv, err := httpserver.New(cfg, httpserver.Deps{
		Accounts:   svc,
		Tokens:     tokenSvc,
		Authn:      authn,
		Keys:       km,
		YggHandler: yggH,
		Textures:   textureSt,
		Sessions:   sessionMgr,
		Store:      st,
	})
	if err != nil {
		t.Fatalf("newWebTestStack: httpserver: %v", err)
	}

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// Cookie-jar client so the browser session cookie is sent automatically.
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	return &webStack{
		Server:     ts,
		Svc:        svc,
		Store:      st,
		SessionMgr: sessionMgr,
	}, client
}

// ---- request helpers ----

// doJSON sends method with a JSON-encoded body and optional extra headers.
func doJSON(t *testing.T, client *http.Client, method, url string, body any, headers map[string]string) *http.Response {
	t.Helper()
	var bodyReader *bytes.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("doJSON marshal: %v", err)
		}
		bodyReader = bytes.NewReader(data)
	} else {
		bodyReader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		t.Fatalf("doJSON request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("doJSON do: %v", err)
	}
	return resp
}

// decodeBodyW decodes the response body JSON into v and closes the body.
// (Named distinctly to avoid conflict with decodeBody in httpserver_test.go.)
func decodeBodyW(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatalf("decodeBodyW: %v", err)
	}
}

// discardBody closes the response body.
func discardBody(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
}

// loginWeb logs in via POST /web/api/login and returns the decoded session response.
func loginWeb(t *testing.T, client *http.Client, base, email, password string) (user map[string]any, csrfToken string) {
	t.Helper()
	resp := doJSON(t, client, http.MethodPost, base+"/web/api/login", map[string]any{
		"email":    email,
		"password": password,
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("loginWeb: want 200, got %d", resp.StatusCode)
	}
	var body struct {
		User      map[string]any `json:"user"`
		CSRFToken string         `json:"csrfToken"`
	}
	decodeBodyW(t, resp, &body)
	return body.User, body.CSRFToken
}

// make64x64PNG creates a minimal 64×64 PNG suitable for skin upload tests.
func make64x64PNG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 64, 64))
	for y := 0; y < 64; y++ {
		for x := 0; x < 64; x++ {
			img.Set(x, y, color.RGBA{R: 100, G: 150, B: 200, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("make64x64PNG: %v", err)
	}
	return buf.Bytes()
}

// ---- tests ----

// TestWebLogin verifies that POST /web/api/login with valid credentials returns 200
// with a non-empty csrfToken and sets the minecrauth_session cookie.
func TestWebLogin(t *testing.T) {
	cfg := defaultTestConfig()
	ws, client := newWebTestStack(t, cfg)

	_, err := ws.Svc.AdminCreateUser(context.Background(), "login@example.com", "password123", false)
	if err != nil {
		t.Fatalf("creating user: %v", err)
	}

	_, csrf := loginWeb(t, client, ws.Server.URL, "login@example.com", "password123")
	if csrf == "" {
		t.Fatal("csrfToken must not be empty after login")
	}

	// Cookie jar must contain the session cookie.
	req, _ := http.NewRequest(http.MethodGet, ws.Server.URL, nil)
	var found bool
	for _, c := range client.Jar.Cookies(req.URL) {
		if c.Name == "minecrauth_session" && c.Value != "" {
			found = true
		}
	}
	if !found {
		t.Fatal("minecrauth_session cookie must be set after login")
	}
}

// TestWebLoginBadCreds verifies that POST /web/api/login with wrong credentials returns 401.
func TestWebLoginBadCreds(t *testing.T) {
	cfg := defaultTestConfig()
	ws, client := newWebTestStack(t, cfg)

	_, _ = ws.Svc.AdminCreateUser(context.Background(), "badcreds@example.com", "goodpass1", false)

	resp := doJSON(t, client, http.MethodPost, ws.Server.URL+"/web/api/login", map[string]any{
		"email":    "badcreds@example.com",
		"password": "wrongpass",
	}, nil)
	discardBody(resp)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad creds: want 401, got %d", resp.StatusCode)
	}
}

// TestWebSessionEndpoint verifies that GET /web/api/session returns user+csrf with a
// valid cookie, and 401 without any credentials.
func TestWebSessionEndpoint(t *testing.T) {
	cfg := defaultTestConfig()
	ws, client := newWebTestStack(t, cfg)

	_, _ = ws.Svc.AdminCreateUser(context.Background(), "sess@example.com", "password123", false)

	// 401 without any auth.
	noAuthClient := &http.Client{}
	resp := doJSON(t, noAuthClient, http.MethodGet, ws.Server.URL+"/web/api/session", nil, nil)
	discardBody(resp)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no auth session: want 401, got %d", resp.StatusCode)
	}

	// Login to populate cookie jar.
	loginWeb(t, client, ws.Server.URL, "sess@example.com", "password123")

	// GET /web/api/session with cookie.
	sessResp := doJSON(t, client, http.MethodGet, ws.Server.URL+"/web/api/session", nil, nil)
	var body struct {
		User struct {
			Email string `json:"email"`
		} `json:"user"`
		CSRFToken string `json:"csrfToken"`
	}
	decodeBodyW(t, sessResp, &body)
	if sessResp.StatusCode != http.StatusOK {
		t.Fatalf("session with cookie: want 200, got %d", sessResp.StatusCode)
	}
	if body.User.Email != "sess@example.com" {
		t.Errorf("session email: want sess@example.com, got %s", body.User.Email)
	}
	if body.CSRFToken == "" {
		t.Error("csrfToken must not be empty")
	}
}

// TestWebLogout verifies that POST /web/api/logout (with CSRF) revokes the session.
func TestWebLogout(t *testing.T) {
	cfg := defaultTestConfig()
	ws, client := newWebTestStack(t, cfg)

	_, _ = ws.Svc.AdminCreateUser(context.Background(), "logout@example.com", "password123", false)

	_, csrf := loginWeb(t, client, ws.Server.URL, "logout@example.com", "password123")

	logoutResp := doJSON(t, client, http.MethodPost, ws.Server.URL+"/web/api/logout", nil, map[string]string{
		"X-CSRF-Token": csrf,
	})
	discardBody(logoutResp)
	if logoutResp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout: want 204, got %d", logoutResp.StatusCode)
	}

	// Subsequent session check: 401.
	sessResp := doJSON(t, client, http.MethodGet, ws.Server.URL+"/web/api/session", nil, nil)
	discardBody(sessResp)
	if sessResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("after logout: want 401, got %d", sessResp.StatusCode)
	}
}

// TestCSRFRequired verifies that a cookie-authed mutating request without X-CSRF-Token
// returns 403, and with the correct token returns 2xx.
func TestCSRFRequired(t *testing.T) {
	cfg := defaultTestConfig()
	ws, client := newWebTestStack(t, cfg)

	_, _ = ws.Svc.AdminCreateUser(context.Background(), "csrf@example.com", "password123", false)

	_, csrf := loginWeb(t, client, ws.Server.URL, "csrf@example.com", "password123")

	// POST logout without CSRF → 403.
	resp403 := doJSON(t, client, http.MethodPost, ws.Server.URL+"/web/api/logout", nil, nil)
	discardBody(resp403)
	if resp403.StatusCode != http.StatusForbidden {
		t.Fatalf("no CSRF: want 403, got %d", resp403.StatusCode)
	}

	// POST logout with CSRF → 204.
	respOK := doJSON(t, client, http.MethodPost, ws.Server.URL+"/web/api/logout", nil, map[string]string{
		"X-CSRF-Token": csrf,
	})
	discardBody(respOK)
	if respOK.StatusCode != http.StatusNoContent {
		t.Fatalf("with CSRF: want 204, got %d", respOK.StatusCode)
	}
}

// TestCookieMutationWithCorrectCSRF verifies that a cookie-authed mutating API request
// (PUT /api/me/email) with X-CSRF-Token succeeds.
func TestCookieMutationWithCorrectCSRF(t *testing.T) {
	cfg := defaultTestConfig()
	ws, client := newWebTestStack(t, cfg)

	_, _ = ws.Svc.AdminCreateUser(context.Background(), "mutate@example.com", "password123", false)

	_, csrf := loginWeb(t, client, ws.Server.URL, "mutate@example.com", "password123")

	resp := doJSON(t, client, http.MethodPut, ws.Server.URL+"/api/me/email",
		map[string]any{"email": "mutate2@example.com"},
		map[string]string{"X-CSRF-Token": csrf},
	)
	discardBody(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("cookie mutation with CSRF: want 200, got %d", resp.StatusCode)
	}
}

// TestCookieMutationMissingCSRF verifies that a cookie-authed mutating request without
// X-CSRF-Token returns 403.
func TestCookieMutationMissingCSRF(t *testing.T) {
	cfg := defaultTestConfig()
	ws, client := newWebTestStack(t, cfg)

	_, _ = ws.Svc.AdminCreateUser(context.Background(), "nocsrf@example.com", "password123", false)

	loginWeb(t, client, ws.Server.URL, "nocsrf@example.com", "password123")

	// PUT without X-CSRF-Token → 403.
	resp := doJSON(t, client, http.MethodPut, ws.Server.URL+"/api/me/email",
		map[string]any{"email": "nocsrf2@example.com"},
		nil, // no CSRF header
	)
	discardBody(resp)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("missing CSRF: want 403, got %d", resp.StatusCode)
	}
}

// TestBasicAuthMutationNoCSRF verifies that HTTP Basic auth callers can make mutating
// requests without X-CSRF-Token (Basic is self-authenticating per request).
func TestBasicAuthMutationNoCSRF(t *testing.T) {
	cfg := defaultTestConfig()
	ws, _ := newWebTestStack(t, cfg)

	_, _ = ws.Svc.AdminCreateUser(context.Background(), "basic@example.com", "password123", false)

	reqBody, _ := json.Marshal(map[string]any{"email": "basic2@example.com"})
	req, _ := http.NewRequest(http.MethodPut, ws.Server.URL+"/api/me/email", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("basic@example.com", "password123")
	// No X-CSRF-Token — must succeed for Basic callers.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("basic PUT: %v", err)
	}
	discardBody(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("basic mutation no CSRF: want 200, got %d", resp.StatusCode)
	}
}

// TestBlockedUser verifies that blocking a user:
//   - prevents subsequent login (401)
//   - invalidates their existing session immediately (401)
func TestBlockedUser(t *testing.T) {
	cfg := defaultTestConfig()
	ws, _ := newWebTestStack(t, cfg)

	_, _ = ws.Svc.AdminCreateUser(context.Background(), "admin_b@example.com", "adminpass1", true)
	victim, _ := ws.Svc.AdminCreateUser(context.Background(), "victim@example.com", "password123", false)

	// Victim logs in to establish a session.
	victimJar, _ := cookiejar.New(nil)
	victimClient := &http.Client{Jar: victimJar}
	_, victimCSRF := loginWeb(t, victimClient, ws.Server.URL, "victim@example.com", "password123")
	_ = victimCSRF

	// Confirm session works.
	sessResp := doJSON(t, victimClient, http.MethodGet, ws.Server.URL+"/web/api/session", nil, nil)
	discardBody(sessResp)
	if sessResp.StatusCode != http.StatusOK {
		t.Fatalf("victim pre-block session: want 200, got %d", sessResp.StatusCode)
	}

	// Admin blocks the victim.
	blockBody, _ := json.Marshal(map[string]any{"blocked": true})
	blockReq, _ := http.NewRequest(http.MethodPut, ws.Server.URL+"/admin/users/"+victim.ID+"/blocked", bytes.NewReader(blockBody))
	blockReq.Header.Set("Content-Type", "application/json")
	blockReq.SetBasicAuth("admin_b@example.com", "adminpass1")
	blockResp, _ := http.DefaultClient.Do(blockReq)
	discardBody(blockResp)
	if blockResp.StatusCode != http.StatusOK {
		t.Fatalf("block user: want 200, got %d", blockResp.StatusCode)
	}

	// Victim's existing session should now return 401.
	sessResp2 := doJSON(t, victimClient, http.MethodGet, ws.Server.URL+"/web/api/session", nil, nil)
	discardBody(sessResp2)
	if sessResp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("blocked session: want 401, got %d", sessResp2.StatusCode)
	}

	// Victim's login should also fail.
	loginResp := doJSON(t, victimClient, http.MethodPost, ws.Server.URL+"/web/api/login",
		map[string]any{"email": "victim@example.com", "password": "password123"}, nil)
	discardBody(loginResp)
	if loginResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("blocked login: want 401, got %d", loginResp.StatusCode)
	}
}

// TestAdminPlayerCRUD verifies that an admin can list, create, rename, and delete
// players belonging to another user via /admin/users/{id}/players routes.
func TestAdminPlayerCRUD(t *testing.T) {
	cfg := defaultTestConfig()
	ws, _ := newWebTestStack(t, cfg)

	_, _ = ws.Svc.AdminCreateUser(context.Background(), "admin_pl@example.com", "adminpass1", true)
	target, _ := ws.Svc.AdminCreateUser(context.Background(), "target_pl@example.com", "pass1234", false)

	// Create player via admin route.
	createBody, _ := json.Marshal(map[string]any{"name": "AdminPl01"})
	createReq, _ := http.NewRequest(http.MethodPost, ws.Server.URL+"/admin/users/"+target.ID+"/players", bytes.NewReader(createBody))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.SetBasicAuth("admin_pl@example.com", "adminpass1")
	createResp, _ := http.DefaultClient.Do(createReq)
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("admin create player: want 201, got %d", createResp.StatusCode)
	}
	var player struct {
		ID string `json:"id"`
	}
	decodeBodyW(t, createResp, &player)
	if player.ID == "" {
		t.Fatal("created player must have an ID")
	}

	// List players.
	listReq, _ := http.NewRequest(http.MethodGet, ws.Server.URL+"/admin/users/"+target.ID+"/players", nil)
	listReq.SetBasicAuth("admin_pl@example.com", "adminpass1")
	listResp, _ := http.DefaultClient.Do(listReq)
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("admin list players: want 200, got %d", listResp.StatusCode)
	}
	var players []struct {
		ID string `json:"id"`
	}
	decodeBodyW(t, listResp, &players)
	if len(players) != 1 || players[0].ID != player.ID {
		t.Fatalf("want 1 player with ID %s, got %v", player.ID, players)
	}

	// Rename.
	renameBody, _ := json.Marshal(map[string]any{"name": "AdminPl02"})
	renameReq, _ := http.NewRequest(http.MethodPatch, ws.Server.URL+"/admin/users/"+target.ID+"/players/"+player.ID, bytes.NewReader(renameBody))
	renameReq.Header.Set("Content-Type", "application/json")
	renameReq.SetBasicAuth("admin_pl@example.com", "adminpass1")
	renameResp, _ := http.DefaultClient.Do(renameReq)
	discardBody(renameResp)
	if renameResp.StatusCode != http.StatusOK {
		t.Fatalf("admin rename player: want 200, got %d", renameResp.StatusCode)
	}

	// Delete.
	deleteReq, _ := http.NewRequest(http.MethodDelete, ws.Server.URL+"/admin/users/"+target.ID+"/players/"+player.ID, nil)
	deleteReq.SetBasicAuth("admin_pl@example.com", "adminpass1")
	deleteResp, _ := http.DefaultClient.Do(deleteReq)
	discardBody(deleteResp)
	if deleteResp.StatusCode != http.StatusNoContent {
		t.Fatalf("admin delete player: want 204, got %d", deleteResp.StatusCode)
	}
}

// TestAdminSkinManagement verifies that an admin can upload / delete a skin for another
// user's player, and that AllowSkins=false is bypassed for admins.
func TestAdminSkinManagement(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.AllowSkins = false // Admins bypass this flag.
	ws, _ := newWebTestStack(t, cfg)

	_, _ = ws.Svc.AdminCreateUser(context.Background(), "admin_sk@example.com", "adminpass1", true)
	target, _ := ws.Svc.AdminCreateUser(context.Background(), "target_sk@example.com", "pass1234", false)
	player, err := ws.Svc.CreatePlayer(context.Background(), target.ID, "SkinTest01", "")
	if err != nil {
		t.Fatalf("creating player: %v", err)
	}

	skinPNG := make64x64PNG(t)

	// Upload skin.
	skinReq, _ := http.NewRequest(http.MethodPut,
		ws.Server.URL+"/admin/users/"+target.ID+"/players/"+player.ID+"/skin?model=classic",
		bytes.NewReader(skinPNG))
	skinReq.Header.Set("Content-Type", "image/png")
	skinReq.SetBasicAuth("admin_sk@example.com", "adminpass1")
	skinResp, _ := http.DefaultClient.Do(skinReq)
	if skinResp.StatusCode != http.StatusOK {
		t.Fatalf("admin upload skin: want 200, got %d", skinResp.StatusCode)
	}
	var updated struct {
		SkinHash *string `json:"skin_hash"`
	}
	decodeBodyW(t, skinResp, &updated)
	if updated.SkinHash == nil || *updated.SkinHash == "" {
		t.Fatal("skin_hash must be set after upload")
	}

	// Delete skin.
	delReq, _ := http.NewRequest(http.MethodDelete,
		ws.Server.URL+"/admin/users/"+target.ID+"/players/"+player.ID+"/skin", nil)
	delReq.SetBasicAuth("admin_sk@example.com", "adminpass1")
	delResp, _ := http.DefaultClient.Do(delReq)
	discardBody(delResp)
	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("admin delete skin: want 204, got %d", delResp.StatusCode)
	}
}

// TestNonAdminOnAdminRoutes verifies that a non-admin user gets 403 on /admin routes.
func TestNonAdminOnAdminRoutes(t *testing.T) {
	cfg := defaultTestConfig()
	ws, _ := newWebTestStack(t, cfg)

	_, _ = ws.Svc.AdminCreateUser(context.Background(), "notadmin@example.com", "password123", false)

	req, _ := http.NewRequest(http.MethodGet, ws.Server.URL+"/admin/users", nil)
	req.SetBasicAuth("notadmin@example.com", "password123")
	resp, _ := http.DefaultClient.Do(req)
	discardBody(resp)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin on /admin: want 403, got %d", resp.StatusCode)
	}
}

// TestExistingBasicAPIWorks verifies the existing HTTP Basic auth flow on /api still
// works correctly after the sessionOrBasicAuth migration.
func TestExistingBasicAPIWorks(t *testing.T) {
	cfg := defaultTestConfig()
	ws, _ := newWebTestStack(t, cfg)

	_, _ = ws.Svc.AdminCreateUser(context.Background(), "existing@example.com", "password123", false)

	req, _ := http.NewRequest(http.MethodGet, ws.Server.URL+"/api/me", nil)
	req.SetBasicAuth("existing@example.com", "password123")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("basic /api/me: want 200, got %d", resp.StatusCode)
	}
	var u struct {
		Email string `json:"email"`
	}
	decodeBodyW(t, resp, &u)
	if u.Email != "existing@example.com" {
		t.Errorf("email: want existing@example.com, got %s", u.Email)
	}
}

// TestExistingBasicAdminWorks verifies the existing HTTP Basic auth flow on /admin still
// works correctly after the sessionOrBasicAuth migration.
func TestExistingBasicAdminWorks(t *testing.T) {
	cfg := defaultTestConfig()
	ws, _ := newWebTestStack(t, cfg)

	_, _ = ws.Svc.AdminCreateUser(context.Background(), "admin_ex@example.com", "adminpass1", true)

	req, _ := http.NewRequest(http.MethodGet, ws.Server.URL+"/admin/users", nil)
	req.SetBasicAuth("admin_ex@example.com", "adminpass1")
	resp, _ := http.DefaultClient.Do(req)
	discardBody(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("basic /admin/users: want 200, got %d", resp.StatusCode)
	}
}

// TestWebConfig verifies that GET /web/api/config returns the expected flags.
func TestWebConfig(t *testing.T) {
	cfg := defaultTestConfig()
	ws, client := newWebTestStack(t, cfg)

	resp := doJSON(t, client, http.MethodGet, ws.Server.URL+"/web/api/config", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("web config: want 200, got %d", resp.StatusCode)
	}
	var body struct {
		OIDCEnabled         bool `json:"oidcEnabled"`
		AllowSkins          bool `json:"allowSkins"`
		AllowCapes          bool `json:"allowCapes"`
		AllowTextureFromURL bool `json:"allowTextureFromURL"`
		RequireInvite       bool `json:"requireInvite"`
	}
	decodeBodyW(t, resp, &body)

	if body.OIDCEnabled {
		t.Error("oidcEnabled: want false by default")
	}
	if !body.AllowSkins {
		t.Error("allowSkins: want true by default")
	}
	if !body.AllowCapes {
		t.Error("allowCapes: want true by default")
	}
	if body.AllowTextureFromURL {
		t.Error("allowTextureFromURL: want false by default")
	}
	if body.RequireInvite {
		t.Error("requireInvite: want false by default")
	}
}

// TestAdminPlayerBelongsToWrongUser verifies that an admin cannot manage a player via
// another user's route (player ownership mismatch returns 404).
func TestAdminPlayerBelongsToWrongUser(t *testing.T) {
	cfg := defaultTestConfig()
	ws, _ := newWebTestStack(t, cfg)

	_, _ = ws.Svc.AdminCreateUser(context.Background(), "admin_mis@example.com", "adminpass1", true)
	owner, _ := ws.Svc.AdminCreateUser(context.Background(), "owner@example.com", "pass1234", false)
	other, _ := ws.Svc.AdminCreateUser(context.Background(), "other@example.com", "pass1234", false)
	player, err := ws.Svc.CreatePlayer(context.Background(), owner.ID, "OwnedPlayer", "")
	if err != nil {
		t.Fatalf("creating player: %v", err)
	}

	// Try to access owner's player via other user's path → 404.
	deleteReq, _ := http.NewRequest(http.MethodDelete,
		ws.Server.URL+"/admin/users/"+other.ID+"/players/"+player.ID, nil)
	deleteReq.SetBasicAuth("admin_mis@example.com", "adminpass1")
	deleteResp, _ := http.DefaultClient.Do(deleteReq)
	discardBody(deleteResp)
	if deleteResp.StatusCode != http.StatusNotFound {
		t.Fatalf("mismatched player owner: want 404, got %d", deleteResp.StatusCode)
	}
}

// TestImpersonation verifies that an admin can impersonate a target user,
// and stop impersonating to return to their admin session.
func TestImpersonation(t *testing.T) {
	cfg := defaultTestConfig()
	ws, client := newWebTestStack(t, cfg)

	admin, _ := ws.Svc.AdminCreateUser(context.Background(), "admin_imp@example.com", "password123", true)
	target, _ := ws.Svc.AdminCreateUser(context.Background(), "target_imp@example.com", "password123", false)

	// Admin logs in.
	_, adminCSRF := loginWeb(t, client, ws.Server.URL, "admin_imp@example.com", "password123")

	// Verify we are admin.
	sessResp := doJSON(t, client, http.MethodGet, ws.Server.URL+"/web/api/session", nil, nil)
	var body map[string]any
	decodeBodyW(t, sessResp, &body)
	if sessResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /web/api/session before impersonation: want 200, got %d", sessResp.StatusCode)
	}
	u := body["user"].(map[string]any)
	if u["email"].(string) != admin.Email {
		t.Errorf("expected email %q, got %s", admin.Email, u["email"].(string))
	}
	if body["impersonating"].(bool) {
		t.Errorf("expected impersonating false, got true")
	}

	// Impersonate target.
	impResp := doJSON(t, client, http.MethodPost, ws.Server.URL+"/admin/users/"+target.ID+"/impersonate", nil, map[string]string{
		"X-CSRF-Token": adminCSRF,
	})
	var impBody map[string]any
	decodeBodyW(t, impResp, &impBody)
	if impResp.StatusCode != http.StatusOK {
		t.Fatalf("POST impersonate: want 200, got %d", impResp.StatusCode)
	}
	targetCSRF := impBody["csrfToken"].(string)

	// Verify we are now the target user with impersonating: true.
	sessResp2 := doJSON(t, client, http.MethodGet, ws.Server.URL+"/web/api/session", nil, nil)
	var body2 map[string]any
	decodeBodyW(t, sessResp2, &body2)
	if sessResp2.StatusCode != http.StatusOK {
		t.Fatalf("GET /web/api/session during impersonation: want 200, got %d", sessResp2.StatusCode)
	}
	u2 := body2["user"].(map[string]any)
	if u2["email"].(string) != target.Email {
		t.Errorf("expected email %q, got %s", target.Email, u2["email"].(string))
	}
	if !body2["impersonating"].(bool) {
		t.Errorf("expected impersonating true, got false")
	}

	// Non-admin impersonation check (should fail as target is not admin, so cannot call admin API even if impersonated).
	impFailResp := doJSON(t, client, http.MethodPost, ws.Server.URL+"/admin/users/"+admin.ID+"/impersonate", nil, map[string]string{
		"X-CSRF-Token": targetCSRF,
	})
	discardBody(impFailResp)
	if impFailResp.StatusCode != http.StatusForbidden {
		t.Errorf("impersonated user calling admin API: want 403, got %d", impFailResp.StatusCode)
	}

	// Stop impersonating.
	stopResp := doJSON(t, client, http.MethodPost, ws.Server.URL+"/web/api/stop-impersonation", nil, map[string]string{
		"X-CSRF-Token": targetCSRF,
	})
	var stopBody map[string]any
	decodeBodyW(t, stopResp, &stopBody)
	if stopResp.StatusCode != http.StatusOK {
		t.Fatalf("POST stop-impersonation: want 200, got %d", stopResp.StatusCode)
	}

	// Verify we are admin again.
	sessResp3 := doJSON(t, client, http.MethodGet, ws.Server.URL+"/web/api/session", nil, nil)
	var body3 map[string]any
	decodeBodyW(t, sessResp3, &body3)
	if sessResp3.StatusCode != http.StatusOK {
		t.Fatalf("GET /web/api/session after stop: want 200, got %d", sessResp3.StatusCode)
	}
	u3 := body3["user"].(map[string]any)
	if u3["email"].(string) != admin.Email {
		t.Errorf("expected email %q, got %s", admin.Email, u3["email"].(string))
	}
	if body3["impersonating"].(bool) {
		t.Errorf("expected impersonating false, got true")
	}
}

// TestImpersonationNonAdmin verifies that a non-admin cannot call impersonate.
func TestImpersonationNonAdmin(t *testing.T) {
	cfg := defaultTestConfig()
	ws, client := newWebTestStack(t, cfg)

	_, _ = ws.Svc.AdminCreateUser(context.Background(), "nonadmin@example.com", "password123", false)
	target, _ := ws.Svc.AdminCreateUser(context.Background(), "target@example.com", "password123", false)

	// Non-admin logs in.
	_, nonadminCSRF := loginWeb(t, client, ws.Server.URL, "nonadmin@example.com", "password123")

	// Try to impersonate target → should be blocked at admin gate.
	impResp := doJSON(t, client, http.MethodPost, ws.Server.URL+"/admin/users/"+target.ID+"/impersonate", nil, map[string]string{
		"X-CSRF-Token": nonadminCSRF,
	})
	discardBody(impResp)
	if impResp.StatusCode != http.StatusForbidden {
		t.Errorf("non-admin calling impersonate: want 403, got %d", impResp.StatusCode)
	}
}

func TestWebTOTPLogin(t *testing.T) {
	cfg := defaultTestConfig()
	ws, client := newWebTestStack(t, cfg)
	ctx := context.Background()

	// 1. Create a user
	u, err := ws.Svc.AdminCreateUser(ctx, "totp_user@example.com", "password123", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// 2. Regular login to enable TOTP first
	_, csrfToken := loginWeb(t, client, ws.Server.URL, "totp_user@example.com", "password123")

	// Call /api/me/totp/setup
	setupResp := doJSON(t, client, http.MethodPost, ws.Server.URL+"/api/me/totp/setup", nil, map[string]string{
		"X-CSRF-Token": csrfToken,
	})
	if setupResp.StatusCode != http.StatusOK {
		t.Fatalf("POST totp setup: want 200, got %d", setupResp.StatusCode)
	}
	var setupBody struct {
		OtpauthUrl string `json:"otpauthUrl"`
		Secret     string `json:"secret"`
	}
	decodeBodyW(t, setupResp, &setupBody)

	// Confirm setup via /api/me/totp/confirm
	code, err := totp.GenerateCode(setupBody.Secret, time.Now())
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}
	confirmResp := doJSON(t, client, http.MethodPost, ws.Server.URL+"/api/me/totp/confirm", map[string]any{
		"code": code,
	}, map[string]string{
		"X-CSRF-Token": csrfToken,
	})
	if confirmResp.StatusCode != http.StatusOK {
		t.Fatalf("POST totp confirm: want 200, got %d", confirmResp.StatusCode)
	}
	var confirmBody struct {
		RecoveryCodes []string `json:"recoveryCodes"`
	}
	decodeBodyW(t, confirmResp, &confirmBody)
	if len(confirmBody.RecoveryCodes) != 10 {
		t.Fatalf("expected 10 recovery codes, got %d", len(confirmBody.RecoveryCodes))
	}

	// 3. Clear cookie-jar to perform fresh login
	jar, _ := cookiejar.New(nil)
	client.Jar = jar

	// 4. POST login (first step)
	loginResp := doJSON(t, client, http.MethodPost, ws.Server.URL+"/web/api/login", map[string]any{
		"email":    "totp_user@example.com",
		"password": "password123",
	}, nil)
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("POST login: want 200, got %d", loginResp.StatusCode)
	}
	var loginBody struct {
		TotpRequired bool   `json:"totpRequired"`
		TotpToken    string `json:"totpToken"`
	}
	decodeBodyW(t, loginResp, &loginBody)
	if !loginBody.TotpRequired || loginBody.TotpToken == "" {
		t.Fatalf("expected totpRequired=true and non-empty totpToken, got: %+v", loginBody)
	}

	// 5. POST login-totp with wrong code
	badTotpResp := doJSON(t, client, http.MethodPost, ws.Server.URL+"/web/api/login-totp", map[string]any{
		"totpToken": loginBody.TotpToken,
		"code":      "000000",
	}, nil)
	if badTotpResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("POST login-totp bad code: want 401, got %d", badTotpResp.StatusCode)
	}
	discardBody(badTotpResp)

	// 6. POST login-totp with correct code
	validCode, err := totp.GenerateCode(setupBody.Secret, time.Now())
	if err != nil {
		t.Fatalf("failed to generate second code: %v", err)
	}
	goodTotpResp := doJSON(t, client, http.MethodPost, ws.Server.URL+"/web/api/login-totp", map[string]any{
		"totpToken": loginBody.TotpToken,
		"code":      validCode,
	}, nil)
	if goodTotpResp.StatusCode != http.StatusOK {
		t.Fatalf("POST login-totp good code: want 200, got %d", goodTotpResp.StatusCode)
	}
	var goodLoginBody struct {
		User      map[string]any `json:"user"`
		CSRFToken string         `json:"csrfToken"`
	}
	decodeBodyW(t, goodTotpResp, &goodLoginBody)
	if goodLoginBody.CSRFToken == "" {
		t.Errorf("expected non-empty CSRFToken on successful login")
	}

	// 7. Impersonated disable test
	_, err = ws.Svc.AdminCreateUser(ctx, "admin_totp@example.com", "password123", true)
	if err != nil {
		t.Fatalf("failed to create admin: %v", err)
	}

	// Log in as admin
	_, adminCSRF := loginWeb(t, client, ws.Server.URL, "admin_totp@example.com", "password123")

	// Impersonate the totp_user
	impResp := doJSON(t, client, http.MethodPost, ws.Server.URL+"/admin/users/"+u.ID+"/impersonate", nil, map[string]string{
		"X-CSRF-Token": adminCSRF,
	})
	if impResp.StatusCode != http.StatusOK {
		t.Fatalf("POST impersonate: want 200, got %d", impResp.StatusCode)
	}
	var impBody struct {
		CSRFToken string `json:"csrfToken"`
	}
	decodeBodyW(t, impResp, &impBody)

	// Disable TOTP through impersonated session (no code or empty code is fine)
	disableResp := doJSON(t, client, http.MethodPost, ws.Server.URL+"/api/me/totp/disable", map[string]any{
		"code": "",
	}, map[string]string{
		"X-CSRF-Token": impBody.CSRFToken,
	})
	if disableResp.StatusCode != http.StatusOK {
		t.Errorf("POST totp disable (impersonated): want 200, got %d", disableResp.StatusCode)
	}
	discardBody(disableResp)

	// Verify TOTP is disabled on target user
	reloadedUser, err := ws.Svc.GetUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("failed to load user: %v", err)
	}
	if reloadedUser.TOTPEnabled {
		t.Errorf("expected TOTP to be disabled after impersonated disable")
	}
}
