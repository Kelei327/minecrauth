package httpserver_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"image"
	"image/color"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/achetronic/minecrauth/internal/accounts"
	"github.com/achetronic/minecrauth/internal/auth"
	"github.com/achetronic/minecrauth/internal/backup"
	"github.com/achetronic/minecrauth/internal/config"
	"github.com/achetronic/minecrauth/internal/httpserver"
	"github.com/achetronic/minecrauth/internal/mailer"
	"github.com/achetronic/minecrauth/internal/signing"
	sqlitestore "github.com/achetronic/minecrauth/internal/store/sqlite"
	"github.com/achetronic/minecrauth/internal/textures"
	"github.com/achetronic/minecrauth/internal/yggdrasil"
)

// defaultTestConfig returns a Config suitable for integration tests.
// All fields are explicitly set so tests are not surprised by future default changes.
func defaultTestConfig() *config.Config {
	return &config.Config{
		BaseURL:             "http://test.example.com",
		Domain:              "test.example.com",
		ListenAddr:          "127.0.0.1:0",
		StateDir:            "",
		TokenExpirySeconds:  0,
		RateLimitRPS:        10.0,
		RateLimitBurst:      20,
		BodyLimitBytes:      1048576,
		MinPasswordLength:   8,
		PlayerNameRegex:     `^[a-zA-Z0-9_]{2,16}$`,
		ServerName:          "test-server",
		YggdrasilPrefix:     "/authlib-injector",
		MaxPlayersPerUser:   3,
		UUIDGeneration:      "random",
		RequireInvite:       false,
		DefaultAdmins:       nil,
		AdminPrefix:         "/admin",
		ApiPrefix:           "/api",
		SkinSizeLimit:       64,
		AllowSkins:          true,
		AllowCapes:          true,
		AllowTextureFromURL: false,
		SessionTTLSeconds:   604800,
	}
}

type fakeMailer struct {
	mu       sync.Mutex
	lastTo   string
	lastSub  string
	lastBody string
}

func (m *fakeMailer) Send(ctx context.Context, to, subject, htmlBody string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastTo = to
	m.lastSub = subject
	m.lastBody = htmlBody
	return nil
}

// newTestStack wires the full stack against an in-memory SQLite database and returns
// an httptest.Server ready to receive requests. A 2048-bit RSA key is generated for
// speed (production always uses 4096).
func newTestStack(t *testing.T, cfg *config.Config) (*httptest.Server, *accounts.Service, *sqlitestore.Store) {
	return newTestStackWithMailer(t, cfg, &mailer.NoopMailer{})
}

func newTestStackWithMailer(t *testing.T, cfg *config.Config, ml mailer.Mailer) (*httptest.Server, *accounts.Service, *sqlitestore.Store) {
	t.Helper()

	// 1. In-memory SQLite store.
	st, err := sqlitestore.New(":memory:")
	if err != nil {
		t.Fatalf("newTestStack: creating store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("newTestStack: migrating: %v", err)
	}

	// 2. 2048-bit signing key (fast for tests; production uses 4096).
	km := newTestKeyManager(t)

	// 3. Domain services.
	tokenSvc := auth.NewTokenService(st, 0, nil)
	authn := auth.NewPasswordAuthenticator(st)
	gameAuthn := auth.NewGameAuthenticator(st)

	nameRegex := regexp.MustCompile(cfg.PlayerNameRegex)
	svc := accounts.NewService(st, accounts.Policy{
		MinPasswordLength:        cfg.MinPasswordLength,
		MaxPlayersPerUser:        cfg.MaxPlayersPerUser,
		PlayerNameRegex:          nameRegex,
		UUIDGeneration:           cfg.UUIDGeneration,
		RequireInvite:            cfg.RequireInvite,
		RequireEmailVerification: cfg.RequireEmailVerification,
	})

	// 4. Yggdrasil protocol handler (no fallback in tests).
	yggH := yggdrasil.NewHandler(tokenSvc, gameAuthn, svc, km, cfg.ServerName, cfg.Domain, cfg.BaseURL, nil, false, false)

	// 5. Texture store (temp dir; each test gets its own isolated store).
	textureDir := t.TempDir()
	textureStore, err := textures.New(textureDir)
	if err != nil {
		t.Fatalf("newTestStack: creating texture store: %v", err)
	}

	// 6. HTTP server.
	sessionMgr := auth.NewSessionManager(st, 7*24*time.Hour, nil)
	srv, err := httpserver.New(cfg, httpserver.Deps{
		Accounts:   svc,
		Tokens:     tokenSvc,
		Authn:      authn,
		Keys:       km,
		YggHandler: yggH,
		Textures:   textureStore,
		Sessions:   sessionMgr,
		Store:      st,
		Mailer:     ml,
	})
	if err != nil {
		t.Fatalf("newTestStack: creating httpserver: %v", err)
	}

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	return ts, svc, st
}

// newTestKeyManager generates a 2048-bit RSA key and loads it via signing.New so the
// key path is exercised. The 2048-bit size is intentional to keep tests fast; production
// always generates 4096-bit keys.
func newTestKeyManager(t *testing.T) *signing.KeyManager {
	t.Helper()
	keyDir := t.TempDir()
	keyPath := filepath.Join(keyDir, "signing.key")

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("newTestKeyManager: generating key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("newTestKeyManager: marshaling key: %v", err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(keyPath, pemData, 0600); err != nil {
		t.Fatalf("newTestKeyManager: writing key: %v", err)
	}

	km, err := signing.New(keyPath)
	if err != nil {
		t.Fatalf("newTestKeyManager: loading key manager: %v", err)
	}
	return km
}

// jsonBody encodes v to JSON and wraps it in a *bytes.Reader for use as an http.Request body.
func jsonBody(t *testing.T, v any) *bytes.Reader {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("jsonBody: encoding: %v", err)
	}
	return bytes.NewReader(b)
}

// decodeBody decodes the JSON response body into v.
func decodeBody(t *testing.T, r *http.Response, v any) {
	t.Helper()
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		t.Fatalf("decodeBody: decoding: %v", err)
	}
}

// TestRegisterThenBasicAuth is the primary canary: it verifies that a freshly registered
// user can authenticate via HTTP Basic auth on GET /api/me, and that the response
// contains the correct email. If registration or auth is broken this test fails.
func TestRegisterThenBasicAuth(t *testing.T) {
	cfg := defaultTestConfig()
	ts, _, _ := newTestStack(t, cfg)

	email := "user@example.com"
	password := "Password123"

	// 1. Register
	resp, err := http.Post(ts.URL+"/api/register",
		"application/json",
		jsonBody(t, map[string]string{"email": email, "password": password}))
	if err != nil {
		t.Fatalf("register request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: expected 201, got %d", resp.StatusCode)
	}

	var created map[string]any
	decodeBody(t, resp, &created)
	if created["email"] != email {
		t.Errorf("register response: email mismatch: got %v", created["email"])
	}
	// PasswordHash must not appear in the response.
	if _, exists := created["password_hash"]; exists {
		t.Error("register response: password_hash must not be present in the response")
	}

	// 2. GET /api/me with correct credentials.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/me", nil)
	req.SetBasicAuth(email, password)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/me: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/me: expected 200, got %d", resp2.StatusCode)
	}

	var me map[string]any
	decodeBody(t, resp2, &me)
	if me["email"] != email {
		t.Errorf("GET /api/me: email mismatch: got %v", me["email"])
	}
	if _, exists := me["password_hash"]; exists {
		t.Error("GET /api/me: password_hash must not be present in the response")
	}
}

// TestWrongPassword verifies that a correct email with a wrong password returns 401.
// If basicAuth skips credential checking this test fails.
func TestWrongPassword(t *testing.T) {
	cfg := defaultTestConfig()
	ts, _, _ := newTestStack(t, cfg)

	email := "user@example.com"
	password := "RightPassword"

	// Create user via register endpoint.
	resp, _ := http.Post(ts.URL+"/api/register", "application/json",
		jsonBody(t, map[string]string{"email": email, "password": password}))
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("setup: register failed with %d", resp.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/me", nil)
	req.SetBasicAuth(email, "WrongPassword")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/me: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 on wrong password, got %d", resp2.StatusCode)
	}
}

// TestMissingAuth verifies that a request to a protected endpoint without any credentials
// returns 401 with a WWW-Authenticate header. If basicAuth is not applied this fails.
func TestMissingAuth(t *testing.T) {
	cfg := defaultTestConfig()
	ts, _, _ := newTestStack(t, cfg)

	resp, err := http.Get(ts.URL + "/api/me")
	if err != nil {
		t.Fatalf("GET /api/me: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 on missing auth, got %d", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("WWW-Authenticate"), "Basic") {
		t.Errorf("expected WWW-Authenticate: Basic header, got: %q", resp.Header.Get("WWW-Authenticate"))
	}
}

// TestXHRNoBasicChallenge verifies that an unauthenticated browser XHR request
// (identified by X-Requested-With) gets a 401 WITHOUT a WWW-Authenticate header,
// so the browser does not pop its native Basic-auth dialog and the SPA can
// redirect to its own login view instead. If the suppression is removed this
// test fails.
func TestXHRNoBasicChallenge(t *testing.T) {
	cfg := defaultTestConfig()
	ts, _, _ := newTestStack(t, cfg)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/me", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/me: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 on missing auth, got %d", resp.StatusCode)
	}
	if resp.Header.Get("WWW-Authenticate") != "" {
		t.Errorf("expected no WWW-Authenticate header for XHR, got: %q", resp.Header.Get("WWW-Authenticate"))
	}
}

// TestNonAdminForbiddenOnAdminRoute verifies that a non-admin user gets 403 when hitting
// an admin endpoint. If the admin gate is missing this test fails.
func TestNonAdminForbiddenOnAdminRoute(t *testing.T) {
	cfg := defaultTestConfig()
	ts, _, _ := newTestStack(t, cfg)

	// Register a plain (non-admin) user via the public API.
	email := "plain@example.com"
	password := "Password123"
	resp, _ := http.Post(ts.URL+"/api/register", "application/json",
		jsonBody(t, map[string]string{"email": email, "password": password}))
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("setup: register failed with %d", resp.StatusCode)
	}

	// Try to access an admin route.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/admin/users", nil)
	req.SetBasicAuth(email, password)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /admin/users: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("non-admin on /admin route: expected 403, got %d", resp2.StatusCode)
	}
}

// TestAdminCanAccessAdminRoute verifies that a user with IsAdmin=true gets 200 on admin
// routes. If the admin gate rejects valid admins this test fails.
func TestAdminCanAccessAdminRoute(t *testing.T) {
	cfg := defaultTestConfig()
	ts, svc, _ := newTestStack(t, cfg)

	email := "admin@example.com"
	password := "AdminPass123"

	// Create an admin user directly through the domain service (bypasses HTTP layer).
	_, err := svc.AdminCreateUser(context.Background(), email, password, true)
	if err != nil {
		t.Fatalf("setup: creating admin user: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/admin/users", nil)
	req.SetBasicAuth(email, password)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /admin/users: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("admin on /admin/users: expected 200, got %d", resp.StatusCode)
	}
}

// TestCreatePlayerThenListPlayers verifies the player lifecycle: create via POST then
// retrieve via GET. If either handler is broken this test fails.
func TestCreatePlayerThenListPlayers(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.MaxPlayersPerUser = 5
	ts, _, _ := newTestStack(t, cfg)

	email := "gamer@example.com"
	password := "Password123"

	// Register user.
	resp, _ := http.Post(ts.URL+"/api/register", "application/json",
		jsonBody(t, map[string]string{"email": email, "password": password}))
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("setup: register failed with %d", resp.StatusCode)
	}

	// Create a player.
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/me/players",
		jsonBody(t, map[string]string{"name": "HeroPlayer"}))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(email, password)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /api/me/players: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusCreated {
		t.Fatalf("create player: expected 201, got %d", resp2.StatusCode)
	}

	var created map[string]any
	decodeBody(t, resp2, &created)
	if created["name"] != "HeroPlayer" {
		t.Errorf("created player name: expected HeroPlayer, got %v", created["name"])
	}

	// List players.
	req3, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/me/players", nil)
	req3.SetBasicAuth(email, password)
	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatalf("GET /api/me/players: %v", err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("list players: expected 200, got %d", resp3.StatusCode)
	}

	var players []map[string]any
	decodeBody(t, resp3, &players)
	if len(players) != 1 {
		t.Fatalf("expected 1 player, got %d", len(players))
	}
	if players[0]["name"] != "HeroPlayer" {
		t.Errorf("listed player name: expected HeroPlayer, got %v", players[0]["name"])
	}
}

// TestPlayerLimitReached verifies that exceeding MaxPlayersPerUser returns 409.
// If the limit check is absent, the last creation would succeed instead.
func TestPlayerLimitReached(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.MaxPlayersPerUser = 2
	ts, _, _ := newTestStack(t, cfg)

	email := "gamer2@example.com"
	password := "Password123"

	resp, _ := http.Post(ts.URL+"/api/register", "application/json",
		jsonBody(t, map[string]string{"email": email, "password": password}))
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("setup: register failed with %d", resp.StatusCode)
	}

	createPlayer := func(name string) int {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/me/players",
			jsonBody(t, map[string]string{"name": name}))
		req.Header.Set("Content-Type", "application/json")
		req.SetBasicAuth(email, password)
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST /api/me/players(%s): %v", name, err)
		}
		r.Body.Close()
		return r.StatusCode
	}

	if s := createPlayer("Alpha"); s != http.StatusCreated {
		t.Fatalf("player 1: expected 201, got %d", s)
	}
	if s := createPlayer("Bravo"); s != http.StatusCreated {
		t.Fatalf("player 2: expected 201, got %d", s)
	}
	// Third player should be rejected.
	if s := createPlayer("Charlie"); s != http.StatusConflict {
		t.Errorf("player 3 over limit: expected 409, got %d", s)
	}
}

// TestRequireInvite verifies the invite-gated registration flow.
// Without an invite code the server must return 403. With a valid invite it must return 201.
// If the invite check is absent both registrations would succeed.
func TestRequireInvite(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.RequireInvite = true
	ts, svc, _ := newTestStack(t, cfg)

	// Create an admin so we can use the invite API.
	adminEmail := "admin@example.com"
	adminPass := "AdminPass123"
	_, err := svc.AdminCreateUser(context.Background(), adminEmail, adminPass, true)
	if err != nil {
		t.Fatalf("setup: creating admin: %v", err)
	}

	// Registration without invite must fail.
	resp, _ := http.Post(ts.URL+"/api/register", "application/json",
		jsonBody(t, map[string]string{
			"email":    "user@example.com",
			"password": "Password123",
		}))
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("register without invite: expected 403, got %d", resp.StatusCode)
	}

	// Admin creates an invite via the API.
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/invites",
		jsonBody(t, map[string]any{}))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(adminEmail, adminPass)
	invResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /admin/invites: %v", err)
	}
	defer invResp.Body.Close()
	if invResp.StatusCode != http.StatusCreated {
		t.Fatalf("create invite: expected 201, got %d", invResp.StatusCode)
	}

	var invite map[string]any
	decodeBody(t, invResp, &invite)
	inviteCode, _ := invite["code"].(string)
	if inviteCode == "" {
		t.Fatal("invite response missing code field")
	}

	// Registration with the invite code must succeed.
	resp2, _ := http.Post(ts.URL+"/api/register", "application/json",
		jsonBody(t, map[string]any{
			"email":      "user@example.com",
			"password":   "Password123",
			"inviteCode": inviteCode,
		}))
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusCreated {
		t.Errorf("register with invite: expected 201, got %d", resp2.StatusCode)
	}
}

// TestRateLimit verifies that the token-bucket rate limiter fires 429 after the burst is
// exhausted on a rate-limited route (authserver authenticate), and that sessionserver
// routes are completely exempt even after the burst is exhausted.
// If the exemption is removed, the sessionserver requests would also return 429.
func TestRateLimit(t *testing.T) {
	cfg := defaultTestConfig()
	// Very low rate and burst so the bucket empties during the test.
	cfg.RateLimitRPS = 0.0001
	cfg.RateLimitBurst = 3
	ts, _, _ := newTestStack(t, cfg)

	authBody := `{"username":"nobody@example.com","password":"wrongpass"}`

	// Send burst+2 requests to the (rate-limited) authserver authenticate endpoint.
	// The first cfg.RateLimitBurst requests should NOT be 429; the rest must be 429.
	const total = 6
	rateLimitHit := false
	for i := 0; i < total; i++ {
		resp, err := http.Post(ts.URL+"/authlib-injector/authserver/authenticate",
			"application/json", strings.NewReader(authBody))
		if err != nil {
			t.Fatalf("authserver request %d: %v", i+1, err)
		}
		resp.Body.Close()

		if i < cfg.RateLimitBurst {
			// Within burst: must not be 429.
			if resp.StatusCode == http.StatusTooManyRequests {
				t.Errorf("request %d (within burst): unexpected 429", i+1)
			}
		} else {
			// Beyond burst: must be 429.
			if resp.StatusCode == http.StatusTooManyRequests {
				rateLimitHit = true
			}
		}
	}
	if !rateLimitHit {
		t.Error("rate limiter never fired 429 after burst exhausted on authserver route")
	}

	// Sessionserver hasJoined requests must NEVER return 429, even though the token
	// bucket for this IP is now empty.
	for i := 0; i < 5; i++ {
		resp, err := http.Get(ts.URL +
			"/authlib-injector/sessionserver/session/minecraft/hasJoined?username=test&serverId=abc")
		if err != nil {
			t.Fatalf("sessionserver request %d: %v", i+1, err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			t.Errorf("sessionserver request %d: got 429 (must be exempt from rate limiting)", i+1)
		}
	}
}

// TestBodyLimit verifies that a body larger than BodyLimitBytes is rejected with 413.
// If MaxBytesReader is not applied, oversized bodies would be decoded successfully.
func TestBodyLimit(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.BodyLimitBytes = 20 // intentionally tiny
	ts, _, _ := newTestStack(t, cfg)

	// Build a body that clearly exceeds 20 bytes.
	largeBody := strings.Repeat("x", 200)
	rawBody := `{"email":"` + largeBody + `@example.com","password":"pass"}`

	resp, err := http.Post(ts.URL+"/api/register",
		"application/json", strings.NewReader(rawBody))
	if err != nil {
		t.Fatalf("POST /api/register: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("body limit: expected 413, got %d", resp.StatusCode)
	}
}

// TestYggdrasilMetadataRoot verifies that the Yggdrasil metadata document is served at
// the YggdrasilPrefix path (with and without trailing slash). This is what authlib-injector
// clients request first.
func TestYggdrasilMetadataRoot(t *testing.T) {
	cfg := defaultTestConfig()
	ts, _, _ := newTestStack(t, cfg)

	for _, path := range []string{
		"/authlib-injector",
		"/authlib-injector/",
	} {
		t.Run("path="+path, func(t *testing.T) {
			resp, err := http.Get(ts.URL + path)
			if err != nil {
				t.Fatalf("GET %s: %v", path, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("GET %s: expected 200, got %d", path, resp.StatusCode)
			}

			var meta map[string]any
			decodeBody(t, resp, &meta)
			if _, ok := meta["signaturePublickey"]; !ok {
				t.Error("metadata response missing signaturePublickey field")
			}
			if _, ok := meta["skinDomains"]; !ok {
				t.Error("metadata response missing skinDomains field")
			}
			metaInner, _ := meta["meta"].(map[string]any)
			if metaInner["serverName"] != "test-server" {
				t.Errorf("meta.serverName: expected test-server, got %v", metaInner["serverName"])
			}
		})
	}
}

// TestAdminCreateInviteFlow verifies the full admin invite management cycle:
// create invite via admin API, list it, delete it.
func TestAdminCreateInviteFlow(t *testing.T) {
	cfg := defaultTestConfig()
	ts, svc, _ := newTestStack(t, cfg)

	adminEmail := "admin@example.com"
	adminPass := "AdminPass123"
	_, err := svc.AdminCreateUser(context.Background(), adminEmail, adminPass, true)
	if err != nil {
		t.Fatalf("setup: creating admin: %v", err)
	}

	doAdmin := func(method, path string, body any) *http.Response {
		var bodyReader *bytes.Reader
		if body != nil {
			bodyReader = jsonBody(t, body)
		} else {
			bodyReader = bytes.NewReader(nil)
		}
		req, _ := http.NewRequest(method, ts.URL+"/admin"+path, bodyReader)
		req.Header.Set("Content-Type", "application/json")
		req.SetBasicAuth(adminEmail, adminPass)
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s /admin%s: %v", method, path, err)
		}
		return r
	}

	// Create invite.
	r := doAdmin(http.MethodPost, "/invites", map[string]any{"ttlSeconds": 3600})
	defer r.Body.Close()
	if r.StatusCode != http.StatusCreated {
		t.Fatalf("create invite: expected 201, got %d", r.StatusCode)
	}
	var inv map[string]any
	decodeBody(t, r, &inv)
	code, _ := inv["code"].(string)
	if code == "" {
		t.Fatal("invite missing code")
	}

	// List invites must include the created one.
	r2 := doAdmin(http.MethodGet, "/invites", nil)
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusOK {
		t.Fatalf("list invites: expected 200, got %d", r2.StatusCode)
	}
	var invites []map[string]any
	decodeBody(t, r2, &invites)
	if len(invites) != 1 {
		t.Fatalf("expected 1 invite, got %d", len(invites))
	}

	// Delete invite.
	r3 := doAdmin(http.MethodDelete, "/invites/"+code, nil)
	r3.Body.Close()
	if r3.StatusCode != http.StatusNoContent {
		t.Errorf("delete invite: expected 204, got %d", r3.StatusCode)
	}

	// List again - must be empty.
	r4 := doAdmin(http.MethodGet, "/invites", nil)
	defer r4.Body.Close()
	var invites2 []map[string]any
	decodeBody(t, r4, &invites2)
	if len(invites2) != 0 {
		t.Errorf("after delete: expected 0 invites, got %d", len(invites2))
	}
}

// TestPlayerOwnership verifies that a user cannot rename or delete a player owned by
// another user: the server must return 404 (ownership mismatch treated as not-found
// to avoid leaking existence).
func TestPlayerOwnership(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.MaxPlayersPerUser = 5
	ts, svc, _ := newTestStack(t, cfg)

	// Create two users.
	alice, err := svc.AdminCreateUser(context.Background(), "alice@example.com", "AlicePass1", false)
	if err != nil {
		t.Fatalf("setup alice: %v", err)
	}
	_, err = svc.AdminCreateUser(context.Background(), "bob@example.com", "BobsPass1", false)
	if err != nil {
		t.Fatalf("setup bob: %v", err)
	}

	// Alice creates a player through the domain service directly.
	alicePlayer, err := svc.CreatePlayer(context.Background(), alice.ID, "AliceChar", "")
	if err != nil {
		t.Fatalf("setup alice player: %v", err)
	}

	// Bob tries to rename Alice's player.
	req, _ := http.NewRequest(http.MethodPatch,
		ts.URL+"/api/me/players/"+alicePlayer.ID,
		jsonBody(t, map[string]string{"name": "Hijacked"}))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("bob@example.com", "BobsPass1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PATCH player: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("bob accessing alice's player: expected 404, got %d", resp.StatusCode)
	}
}

// TestConfigNewFields is a direct config.Load test for the new fields.
// It does not touch the HTTP stack; it validates the config package in isolation.
func TestConfigNewFields(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr bool
		check   func(*testing.T, *config.Config)
	}{
		{
			name: "invalid UUIDGeneration rejects at startup",
			yaml: `
base_url: "https://auth.example.com"
uuid_generation: "md5"
`,
			wantErr: true,
		},
		{
			name: "identical prefixes rejected",
			yaml: `
base_url: "https://auth.example.com"
api_prefix: "/same"
admin_prefix: "/same"
`,
			wantErr: true,
		},
		{
			name: "offline UUID generation accepted",
			yaml: `
base_url: "https://auth.example.com"
uuid_generation: "offline"
`,
			check: func(t *testing.T, cfg *config.Config) {
				if cfg.UUIDGeneration != "offline" {
					t.Errorf("expected offline, got %s", cfg.UUIDGeneration)
				}
			},
		},
		{
			name: "require invite parsed",
			yaml: `
base_url: "https://auth.example.com"
require_invite: true
`,
			check: func(t *testing.T, cfg *config.Config) {
				if !cfg.RequireInvite {
					t.Error("expected RequireInvite true")
				}
			},
		},
		{
			name: "default admins list",
			yaml: `
base_url: "https://auth.example.com"
default_admins:
  - "a@b.com"
  - "c@d.com"
`,
			check: func(t *testing.T, cfg *config.Config) {
				if len(cfg.DefaultAdmins) != 2 {
					t.Fatalf("expected 2 admins, got %d", len(cfg.DefaultAdmins))
				}
				if cfg.DefaultAdmins[0] != "a@b.com" {
					t.Errorf("first admin: expected a@b.com, got %s", cfg.DefaultAdmins[0])
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(path, []byte(tt.yaml), 0600); err != nil {
				t.Fatalf("writing temp config: %v", err)
			}

			cfg, err := config.Load(path)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, cfg)
			}
		})
	}
}

// TestAdminUserManagement exercises the admin user CRUD endpoints.
func TestAdminUserManagement(t *testing.T) {
	cfg := defaultTestConfig()
	ts, svc, _ := newTestStack(t, cfg)

	adminEmail := "superadmin@example.com"
	adminPass := "SuperPass123"
	_, err := svc.AdminCreateUser(context.Background(), adminEmail, adminPass, true)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	doAdmin := func(method, path string, body any) *http.Response {
		var br *bytes.Reader
		if body != nil {
			br = jsonBody(t, body)
		} else {
			br = bytes.NewReader(nil)
		}
		req, _ := http.NewRequest(method, ts.URL+"/admin"+path, br)
		req.Header.Set("Content-Type", "application/json")
		req.SetBasicAuth(adminEmail, adminPass)
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s /admin%s: %v", method, path, err)
		}
		return r
	}

	// Create a user via admin API.
	r := doAdmin(http.MethodPost, "/users", map[string]any{
		"email":    "managed@example.com",
		"password": "Managed123",
		"isAdmin":  false,
	})
	defer r.Body.Close()
	if r.StatusCode != http.StatusCreated {
		t.Fatalf("create user: expected 201, got %d", r.StatusCode)
	}
	var created map[string]any
	decodeBody(t, r, &created)
	userID, _ := created["id"].(string)
	if userID == "" {
		t.Fatal("create user response missing id")
	}
	if _, exists := created["password_hash"]; exists {
		t.Error("password_hash must not appear in the response")
	}

	// Verify GET /admin/users/{id} works.
	r2 := doAdmin(http.MethodGet, "/users/"+userID, nil)
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusOK {
		t.Fatalf("get user: expected 200, got %d", r2.StatusCode)
	}

	// Promote to admin.
	r3 := doAdmin(http.MethodPut, "/users/"+userID+"/admin", map[string]any{"isAdmin": true})
	defer r3.Body.Close()
	if r3.StatusCode != http.StatusOK {
		t.Fatalf("set admin: expected 200, got %d", r3.StatusCode)
	}
	var updated map[string]any
	decodeBody(t, r3, &updated)
	if updated["is_admin"] != true {
		t.Errorf("set admin: is_admin should be true, got %v", updated["is_admin"])
	}

	// Delete user.
	r4 := doAdmin(http.MethodDelete, "/users/"+userID, nil)
	r4.Body.Close()
	if r4.StatusCode != http.StatusNoContent {
		t.Errorf("delete user: expected 204, got %d", r4.StatusCode)
	}

	// GET after delete must be 404.
	r5 := doAdmin(http.MethodGet, "/users/"+userID, nil)
	r5.Body.Close()
	if r5.StatusCode != http.StatusNotFound {
		t.Errorf("get deleted user: expected 404, got %d", r5.StatusCode)
	}
}

// TestGetAdminUsersTime is a regression guard: verifies that user list timestamps are
// properly serialized (not zero values), which would happen if the DB scan was broken.
func TestGetAdminUsersTime(t *testing.T) {
	cfg := defaultTestConfig()
	ts, svc, _ := newTestStack(t, cfg)

	adminEmail := "timeadmin@example.com"
	adminPass := "TimePass123"
	_, err := svc.AdminCreateUser(context.Background(), adminEmail, adminPass, true)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/admin/users", nil)
	req.SetBasicAuth(adminEmail, adminPass)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /admin/users: %v", err)
	}
	defer resp.Body.Close()

	var users []map[string]any
	decodeBody(t, resp, &users)
	if len(users) == 0 {
		t.Fatal("expected at least one user")
	}
	createdAt, _ := users[0]["created_at"].(string)
	if createdAt == "" {
		t.Error("created_at should not be empty")
	}
	// Parse to confirm it is a real timestamp.
	if _, err := time.Parse(time.RFC3339Nano, createdAt); err != nil {
		t.Errorf("created_at %q is not a valid RFC3339 timestamp: %v", createdAt, err)
	}
}

// generateTestPNG creates a solid-colour RGBA PNG of the given dimensions in memory.
// Used in texture e2e tests; no base64 blobs embedded.
func generateTestPNG(t *testing.T, width, height int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, color.RGBA{R: 0x3c, G: 0x7e, B: 0xab, A: 0xff})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("generateTestPNG: %v", err)
	}
	return buf.Bytes()
}

// TestTextureUploadAndServe is the end-to-end canary for the full texture pipeline:
//  1. Register a user and create a player via the accounts service.
//  2. Upload a 64x64 slim-model skin via PUT /api/me/players/{id}/skin?model=slim.
//  3. Fetch the Yggdrasil profile and verify the SKIN URL points to the right hash.
//  4. Fetch the texture file via GET /textures/{hash} and verify the bytes match.
func TestTextureUploadAndServe(t *testing.T) {
	cfg := defaultTestConfig()
	// Allow 64x64 skins (the default limit).
	cfg.SkinSizeLimit = 64

	ts, svc, _ := newTestStack(t, cfg)

	// Register a user directly through the service (bypasses HTTP registration).
	ctx := context.Background()
	userEmail := "skintester@example.com"
	userPass := "SkinPass123"
	user, err := svc.AdminCreateUser(ctx, userEmail, userPass, false)
	if err != nil {
		t.Fatalf("setup: creating user: %v", err)
	}
	player, err := svc.CreatePlayer(ctx, user.ID, "SkinPlayer", "")
	if err != nil {
		t.Fatalf("setup: creating player: %v", err)
	}

	// Generate a valid 64x64 skin PNG in code.
	skinPNG := generateTestPNG(t, 64, 64)

	// Upload the skin with model=slim.
	uploadURL := ts.URL + "/api/me/players/" + player.ID + "/skin?model=slim"
	req, err := http.NewRequest(http.MethodPut, uploadURL, bytes.NewReader(skinPNG))
	if err != nil {
		t.Fatalf("build upload request: %v", err)
	}
	req.Header.Set("Content-Type", "image/png")
	req.SetBasicAuth(userEmail, userPass)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT skin: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT skin: expected 200, got %d", resp.StatusCode)
	}

	// Decode the updated player from the response.
	var updatedPlayer struct {
		SkinHash *string `json:"skin_hash"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&updatedPlayer); err != nil {
		t.Fatalf("decode PUT skin response: %v", err)
	}
	if updatedPlayer.SkinHash == nil || *updatedPlayer.SkinHash == "" {
		t.Fatal("PUT skin response did not include a skin_hash")
	}
	skinHash := *updatedPlayer.SkinHash

	// Fetch the Yggdrasil profile and verify the textures payload.
	// The profile is served at GET /authlib-injector/sessionserver/session/minecraft/profile/{undashed-uuid}.
	undashed := strings.ReplaceAll(player.UUID, "-", "")
	profileURL := ts.URL + "/authlib-injector/sessionserver/session/minecraft/profile/" + undashed
	profileResp, err := http.Get(profileURL)
	if err != nil {
		t.Fatalf("GET profile: %v", err)
	}
	defer profileResp.Body.Close()
	if profileResp.StatusCode != http.StatusOK {
		t.Fatalf("GET profile: expected 200, got %d", profileResp.StatusCode)
	}

	var profile struct {
		Properties []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"properties"`
	}
	if err := json.NewDecoder(profileResp.Body).Decode(&profile); err != nil {
		t.Fatalf("decode profile: %v", err)
	}

	var textureValue string
	for _, prop := range profile.Properties {
		if prop.Name == "textures" {
			textureValue = prop.Value
			break
		}
	}
	if textureValue == "" {
		t.Fatal("profile has no textures property")
	}

	// Decode the base64-encoded texture payload and inspect SKIN entry.
	payloadJSON, err := base64.StdEncoding.DecodeString(textureValue)
	if err != nil {
		t.Fatalf("decoding texture value: %v", err)
	}
	var payload struct {
		Textures map[string]struct {
			URL      string         `json:"url"`
			Metadata map[string]any `json:"metadata"`
		} `json:"textures"`
	}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		t.Fatalf("unmarshal texture payload: %v", err)
	}
	skinEntry, ok := payload.Textures["SKIN"]
	if !ok {
		t.Fatal("texture payload has no SKIN key")
	}
	wantSuffix := "/textures/" + skinHash
	if !strings.HasSuffix(skinEntry.URL, wantSuffix) {
		t.Errorf("SKIN url %q does not end with %q", skinEntry.URL, wantSuffix)
	}
	// Slim model must carry metadata.model == "slim".
	if skinEntry.Metadata["model"] != "slim" {
		t.Errorf("SKIN metadata.model = %v; want \"slim\"", skinEntry.Metadata["model"])
	}

	// Fetch the actual texture file from the root-level GET /textures/{hash} route.
	textureFileURL := ts.URL + "/textures/" + skinHash
	fileResp, err := http.Get(textureFileURL)
	if err != nil {
		t.Fatalf("GET /textures/%s: %v", skinHash, err)
	}
	defer fileResp.Body.Close()
	if fileResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /textures/%s: expected 200, got %d", skinHash, fileResp.StatusCode)
	}
	if ct := fileResp.Header.Get("Content-Type"); ct != "image/png" {
		t.Errorf("Content-Type = %q; want image/png", ct)
	}
	body, err := io.ReadAll(fileResp.Body)
	if err != nil {
		t.Fatalf("reading texture file: %v", err)
	}
	if !bytes.Equal(body, skinPNG) {
		t.Error("texture file bytes differ from uploaded PNG bytes")
	}
}

// TestSkinUploadDisabledReturns403 verifies that the AllowSkins=false config causes
// the skin upload endpoint to return 403 Forbidden.
func TestSkinUploadDisabledReturns403(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.AllowSkins = false

	ts, svc, _ := newTestStack(t, cfg)

	ctx := context.Background()
	user, err := svc.AdminCreateUser(ctx, "noskin@example.com", "NoSkinPass1", false)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	player, err := svc.CreatePlayer(ctx, user.ID, "NoSkinPlayer", "")
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	skinPNG := generateTestPNG(t, 64, 64)
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/me/players/"+player.ID+"/skin", bytes.NewReader(skinPNG))
	req.Header.Set("Content-Type", "image/png")
	req.SetBasicAuth("noskin@example.com", "NoSkinPass1")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT skin: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 when AllowSkins=false, got %d", resp.StatusCode)
	}
}

// TestSkinUploadBadDimension verifies that a PNG with wrong dimensions is rejected with 400.
func TestSkinUploadBadDimension(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.SkinSizeLimit = 64

	ts, svc, _ := newTestStack(t, cfg)

	ctx := context.Background()
	user, err := svc.AdminCreateUser(ctx, "badskin@example.com", "BadSkinPass1", false)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	player, err := svc.CreatePlayer(ctx, user.ID, "BadSkinPlayer", "")
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	// A 128x128 skin when SkinSizeLimit=64 should be rejected.
	bigPNG := generateTestPNG(t, 128, 128)
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/me/players/"+player.ID+"/skin?model=classic", bytes.NewReader(bigPNG))
	req.Header.Set("Content-Type", "image/png")
	req.SetBasicAuth("badskin@example.com", "BadSkinPass1")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT skin: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for oversized skin, got %d", resp.StatusCode)
	}
}

func TestHTTPServer_PasswordReset(t *testing.T) {
	cfg := defaultTestConfig()
	ts, svc, _ := newTestStack(t, cfg)

	// Create an admin user.
	adminEmail := "admin-reset@example.com"
	adminPass := "AdminPass123"
	_, err := svc.AdminCreateUser(context.Background(), adminEmail, adminPass, true)
	if err != nil {
		t.Fatalf("setup admin: %v", err)
	}

	// Create a target user.
	targetEmail := "user-reset@example.com"
	targetPass := "UserPass123"
	targetUser, err := svc.AdminCreateUser(context.Background(), targetEmail, targetPass, false)
	if err != nil {
		t.Fatalf("setup target user: %v", err)
	}

	// 1. As admin, POST /admin/users/{id}/reset-token
	resetURL := ts.URL + "/admin/users/" + targetUser.ID + "/reset-token"
	req, err := http.NewRequest(http.MethodPost, resetURL, nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.SetBasicAuth(adminEmail, adminPass)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST reset-token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var resetRes map[string]any
	decodeBody(t, resp, &resetRes)

	resetLink, ok := resetRes["resetUrl"].(string)
	if !ok || resetLink == "" {
		t.Fatalf("invalid or missing resetUrl in response: %v", resetRes)
	}

	// Verify resetUrl contains "token="
	if !strings.Contains(resetLink, "token=") {
		t.Errorf("expected resetUrl to contain 'token=', got: %s", resetLink)
	}

	// Extract token from URL
	u, err := url.Parse(resetLink)
	if err != nil {
		t.Fatalf("failed to parse reset link URL: %v", err)
	}
	token := u.Query().Get("token")
	if token == "" {
		t.Fatal("extracted token is empty")
	}

	// 2. POST /api/reset-password unauthenticated
	newPass := "NewPassword123"
	resetBody := map[string]string{
		"token":    token,
		"password": newPass,
	}
	resp2, err := http.Post(ts.URL+"/api/reset-password", "application/json", jsonBody(t, resetBody))
	if err != nil {
		t.Fatalf("POST reset-password: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200 from reset-password, got %d", resp2.StatusCode)
	}

	// 3. Assert old password no longer authenticates
	reqOld, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/me", nil)
	reqOld.SetBasicAuth(targetEmail, targetPass)
	respOld, err := http.DefaultClient.Do(reqOld)
	if err != nil {
		t.Fatalf("GET /api/me with old password: %v", err)
	}
	defer respOld.Body.Close()
	if respOld.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized for old password, got %d", respOld.StatusCode)
	}

	// 4. Assert new password successfully authenticates
	reqNew, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/me", nil)
	reqNew.SetBasicAuth(targetEmail, newPass)
	respNew, err := http.DefaultClient.Do(reqNew)
	if err != nil {
		t.Fatalf("GET /api/me with new password: %v", err)
	}
	defer respNew.Body.Close()
	if respNew.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK for new password, got %d", respNew.StatusCode)
	}
}

func TestEmailVerificationFlow_Integration(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.RequireEmailVerification = true

	mail := &fakeMailer{}
	ts, _, _ := newTestStackWithMailer(t, cfg, mail)

	const email = "verify-flow@example.com"
	const password = "password123"

	// 1. Register a new user
	regReq := map[string]string{
		"email":    email,
		"password": password,
	}
	resp, err := http.Post(ts.URL+"/api/register", "application/json", jsonBody(t, regReq))
	if err != nil {
		t.Fatalf("POST /api/register: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected status 201 Created from register, got %d", resp.StatusCode)
	}

	var regRes struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	decodeBody(t, resp, &regRes)

	if regRes.EmailVerified {
		t.Fatalf("expected email_verified to be false, got true")
	}

	// Capture verify token from the mailer
	mail.mu.Lock()
	body := mail.lastBody
	mail.mu.Unlock()

	if !strings.Contains(body, "/verify?token=") {
		t.Fatalf("expected verification email with link, got body: %s", body)
	}

	// extract the token from link
	tokenPart := strings.Split(body, "/verify?token=")
	if len(tokenPart) < 2 {
		t.Fatalf("failed to parse token from body: %s", body)
	}
	token := tokenPart[1]
	if idx := strings.Index(token, "\""); idx != -1 {
		token = token[:idx]
	}
	token, err = url.QueryUnescape(token)
	if err != nil {
		t.Fatalf("failed to query unescape token: %v", err)
	}

	// 2. Attempt login before email verification -> should return 403 Forbidden with EmailNotVerified
	loginReq := map[string]string{
		"email":    email,
		"password": password,
	}
	respLogin1, err := http.Post(ts.URL+"/web/api/login", "application/json", jsonBody(t, loginReq))
	if err != nil {
		t.Fatalf("POST /web/api/login before verification: %v", err)
	}
	defer respLogin1.Body.Close()

	if respLogin1.StatusCode != http.StatusForbidden {
		t.Fatalf("expected login to fail with 403 Forbidden, got %d", respLogin1.StatusCode)
	}

	var errRes struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	decodeBody(t, respLogin1, &errRes)
	if errRes.Error != "EmailNotVerified" {
		t.Errorf("expected error code EmailNotVerified, got: %s", errRes.Error)
	}

	// 3. Verify Email Address using /api/verify-email
	verifyReq := map[string]string{
		"token": token,
	}
	respVerify, err := http.Post(ts.URL+"/api/verify-email", "application/json", jsonBody(t, verifyReq))
	if err != nil {
		t.Fatalf("POST /api/verify-email: %v", err)
	}
	defer respVerify.Body.Close()

	if respVerify.StatusCode != http.StatusOK {
		t.Fatalf("expected verify email to succeed with 200, got %d", respVerify.StatusCode)
	}

	// 4. Attempt login after verification -> should succeed (200 OK)
	respLogin2, err := http.Post(ts.URL+"/web/api/login", "application/json", jsonBody(t, loginReq))
	if err != nil {
		t.Fatalf("POST /web/api/login after verification: %v", err)
	}
	defer respLogin2.Body.Close()

	if respLogin2.StatusCode != http.StatusOK {
		t.Fatalf("expected login to succeed after verification with 200, got %d", respLogin2.StatusCode)
	}
}

func TestForgotPasswordAndResendFlow_Integration(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.RequireEmailVerification = true

	mail := &fakeMailer{}
	ts, _, _ := newTestStackWithMailer(t, cfg, mail)

	const email = "forgot-flow@example.com"
	const password = "password123"

	// Register user
	regReq := map[string]string{
		"email":    email,
		"password": password,
	}
	respReg, err := http.Post(ts.URL+"/api/register", "application/json", jsonBody(t, regReq))
	if err != nil {
		t.Fatalf("POST /api/register: %v", err)
	}
	respReg.Body.Close()

	// Clear fakeMailer
	mail.mu.Lock()
	mail.lastBody = ""
	mail.mu.Unlock()

	// 1. Resend verification flow for existing unverified user
	resendReq := map[string]string{
		"email": email,
	}
	respResend, err := http.Post(ts.URL+"/api/resend-verification", "application/json", jsonBody(t, resendReq))
	if err != nil {
		t.Fatalf("POST /api/resend-verification: %v", err)
	}
	defer respResend.Body.Close()

	if respResend.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from resend-verification, got %d", respResend.StatusCode)
	}

	mail.mu.Lock()
	resendBody := mail.lastBody
	mail.mu.Unlock()

	if !strings.Contains(resendBody, "/verify?token=") {
		t.Fatalf("expected resend mail to contain verify token, got body: %s", resendBody)
	}

	// 2. Resend verification flow for nonexistent user (should still return 200, but no mail sent)
	mail.mu.Lock()
	mail.lastBody = ""
	mail.mu.Unlock()

	resendReq2 := map[string]string{
		"email": "nonexistent-resend@example.com",
	}
	respResend2, err := http.Post(ts.URL+"/api/resend-verification", "application/json", jsonBody(t, resendReq2))
	if err != nil {
		t.Fatalf("POST /api/resend-verification (nonexistent): %v", err)
	}
	defer respResend2.Body.Close()

	if respResend2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from resend-verification (nonexistent), got %d", respResend2.StatusCode)
	}

	mail.mu.Lock()
	resendBody2 := mail.lastBody
	mail.mu.Unlock()
	if resendBody2 != "" {
		t.Fatalf("expected no email to be sent for nonexistent user, got: %s", resendBody2)
	}

	// 3. Forgot Password Flow for existing user (we need to verify user first so forgot password actually sends)
	// Let's first extract verify token and verify email so forgot-password has a verified user
	tokenPart := strings.Split(resendBody, "/verify?token=")
	token := tokenPart[1]
	if idx := strings.Index(token, "\""); idx != -1 {
		token = token[:idx]
	}
	token, _ = url.QueryUnescape(token)

	verifyReq := map[string]string{
		"token": token,
	}
	respVerify, _ := http.Post(ts.URL+"/api/verify-email", "application/json", jsonBody(t, verifyReq))
	respVerify.Body.Close()

	// Clear mailer
	mail.mu.Lock()
	mail.lastBody = ""
	mail.mu.Unlock()

	forgotReq := map[string]string{
		"email": email,
	}
	respForgot, err := http.Post(ts.URL+"/api/forgot-password", "application/json", jsonBody(t, forgotReq))
	if err != nil {
		t.Fatalf("POST /api/forgot-password: %v", err)
	}
	defer respForgot.Body.Close()

	if respForgot.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from forgot-password, got %d", respForgot.StatusCode)
	}

	mail.mu.Lock()
	forgotBody := mail.lastBody
	mail.mu.Unlock()

	if !strings.Contains(forgotBody, "/reset?token=") {
		t.Fatalf("expected forgot-password mail to contain reset token, got body: %s", forgotBody)
	}

	// 4. Forgot Password Flow for nonexistent user (should return 200, but no mail sent)
	mail.mu.Lock()
	mail.lastBody = ""
	mail.mu.Unlock()

	forgotReq2 := map[string]string{
		"email": "nonexistent-forgot@example.com",
	}
	respForgot2, err := http.Post(ts.URL+"/api/forgot-password", "application/json", jsonBody(t, forgotReq2))
	if err != nil {
		t.Fatalf("POST /api/forgot-password (nonexistent): %v", err)
	}
	defer respForgot2.Body.Close()

	if respForgot2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from forgot-password (nonexistent), got %d", respForgot2.StatusCode)
	}

	mail.mu.Lock()
	forgotBody2 := mail.lastBody
	mail.mu.Unlock()
	if forgotBody2 != "" {
		t.Fatalf("expected no email to be sent for nonexistent user on forgot password, got: %s", forgotBody2)
	}
}

func TestBackupAndRestoreEndpoints(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.StateDir = t.TempDir()

	// Seed key and textures directory
	keyPath := filepath.Join(cfg.StateDir, "signing.key")
	if err := os.WriteFile(keyPath, []byte("fake-key-data"), 0o600); err != nil {
		t.Fatalf("failed to write mock signing key: %v", err)
	}
	texturesDir := filepath.Join(cfg.StateDir, "textures")
	if err := os.MkdirAll(texturesDir, 0o755); err != nil {
		t.Fatalf("failed to create mock textures dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(texturesDir, "test.png"), []byte("fake-texture-data"), 0o644); err != nil {
		t.Fatalf("failed to write mock texture: %v", err)
	}

	ts, svc, _ := newTestStack(t, cfg)

	email := "admin@example.com"
	password := "AdminPass123"

	// Create admin user
	_, err := svc.AdminCreateUser(context.Background(), email, password, true)
	if err != nil {
		t.Fatalf("setup: creating admin user: %v", err)
	}

	// 1. Test GET /admin/backup
	reqBackup, err := http.NewRequest(http.MethodGet, ts.URL+"/admin/backup", nil)
	if err != nil {
		t.Fatalf("failed to create backup request: %v", err)
	}
	reqBackup.SetBasicAuth(email, password)

	respBackup, err := http.DefaultClient.Do(reqBackup)
	if err != nil {
		t.Fatalf("GET /admin/backup: %v", err)
	}
	defer respBackup.Body.Close()

	if respBackup.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200 from backup, got %d", respBackup.StatusCode)
	}

	contentType := respBackup.Header.Get("Content-Type")
	if contentType != "application/gzip" {
		t.Errorf("expected Content-Type application/gzip, got %q", contentType)
	}

	backupBytes, err := io.ReadAll(respBackup.Body)
	if err != nil {
		t.Fatalf("failed to read backup response body: %v", err)
	}

	// Validate the backup archive
	err = backup.ValidateArchive(bytes.NewReader(backupBytes))
	if err != nil {
		t.Fatalf("ValidateArchive failed on downloaded backup: %v", err)
	}

	// 2. Test POST /admin/restore
	reqRestore, err := http.NewRequest(http.MethodPost, ts.URL+"/admin/restore", bytes.NewReader(backupBytes))
	if err != nil {
		t.Fatalf("failed to create restore request: %v", err)
	}
	reqRestore.SetBasicAuth(email, password)
	reqRestore.Header.Set("Content-Type", "application/gzip")

	respRestore, err := http.DefaultClient.Do(reqRestore)
	if err != nil {
		t.Fatalf("POST /admin/restore: %v", err)
	}
	defer respRestore.Body.Close()

	if respRestore.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(respRestore.Body)
		t.Fatalf("expected status 200 from restore, got %d. Body: %s", respRestore.StatusCode, body)
	}

	var restoreResp map[string]string
	if err := json.NewDecoder(respRestore.Body).Decode(&restoreResp); err != nil {
		t.Fatalf("failed to decode restore response: %v", err)
	}

	if restoreResp["status"] != "ok" {
		t.Errorf("expected restore response status 'ok', got %q", restoreResp["status"])
	}

	// Verify .restore-pending.tar.gz exists in the test StateDir
	pendingPath := filepath.Join(cfg.StateDir, ".restore-pending.tar.gz")
	if _, err := os.Stat(pendingPath); err != nil {
		t.Errorf("expected pending restore archive to exist at %s: %v", pendingPath, err)
	}
}

func TestGamePasswordIntegration(t *testing.T) {
	cfg := defaultTestConfig()
	ts, svc, _ := newTestStack(t, cfg)
	ctx := context.Background()

	// 1. Create a verified user with a player
	userEmail := "gameintegration@example.com"
	accountPass := "AccountPass123"
	user, err := svc.AdminCreateUser(ctx, userEmail, accountPass, false)
	if err != nil {
		t.Fatalf("setup: creating user: %v", err)
	}
	_, err = svc.CreatePlayer(ctx, user.ID, "GamePlayer", "")
	if err != nil {
		t.Fatalf("setup: creating player: %v", err)
	}

	// 2. Before setting a game password, authenticating with the ACCOUNT password via Yggdrasil should succeed.
	authBodyAccount := map[string]any{
		"username": userEmail,
		"password": accountPass,
	}
	authJSONAccount, _ := json.Marshal(authBodyAccount)

	resp, err := http.Post(ts.URL+"/authlib-injector/authserver/authenticate", "application/json", bytes.NewReader(authJSONAccount))
	if err != nil {
		t.Fatalf("Yggdrasil authenticate request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 before setting game password, got %d. Body: %s", resp.StatusCode, body)
	}

	var authResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		t.Fatalf("failed to decode authenticate response: %v", err)
	}
	profiles, ok := authResp["availableProfiles"].([]any)
	if !ok || len(profiles) == 0 {
		t.Fatalf("expected availableProfiles to contain the seeded player")
	}

	// 3. Set a game password via PUT /api/me/game-password (authenticated via Basic Auth using the ACCOUNT password)
	gamePass := "DedicatedGamePass123"
	setGamePassBody, _ := json.Marshal(map[string]string{"password": gamePass})
	reqSet, err := http.NewRequest(http.MethodPut, ts.URL+"/api/me/game-password", bytes.NewReader(setGamePassBody))
	if err != nil {
		t.Fatalf("failed to create PUT game-password request: %v", err)
	}
	reqSet.SetBasicAuth(userEmail, accountPass)
	reqSet.Header.Set("Content-Type", "application/json")

	respSet, err := http.DefaultClient.Do(reqSet)
	if err != nil {
		t.Fatalf("PUT /api/me/game-password: %v", err)
	}
	defer respSet.Body.Close()
	if respSet.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(respSet.Body)
		t.Fatalf("expected 200 from PUT game-password, got %d. Body: %s", respSet.StatusCode, body)
	}

	var statusResp map[string]string
	if err := json.NewDecoder(respSet.Body).Decode(&statusResp); err != nil {
		t.Fatalf("failed to decode PUT game-password response: %v", err)
	}
	if statusResp["status"] != "ok" {
		t.Errorf("expected status 'ok', got %q", statusResp["status"])
	}

	// 4. Now, Yggdrasil authenticate with the ACCOUNT password must FAIL with 403
	respFail, err := http.Post(ts.URL+"/authlib-injector/authserver/authenticate", "application/json", bytes.NewReader(authJSONAccount))
	if err != nil {
		t.Fatalf("Yggdrasil authenticate request: %v", err)
	}
	defer respFail.Body.Close()
	if respFail.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(respFail.Body)
		t.Fatalf("expected 403 when using account password, got %d. Body: %s", respFail.StatusCode, body)
	}

	// 5. Yggdrasil authenticate with the GAME password must SUCCEED with 200 and availableProfiles
	authBodyGame := map[string]any{
		"username": userEmail,
		"password": gamePass,
	}
	authJSONGame, _ := json.Marshal(authBodyGame)
	respSuccess, err := http.Post(ts.URL+"/authlib-injector/authserver/authenticate", "application/json", bytes.NewReader(authJSONGame))
	if err != nil {
		t.Fatalf("Yggdrasil authenticate request: %v", err)
	}
	defer respSuccess.Body.Close()
	if respSuccess.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(respSuccess.Body)
		t.Fatalf("expected 200 with game password, got %d. Body: %s", respSuccess.StatusCode, body)
	}

	var authRespGame map[string]any
	if err := json.NewDecoder(respSuccess.Body).Decode(&authRespGame); err != nil {
		t.Fatalf("failed to decode authenticate response: %v", err)
	}
	profilesGame, ok := authRespGame["availableProfiles"].([]any)
	if !ok || len(profilesGame) == 0 {
		t.Fatalf("expected availableProfiles with game password")
	}

	// 6. Web/management plane login with ACCOUNT password must STILL succeed (200)
	webLoginBody, _ := json.Marshal(map[string]string{
		"email":    userEmail,
		"password": accountPass,
	})
	respWebLogin, err := http.Post(ts.URL+"/web/api/login", "application/json", bytes.NewReader(webLoginBody))
	if err != nil {
		t.Fatalf("web login request: %v", err)
	}
	defer respWebLogin.Body.Close()
	if respWebLogin.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(respWebLogin.Body)
		t.Fatalf("expected 200 for web login with account password, got %d. Body: %s", respWebLogin.StatusCode, body)
	}

	// 7. Clear the game password via DELETE /api/me/game-password (authenticated via Basic Auth with ACCOUNT password)
	reqDelete, err := http.NewRequest(http.MethodDelete, ts.URL+"/api/me/game-password", nil)
	if err != nil {
		t.Fatalf("failed to create DELETE request: %v", err)
	}
	reqDelete.SetBasicAuth(userEmail, accountPass)

	respDelete, err := http.DefaultClient.Do(reqDelete)
	if err != nil {
		t.Fatalf("DELETE /api/me/game-password: %v", err)
	}
	defer respDelete.Body.Close()
	if respDelete.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(respDelete.Body)
		t.Fatalf("expected 200 from DELETE, got %d. Body: %s", respDelete.StatusCode, body)
	}

	var clearResp map[string]string
	if err := json.NewDecoder(respDelete.Body).Decode(&clearResp); err != nil {
		t.Fatalf("failed to decode clear response: %v", err)
	}
	if clearResp["status"] != "ok" {
		t.Errorf("expected status 'ok', got %q", clearResp["status"])
	}

	// 8. After clearing, Yggdrasil authenticate with the ACCOUNT password must SUCCEED again!
	respCleared, err := http.Post(ts.URL+"/authlib-injector/authserver/authenticate", "application/json", bytes.NewReader(authJSONAccount))
	if err != nil {
		t.Fatalf("Yggdrasil authenticate request: %v", err)
	}
	defer respCleared.Body.Close()
	if respCleared.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(respCleared.Body)
		t.Fatalf("expected 200 after clearing game password, got %d. Body: %s", respCleared.StatusCode, body)
	}
}
