package httpserver_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/achetronic/minecrauth/internal/accounts"
	"github.com/achetronic/minecrauth/internal/auth"
	"github.com/achetronic/minecrauth/internal/config"
	"github.com/achetronic/minecrauth/internal/httpserver"
	"github.com/achetronic/minecrauth/internal/store"
	sqlitestore "github.com/achetronic/minecrauth/internal/store/sqlite"
	"github.com/achetronic/minecrauth/internal/textures"
	"github.com/achetronic/minecrauth/internal/yggdrasil"
)

type oidcWebJWTHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

type oidcWebJWTPayload struct {
	Iss           string `json:"iss"`
	Aud           string `json:"aud"`
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified *bool  `json:"email_verified,omitempty"`
	Exp           int64  `json:"exp"`
	Iat           int64  `json:"iat"`
}

func oidcWebMintRS256JWT(t *testing.T, key *rsa.PrivateKey, kid string, payload oidcWebJWTPayload) string {
	t.Helper()

	hdrBytes, err := json.Marshal(oidcWebJWTHeader{Alg: "RS256", Kid: kid, Typ: "JWT"})
	if err != nil {
		t.Fatalf("marshal JWT header: %v", err)
	}
	payBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal JWT payload: %v", err)
	}

	h := base64.RawURLEncoding.EncodeToString(hdrBytes)
	p := base64.RawURLEncoding.EncodeToString(payBytes)
	msg := h + "." + p

	digest := sha256.Sum256([]byte(msg))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}

	return msg + "." + base64.RawURLEncoding.EncodeToString(sig)
}

type oidcWebJWKKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type oidcWebJWKSet struct {
	Keys []oidcWebJWKKey `json:"keys"`
}

func oidcWebRsaPublicKeyToJWK(pub *rsa.PublicKey, kid string) oidcWebJWKKey {
	nBytes := pub.N.Bytes()
	eBytes := new(big.Int).SetInt64(int64(pub.E)).Bytes()
	return oidcWebJWKKey{
		Kty: "RSA",
		Kid: kid,
		Use: "sig",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(nBytes),
		E:   base64.RawURLEncoding.EncodeToString(eBytes),
	}
}

type oidcWebFakeIdP struct {
	server     *httptest.Server
	key        *rsa.PrivateKey
	kid        string
	issuerURL  string
	getPayload func() oidcWebJWTPayload
}

func newOIDCWebFakeIdP(t *testing.T, getPayload func() oidcWebJWTPayload) *oidcWebFakeIdP {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	issuerURL := "http://" + ln.Addr().String()
	kid := "test-key-web-1"

	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		doc := map[string]interface{}{
			"issuer":                                issuerURL,
			"jwks_uri":                              issuerURL + "/keys",
			"authorization_endpoint":                issuerURL + "/auth",
			"token_endpoint":                        issuerURL + "/token",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}
		_ = json.NewEncoder(w).Encode(doc)
	})

	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		ks := oidcWebJWKSet{Keys: []oidcWebJWKKey{oidcWebRsaPublicKeyToJWK(&key.PublicKey, kid)}}
		_ = json.NewEncoder(w).Encode(ks)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		idTok := oidcWebMintRS256JWT(t, key, kid, getPayload())
		resp := map[string]interface{}{
			"access_token": "x",
			"token_type":   "Bearer",
			"id_token":     idTok,
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	srv := httptest.NewUnstartedServer(mux)
	srv.Listener = ln
	srv.Start()

	idp := &oidcWebFakeIdP{
		server:     srv,
		key:        key,
		kid:        kid,
		issuerURL:  issuerURL,
		getPayload: getPayload,
	}
	t.Cleanup(func() { srv.Close() })
	return idp
}

type oidcWebProvisioner struct {
	store store.Store
}

func (p *oidcWebProvisioner) CreateProvisionedUser(ctx context.Context, email string) (*store.User, error) {
	u := &store.User{
		ID:      "provisioned-user-web-id",
		Email:   email,
		IsAdmin: false,
		Blocked: false,
	}
	if err := p.store.CreateUser(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

func newOidcWebTestStack(t *testing.T, cfg *config.Config, st store.Store, browserFlow *auth.OIDCBrowserFlow) (*webStack, *http.Client) {
	t.Helper()

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

	yggH := yggdrasil.NewHandler(tokenSvc, authn, svc, km, cfg.ServerName, cfg.Domain, cfg.BaseURL, nil, false, false, true, true)

	textureDir := t.TempDir()
	textureSt, err := textures.New(textureDir)
	if err != nil {
		t.Fatalf("texture store: %v", err)
	}

	sessionTTL := time.Duration(cfg.SessionTTLSeconds) * time.Second
	sessionMgr := auth.NewSessionManager(st, sessionTTL, nil)

	srv, err := httpserver.New(cfg, httpserver.Deps{
		Accounts:    svc,
		Tokens:      tokenSvc,
		Authn:       authn,
		Keys:        km,
		YggHandler:  yggH,
		Textures:    textureSt,
		Sessions:    sessionMgr,
		Store:       st,
		OIDCBrowser: browserFlow,
	})
	if err != nil {
		t.Fatalf("httpserver: %v", err)
	}

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &webStack{
		Server:     ts,
		Svc:        svc,
		Store:      st.(*sqlitestore.Store),
		SessionMgr: sessionMgr,
	}, client
}

func TestOIDCWeb_Disabled(t *testing.T) {
	cfg := defaultTestConfig()
	st, err := sqlitestore.New(":memory:")
	if err != nil {
		t.Fatalf("failed to init SQLite: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("migration failed: %v", err)
	}

	ws, client := newOidcWebTestStack(t, cfg, st, nil)

	// GET /oauth/login -> 404
	resp, err := client.Get(ws.Server.URL + "/oauth/login")
	if err != nil {
		t.Fatalf("GET /oauth/login: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 for disabled OIDC login, got %d", resp.StatusCode)
	}

	// GET /oauth/callback -> 404
	resp, err = client.Get(ws.Server.URL + "/oauth/callback")
	if err != nil {
		t.Fatalf("GET /oauth/callback: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 for disabled OIDC callback, got %d", resp.StatusCode)
	}

	// GET /web/api/config -> oidcEnabled = false
	resp = doJSON(t, client, http.MethodGet, ws.Server.URL+"/web/api/config", nil, nil)
	var body struct {
		OIDCEnabled bool `json:"oidcEnabled"`
	}
	decodeBodyW(t, resp, &body)
	if body.OIDCEnabled {
		t.Error("expected oidcEnabled to be false when browser flow is disabled")
	}
}

func TestOIDCWeb_LoginRedirect(t *testing.T) {
	cfg := defaultTestConfig()
	ctx := context.Background()

	var currentPayload oidcWebJWTPayload
	idp := newOIDCWebFakeIdP(t, func() oidcWebJWTPayload {
		return currentPayload
	})

	st, err := sqlitestore.New(":memory:")
	if err != nil {
		t.Fatalf("failed to init SQLite: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migration failed: %v", err)
	}

	prov := &oidcWebProvisioner{store: st}
	browserFlow, err := auth.NewOIDCBrowserFlow(ctx, idp.issuerURL, "test-client-id", "secret", "http://test.example.com/oauth/callback", st, false, prov)
	if err != nil {
		t.Fatalf("NewOIDCBrowserFlow: %v", err)
	}

	ws, client := newOidcWebTestStack(t, cfg, st, browserFlow)

	// GET /oauth/login
	resp, err := client.Get(ws.Server.URL + "/oauth/login")
	if err != nil {
		t.Fatalf("GET /oauth/login: %v", err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}

	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "/auth?") || !strings.Contains(loc, "code_challenge=") {
		t.Errorf("unexpected redirect Location: %q", loc)
	}

	cookies := resp.Cookies()
	var hasState, hasVerifier bool
	for _, c := range cookies {
		if c.Name == "oidc_state" {
			hasState = true
			if c.Value == "" || c.HttpOnly != true || c.MaxAge != 600 {
				t.Errorf("malformed oidc_state cookie: %+v", c)
			}
		}
		if c.Name == "oidc_verifier" {
			hasVerifier = true
			if c.Value == "" || c.HttpOnly != true || c.MaxAge != 600 {
				t.Errorf("malformed oidc_verifier cookie: %+v", c)
			}
		}
	}
	if !hasState || !hasVerifier {
		t.Errorf("missing oidc state or verifier cookies: %+v", cookies)
	}
}

func TestOIDCWeb_Callback(t *testing.T) {
	cfg := defaultTestConfig()
	ctx := context.Background()

	var currentPayload oidcWebJWTPayload
	idp := newOIDCWebFakeIdP(t, func() oidcWebJWTPayload {
		return currentPayload
	})

	st, err := sqlitestore.New(":memory:")
	if err != nil {
		t.Fatalf("failed to init SQLite: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migration failed: %v", err)
	}

	prov := &oidcWebProvisioner{store: st}
	browserFlow, err := auth.NewOIDCBrowserFlow(ctx, idp.issuerURL, "test-client-id", "secret", "http://test.example.com/oauth/callback", st, false, prov)
	if err != nil {
		t.Fatalf("NewOIDCBrowserFlow: %v", err)
	}

	ws, client := newOidcWebTestStack(t, cfg, st, browserFlow)

	t.Run("state mismatch", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, ws.Server.URL+"/oauth/callback?state=wrong-state&code=any-code", nil)
		req.AddCookie(&http.Cookie{Name: "oidc_state", Value: "real-state"})
		req.AddCookie(&http.Cookie{Name: "oidc_verifier", Value: "real-verifier"})

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("expected 400 for state mismatch, got %d", resp.StatusCode)
		}
	})

	t.Run("valid callback flow", func(t *testing.T) {
		email := "testuser@example.com"
		u := &store.User{
			ID:      "user-123",
			Email:   email,
			Blocked: false,
		}
		if err := ws.Store.CreateUser(ctx, u); err != nil {
			t.Fatalf("failed to create user: %v", err)
		}

		verified := true
		currentPayload = oidcWebJWTPayload{
			Iss:           idp.issuerURL,
			Aud:           "test-client-id",
			Sub:           "sub-test",
			Email:         email,
			EmailVerified: &verified,
			Exp:           time.Now().Add(1 * time.Hour).Unix(),
			Iat:           time.Now().Unix(),
		}

		req, _ := http.NewRequest(http.MethodGet, ws.Server.URL+"/oauth/callback?state=real-state&code=valid-code", nil)
		req.AddCookie(&http.Cookie{Name: "oidc_state", Value: "real-state"})
		req.AddCookie(&http.Cookie{Name: "oidc_verifier", Value: "real-verifier"})

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("expected 302, got %d", resp.StatusCode)
		}

		loc := resp.Header.Get("Location")
		if loc != "/players" {
			t.Errorf("expected redirect to /players, got %q", loc)
		}

		cookies := resp.Cookies()
		var hasSessionCookie bool
		for _, c := range cookies {
			if c.Name == "minecrauth_session" {
				hasSessionCookie = true
				if c.Value == "" || c.HttpOnly != true {
					t.Errorf("malformed session cookie: %+v", c)
				}
			}
		}
		if !hasSessionCookie {
			t.Errorf("missing minecrauth_session cookie in response cookies: %+v", cookies)
		}
	})
}
