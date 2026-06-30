// Copyright 2025 - Alby Hernández and the minecrauth contributors
// SPDX-License-Identifier: Apache-2.0

package auth_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/achetronic/minecrauth/internal/auth"
	"github.com/achetronic/minecrauth/internal/store"
	sqlitestore "github.com/achetronic/minecrauth/internal/store/sqlite"
)

type testJWTHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

type testJWTPayload struct {
	Iss           string `json:"iss"`
	Aud           string `json:"aud"`
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified *bool  `json:"email_verified,omitempty"`
	Exp           int64  `json:"exp"`
	Iat           int64  `json:"iat"`
}

func testMintRS256JWT(t *testing.T, key *rsa.PrivateKey, kid string, payload testJWTPayload) string {
	t.Helper()

	hdrBytes, err := json.Marshal(testJWTHeader{Alg: "RS256", Kid: kid, Typ: "JWT"})
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

type testJWKKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type testJWKSet struct {
	Keys []testJWKKey `json:"keys"`
}

func testRsaPublicKeyToJWK(pub *rsa.PublicKey, kid string) testJWKKey {
	nBytes := pub.N.Bytes()
	eBytes := new(big.Int).SetInt64(int64(pub.E)).Bytes()
	return testJWKKey{
		Kty: "RSA",
		Kid: kid,
		Use: "sig",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(nBytes),
		E:   base64.RawURLEncoding.EncodeToString(eBytes),
	}
}

type browserFakeIdP struct {
	server     *httptest.Server
	key        *rsa.PrivateKey
	kid        string
	issuerURL  string
	getPayload func() testJWTPayload
}

func newBrowserFakeIdP(t *testing.T, getPayload func() testJWTPayload) *browserFakeIdP {
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
	kid := "test-key-browser-1"

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
		ks := testJWKSet{Keys: []testJWKKey{testRsaPublicKeyToJWK(&key.PublicKey, kid)}}
		_ = json.NewEncoder(w).Encode(ks)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		idTok := testMintRS256JWT(t, key, kid, getPayload())
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

	idp := &browserFakeIdP{
		server:     srv,
		key:        key,
		kid:        kid,
		issuerURL:  issuerURL,
		getPayload: getPayload,
	}
	t.Cleanup(func() { srv.Close() })
	return idp
}

type provisionerStub struct {
	store store.Store
}

func (p *provisionerStub) CreateProvisionedUser(ctx context.Context, email string) (*store.User, error) {
	u := &store.User{
		ID:      "provisioned-user-id",
		Email:   email,
		IsAdmin: false,
		Blocked: false,
	}
	if err := p.store.CreateUser(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

func TestOIDCBrowserFlow(t *testing.T) {
	ctx := context.Background()
	clientID := "test-client-id"

	var currentPayload testJWTPayload

	idp := newBrowserFakeIdP(t, func() testJWTPayload {
		return currentPayload
	})

	dbFile := filepath.Join(t.TempDir(), "test_oidc_browser.db")
	st, err := sqlitestore.New(dbFile)
	if err != nil {
		t.Fatalf("failed to init SQLite: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migration failed: %v", err)
	}

	prov := &provisionerStub{store: st}

	t.Run("valid exchange with a pre-created local user", func(t *testing.T) {
		email := "local@example.com"
		uPre := &store.User{
			ID:      "local-id-1",
			Email:   email,
			Blocked: false,
		}
		if err := st.CreateUser(ctx, uPre); err != nil {
			t.Fatalf("failed to create pre-existing user: %v", err)
		}

		verified := true
		currentPayload = testJWTPayload{
			Iss:           idp.issuerURL,
			Aud:           clientID,
			Sub:           "sub-1",
			Email:         email,
			EmailVerified: &verified,
			Exp:           time.Now().Add(1 * time.Hour).Unix(),
			Iat:           time.Now().Unix(),
		}

		flow, err := auth.NewOIDCBrowserFlow(ctx, idp.issuerURL, clientID, "secret", "http://app/oauth/callback", st, false, prov)
		if err != nil {
			t.Fatalf("failed to build browser flow: %v", err)
		}

		user, err := flow.Exchange(ctx, "any-code", "any-verifier")
		if err != nil {
			t.Fatalf("unexpected exchange error: %v", err)
		}
		if user.ID != "local-id-1" {
			t.Errorf("expected user ID 'local-id-1', got %q", user.ID)
		}
	})

	t.Run("email_verified=false", func(t *testing.T) {
		email := "unverified@example.com"
		verified := false
		currentPayload = testJWTPayload{
			Iss:           idp.issuerURL,
			Aud:           clientID,
			Sub:           "sub-2",
			Email:         email,
			EmailVerified: &verified,
			Exp:           time.Now().Add(1 * time.Hour).Unix(),
			Iat:           time.Now().Unix(),
		}

		flow, err := auth.NewOIDCBrowserFlow(ctx, idp.issuerURL, clientID, "secret", "http://app/oauth/callback", st, false, prov)
		if err != nil {
			t.Fatalf("failed to build browser flow: %v", err)
		}

		_, err = flow.Exchange(ctx, "any-code", "any-verifier")
		if !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Errorf("expected ErrInvalidCredentials, got %v", err)
		}
	})

	t.Run("unknown email, autoProvision=false", func(t *testing.T) {
		email := "unknown-no-provision@example.com"
		verified := true
		currentPayload = testJWTPayload{
			Iss:           idp.issuerURL,
			Aud:           clientID,
			Sub:           "sub-3",
			Email:         email,
			EmailVerified: &verified,
			Exp:           time.Now().Add(1 * time.Hour).Unix(),
			Iat:           time.Now().Unix(),
		}

		flow, err := auth.NewOIDCBrowserFlow(ctx, idp.issuerURL, clientID, "secret", "http://app/oauth/callback", st, false, prov)
		if err != nil {
			t.Fatalf("failed to build browser flow: %v", err)
		}

		_, err = flow.Exchange(ctx, "any-code", "any-verifier")
		if !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Errorf("expected ErrInvalidCredentials, got %v", err)
		}
	})

	t.Run("unknown email, autoProvision=true", func(t *testing.T) {
		email := "unknown-with-provision@example.com"
		verified := true
		currentPayload = testJWTPayload{
			Iss:           idp.issuerURL,
			Aud:           clientID,
			Sub:           "sub-4",
			Email:         email,
			EmailVerified: &verified,
			Exp:           time.Now().Add(1 * time.Hour).Unix(),
			Iat:           time.Now().Unix(),
		}

		flow, err := auth.NewOIDCBrowserFlow(ctx, idp.issuerURL, clientID, "secret", "http://app/oauth/callback", st, true, prov)
		if err != nil {
			t.Fatalf("failed to build browser flow: %v", err)
		}

		user, err := flow.Exchange(ctx, "any-code", "any-verifier")
		if err != nil {
			t.Fatalf("unexpected exchange error: %v", err)
		}
		if user.ID != "provisioned-user-id" {
			t.Errorf("expected provisioned user ID, got %q", user.ID)
		}
		if user.Email != email {
			t.Errorf("expected email %q, got %q", email, user.Email)
		}
	})

	t.Run("a blocked user", func(t *testing.T) {
		email := "blocked@example.com"
		uPre := &store.User{
			ID:      "blocked-id-1",
			Email:   email,
			Blocked: true,
		}
		if err := st.CreateUser(ctx, uPre); err != nil {
			t.Fatalf("failed to create blocked user: %v", err)
		}

		verified := true
		currentPayload = testJWTPayload{
			Iss:           idp.issuerURL,
			Aud:           clientID,
			Sub:           "sub-5",
			Email:         email,
			EmailVerified: &verified,
			Exp:           time.Now().Add(1 * time.Hour).Unix(),
			Iat:           time.Now().Unix(),
		}

		flow, err := auth.NewOIDCBrowserFlow(ctx, idp.issuerURL, clientID, "secret", "http://app/oauth/callback", st, false, prov)
		if err != nil {
			t.Fatalf("failed to build browser flow: %v", err)
		}

		_, err = flow.Exchange(ctx, "any-code", "any-verifier")
		if !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Errorf("expected ErrInvalidCredentials, got %v", err)
		}
	})

	t.Run("wrong audience id_token", func(t *testing.T) {
		email := "wrong-aud@example.com"
		verified := true
		currentPayload = testJWTPayload{
			Iss:           idp.issuerURL,
			Aud:           "wrong-audience-id",
			Sub:           "sub-6",
			Email:         email,
			EmailVerified: &verified,
			Exp:           time.Now().Add(1 * time.Hour).Unix(),
			Iat:           time.Now().Unix(),
		}

		flow, err := auth.NewOIDCBrowserFlow(ctx, idp.issuerURL, clientID, "secret", "http://app/oauth/callback", st, false, prov)
		if err != nil {
			t.Fatalf("failed to build browser flow: %v", err)
		}

		_, err = flow.Exchange(ctx, "any-code", "any-verifier")
		if err == nil {
			t.Error("expected exchange error for wrong audience, got nil")
		}
	})

	t.Run("GeneratePKCE", func(t *testing.T) {
		verifier, challenge, err := auth.GeneratePKCE()
		if err != nil {
			t.Fatalf("GeneratePKCE failed: %v", err)
		}
		if verifier == "" || challenge == "" {
			t.Errorf("verifier or challenge is empty")
		}
		h := sha256.Sum256([]byte(verifier))
		expectedChallenge := base64.RawURLEncoding.EncodeToString(h[:])
		if challenge != expectedChallenge {
			t.Errorf("challenge mismatch: got %q, want %q", challenge, expectedChallenge)
		}
	})

	t.Run("GenerateState", func(t *testing.T) {
		s1, err1 := auth.GenerateState()
		s2, err2 := auth.GenerateState()
		if err1 != nil || err2 != nil {
			t.Fatalf("GenerateState failed: %v %v", err1, err2)
		}
		if s1 == "" || s2 == "" {
			t.Errorf("empty state generated")
		}
		if s1 == s2 {
			t.Errorf("two consecutive states must differ, both were %q", s1)
		}
	})
}
