package auth_test

// oidc_test.go contains canary tests for OIDCAuthenticator and CompositeAuthenticator.
//
// Fake IdP design:
//   - A net.Listener is allocated first so the URL is known before handler registration.
//   - The httptest server is started on that listener.
//   - Handlers serve /.well-known/openid-configuration (discovery) and /keys (JWKS).
//   - Tokens are minted in-process with crypto/rsa + crypto/sha256 (RS256).
//   - The real go-oidc library verifies minted tokens, exercising the full
//     discovery → JWKS-fetch → signature-verify path in production code.
//
// The production code always uses go-oidc for verification; only the test minting
// is implemented by hand, which is explicitly permitted.

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/achetronic/minecrauth/internal/auth"
	"github.com/achetronic/minecrauth/internal/store"
)

// ---------------------------------------------------------------------------
// JWT minting helpers (test-only; production code never mints JWTs).
// ---------------------------------------------------------------------------

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

type jwtPayload struct {
	Iss           string `json:"iss"`
	Aud           string `json:"aud"`
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified *bool  `json:"email_verified,omitempty"`
	Exp           int64  `json:"exp"`
	Iat           int64  `json:"iat"`
}

// mintRS256JWT produces a signed RS256 JWT. Only used for test token generation.
func mintRS256JWT(t *testing.T, key *rsa.PrivateKey, kid string, payload jwtPayload) string {
	t.Helper()

	hdrBytes, err := json.Marshal(jwtHeader{Alg: "RS256", Kid: kid, Typ: "JWT"})
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

// ---------------------------------------------------------------------------
// JWKS helpers (test-only; production uses go-oidc JWKS client).
// ---------------------------------------------------------------------------

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwkSet struct {
	Keys []jwkKey `json:"keys"`
}

func rsaPublicKeyToJWK(pub *rsa.PublicKey, kid string) jwkKey {
	nBytes := pub.N.Bytes()
	eBytes := new(big.Int).SetInt64(int64(pub.E)).Bytes()
	return jwkKey{
		Kty: "RSA",
		Kid: kid,
		Use: "sig",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(nBytes),
		E:   base64.RawURLEncoding.EncodeToString(eBytes),
	}
}

// ---------------------------------------------------------------------------
// Fake IdP
// ---------------------------------------------------------------------------

// fakeIdP is a minimal in-process OIDC provider backed by an httptest server.
type fakeIdP struct {
	server    *httptest.Server
	key       *rsa.PrivateKey
	kid       string
	issuerURL string // pre-computed; equals server.URL
}

// newFakeIdP starts a fake OIDC IdP and registers cleanup.
//
// We pre-allocate a TCP listener before registering HTTP handlers so that
// issuerURL is known at handler-registration time (a local immutable string
// captured by the closure). This avoids any data-race between the server
// goroutine reading the URL and the main goroutine writing it.
func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	// Grab a port before starting so issuerURL is known before closures are built.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	issuerURL := "http://" + ln.Addr().String()
	kid := "test-key-1"

	mux := http.NewServeMux()

	// OIDC Discovery document.
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
		if encErr := json.NewEncoder(w).Encode(doc); encErr != nil {
			http.Error(w, encErr.Error(), http.StatusInternalServerError)
		}
	})

	// JWKS – serves the public key for the fake signing key.
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		ks := jwkSet{Keys: []jwkKey{rsaPublicKeyToJWK(&key.PublicKey, kid)}}
		if encErr := json.NewEncoder(w).Encode(ks); encErr != nil {
			http.Error(w, encErr.Error(), http.StatusInternalServerError)
		}
	})

	srv := httptest.NewUnstartedServer(mux)
	srv.Listener = ln
	srv.Start()

	idp := &fakeIdP{
		server:    srv,
		key:       key,
		kid:       kid,
		issuerURL: issuerURL,
	}
	t.Cleanup(func() { srv.Close() })
	return idp
}

// issuer returns the base URL of the fake IdP (used as the OIDC issuer).
func (idp *fakeIdP) issuer() string { return idp.issuerURL }

// mint creates a valid RS256 ID token signed by the fake IdP's key.
func (idp *fakeIdP) mint(
	t *testing.T,
	issuer, aud, sub, email string,
	emailVerified *bool,
	exp time.Time,
) string {
	t.Helper()
	return mintRS256JWT(t, idp.key, idp.kid, jwtPayload{
		Iss:           issuer,
		Aud:           aud,
		Sub:           sub,
		Email:         email,
		EmailVerified: emailVerified,
		Exp:           exp.Unix(),
		Iat:           time.Now().Add(-5 * time.Second).Unix(),
	})
}

// ---------------------------------------------------------------------------
// Shared mock types
// ---------------------------------------------------------------------------

// mockProvisioner implements auth.Provisioner for tests.
type mockProvisioner struct {
	fn func(ctx context.Context, email string) (*store.User, error)
}

func (m *mockProvisioner) CreateProvisionedUser(ctx context.Context, email string) (*store.User, error) {
	return m.fn(ctx, email)
}

// mockAuthenticator implements auth.Authenticator for composite tests.
type mockAuthenticator struct {
	user *store.User
	err  error
}

func (m *mockAuthenticator) Authenticate(_ context.Context, _, _ string) (*store.User, error) {
	return m.user, m.err
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newOIDCAuthn creates an OIDCAuthenticator pointed at the given fake IdP.
func newOIDCAuthn(
	t *testing.T,
	idp *fakeIdP,
	clientID string,
	st store.Store,
	autoProvision bool,
	prov auth.Provisioner,
) *auth.OIDCAuthenticator {
	t.Helper()
	a, err := auth.NewOIDCAuthenticator(context.Background(), idp.issuer(), clientID, st, autoProvision, prov)
	if err != nil {
		t.Fatalf("NewOIDCAuthenticator: %v", err)
	}
	return a
}

// boolPtr is a tiny helper to take the address of a bool literal.
func boolPtr(b bool) *bool { return &b }

// ---------------------------------------------------------------------------
// OIDCAuthenticator canary tests
// ---------------------------------------------------------------------------

// TestOIDCAuthenticator_ValidToken_ReturnsUser is the happy-path canary:
// a valid, correctly-signed ID token with email_verified=true returns the
// pre-seeded local user.
func TestOIDCAuthenticator_ValidToken_ReturnsUser(t *testing.T) {
	const (
		clientID = "test-client"
		email    = "user@example.com"
	)
	st := newTestStore(t)
	idp := newFakeIdP(t)
	seedUser(t, st, "u-oidc-happy", email, "unused-hash")

	a := newOIDCAuthn(t, idp, clientID, st, false, nil)

	token := idp.mint(t, idp.issuer(), clientID, "sub-happy", email, boolPtr(true), time.Now().Add(time.Hour))

	u, err := a.Authenticate(context.Background(), email, token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if u.ID != "u-oidc-happy" {
		t.Errorf("wrong user ID: got %q, want %q", u.ID, "u-oidc-happy")
	}
}

// TestOIDCAuthenticator_WrongAud_ReturnsErrInvalidCredentials verifies that a
// token whose audience does not match the configured clientID is rejected.
func TestOIDCAuthenticator_WrongAud_ReturnsErrInvalidCredentials(t *testing.T) {
	const (
		clientID = "test-client"
		email    = "user@example.com"
	)
	st := newTestStore(t)
	idp := newFakeIdP(t)
	seedUser(t, st, "u-oidc-aud", email, "unused-hash")

	a := newOIDCAuthn(t, idp, clientID, st, false, nil)

	// Mint with wrong audience.
	token := idp.mint(t, idp.issuer(), "wrong-client", "sub-aud", email, boolPtr(true), time.Now().Add(time.Hour))

	_, err := a.Authenticate(context.Background(), email, token)
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials for wrong aud, got %v", err)
	}
}

// TestOIDCAuthenticator_ExpiredToken_ReturnsErrInvalidCredentials verifies that
// a token whose exp is in the past is rejected.
func TestOIDCAuthenticator_ExpiredToken_ReturnsErrInvalidCredentials(t *testing.T) {
	const (
		clientID = "test-client"
		email    = "user@example.com"
	)
	st := newTestStore(t)
	idp := newFakeIdP(t)
	seedUser(t, st, "u-oidc-exp", email, "unused-hash")

	a := newOIDCAuthn(t, idp, clientID, st, false, nil)

	// Mint with expiry in the past.
	token := idp.mint(t, idp.issuer(), clientID, "sub-exp", email, boolPtr(true), time.Now().Add(-time.Hour))

	_, err := a.Authenticate(context.Background(), email, token)
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials for expired token, got %v", err)
	}
}

// TestOIDCAuthenticator_WrongSigningKey_ReturnsErrInvalidCredentials verifies that
// a token signed by a key OTHER THAN the one published in the JWKS is rejected.
// The fake JWKS serves key A; this test signs the token with key B but claims
// kid="test-key-1" so go-oidc looks up key A and fails signature verification.
func TestOIDCAuthenticator_WrongSigningKey_ReturnsErrInvalidCredentials(t *testing.T) {
	const (
		clientID = "test-client"
		email    = "user@example.com"
	)
	st := newTestStore(t)
	idp := newFakeIdP(t)
	seedUser(t, st, "u-oidc-badkey", email, "unused-hash")

	a := newOIDCAuthn(t, idp, clientID, st, false, nil)

	// Generate a different key; use the same kid so go-oidc looks up the JWKS key.
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey for wrong key: %v", err)
	}

	token := mintRS256JWT(t, wrongKey, idp.kid, jwtPayload{
		Iss:           idp.issuer(),
		Aud:           clientID,
		Sub:           "sub-badkey",
		Email:         email,
		EmailVerified: boolPtr(true),
		Exp:           time.Now().Add(time.Hour).Unix(),
		Iat:           time.Now().Add(-5 * time.Second).Unix(),
	})

	_, err = a.Authenticate(context.Background(), email, token)
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials for wrong signing key, got %v", err)
	}
}

// TestOIDCAuthenticator_EmailMismatch_ReturnsErrInvalidCredentials verifies that
// when the token's email claim does not match the email the caller presented,
// authentication is rejected.
func TestOIDCAuthenticator_EmailMismatch_ReturnsErrInvalidCredentials(t *testing.T) {
	const (
		clientID    = "test-client"
		tokenEmail  = "token@example.com"
		callerEmail = "caller@example.com"
	)
	st := newTestStore(t)
	idp := newFakeIdP(t)
	seedUser(t, st, "u-oidc-mismatch", callerEmail, "unused-hash")

	a := newOIDCAuthn(t, idp, clientID, st, false, nil)

	// Token says tokenEmail; caller presents callerEmail.
	token := idp.mint(t, idp.issuer(), clientID, "sub-mismatch", tokenEmail, boolPtr(true), time.Now().Add(time.Hour))

	_, err := a.Authenticate(context.Background(), callerEmail, token)
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials for email mismatch, got %v", err)
	}
}

// TestOIDCAuthenticator_EmailVerifiedFalse_ReturnsErrInvalidCredentials verifies
// that tokens with email_verified=false are rejected regardless of signature validity.
func TestOIDCAuthenticator_EmailVerifiedFalse_ReturnsErrInvalidCredentials(t *testing.T) {
	const (
		clientID = "test-client"
		email    = "user@example.com"
	)
	st := newTestStore(t)
	idp := newFakeIdP(t)
	seedUser(t, st, "u-oidc-unverified", email, "unused-hash")

	a := newOIDCAuthn(t, idp, clientID, st, false, nil)

	token := idp.mint(t, idp.issuer(), clientID, "sub-unverified", email, boolPtr(false), time.Now().Add(time.Hour))

	_, err := a.Authenticate(context.Background(), email, token)
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials for email_verified=false, got %v", err)
	}
}

// TestOIDCAuthenticator_AutoProvision_CreatesNonAdminUser verifies that when
// autoProvision=true and the authenticated email is not yet known locally, the
// provisioner is called and the returned user is non-admin.
func TestOIDCAuthenticator_AutoProvision_CreatesNonAdminUser(t *testing.T) {
	const (
		clientID = "test-client"
		email    = "newbie@example.com"
	)
	st := newTestStore(t)
	idp := newFakeIdP(t)
	// Do NOT seed the user — they must be auto-provisioned.

	var provisionCalled bool
	prov := &mockProvisioner{
		fn: func(ctx context.Context, e string) (*store.User, error) {
			provisionCalled = true
			if e != email {
				return nil, fmt.Errorf("unexpected email in provisioner: got %q, want %q", e, email)
			}
			u := &store.User{
				ID:        "u-provisioned",
				Email:     e,
				IsAdmin:   false, // MUST be non-admin per spec
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}
			if storeErr := st.CreateUser(ctx, u); storeErr != nil {
				return nil, storeErr
			}
			return u, nil
		},
	}

	a := newOIDCAuthn(t, idp, clientID, st, true /* autoProvision */, prov)

	token := idp.mint(t, idp.issuer(), clientID, "sub-prov", email, boolPtr(true), time.Now().Add(time.Hour))

	u, err := a.Authenticate(context.Background(), email, token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !provisionCalled {
		t.Error("expected provisioner to be called for unknown email")
	}
	if u == nil {
		t.Fatal("expected non-nil user from auto-provisioning")
	}
	if u.IsAdmin {
		t.Error("auto-provisioned user must not have admin privileges")
	}
	if u.ID != "u-provisioned" {
		t.Errorf("wrong user ID: got %q, want %q", u.ID, "u-provisioned")
	}
}

// TestOIDCAuthenticator_NoAutoProvision_UnknownUser_ReturnsErrInvalidCredentials
// verifies that when autoProvision=false and the user is not in the local store,
// authentication returns ErrInvalidCredentials (not a real error).
func TestOIDCAuthenticator_NoAutoProvision_UnknownUser_ReturnsErrInvalidCredentials(t *testing.T) {
	const (
		clientID = "test-client"
		email    = "nobody@example.com"
	)
	st := newTestStore(t)
	idp := newFakeIdP(t)
	// No user seeded; autoProvision=false.

	a := newOIDCAuthn(t, idp, clientID, st, false /* autoProvision */, nil)

	token := idp.mint(t, idp.issuer(), clientID, "sub-nobody", email, boolPtr(true), time.Now().Add(time.Hour))

	_, err := a.Authenticate(context.Background(), email, token)
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials for unknown user without auto-provision, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// CompositeAuthenticator tests
// ---------------------------------------------------------------------------

// TestCompositeAuthenticator_FirstFailing_SecondSucceeding_ReturnsSuccess
// verifies that when the first authenticator returns ErrInvalidCredentials,
// the composite falls through to the second and returns its success.
func TestCompositeAuthenticator_FirstFailing_SecondSucceeding_ReturnsSuccess(t *testing.T) {
	want := &store.User{ID: "u-comp-success", Email: "c@example.com"}

	failing := &mockAuthenticator{err: auth.ErrInvalidCredentials}
	succeeding := &mockAuthenticator{user: want}

	c := auth.NewCompositeAuthenticator(failing, succeeding)

	u, err := c.Authenticate(context.Background(), "c@example.com", "token")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if u != want {
		t.Errorf("wrong user pointer: got %v, want %v", u, want)
	}
}

// TestCompositeAuthenticator_AllFailing_ReturnsErrInvalidCredentials verifies
// that when every authenticator returns ErrInvalidCredentials, the composite
// returns ErrInvalidCredentials (not a nil or wrapped error).
func TestCompositeAuthenticator_AllFailing_ReturnsErrInvalidCredentials(t *testing.T) {
	a1 := &mockAuthenticator{err: auth.ErrInvalidCredentials}
	a2 := &mockAuthenticator{err: auth.ErrInvalidCredentials}

	c := auth.NewCompositeAuthenticator(a1, a2)

	_, err := c.Authenticate(context.Background(), "x@example.com", "any")
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials when all fail, got %v", err)
	}
}

// TestCompositeAuthenticator_RealError_ShortCircuits verifies that when an
// authenticator returns a real (non-ErrInvalidCredentials) error, the composite
// short-circuits immediately without trying subsequent authenticators, and the
// original error is preserved in the chain.
func TestCompositeAuthenticator_RealError_ShortCircuits(t *testing.T) {
	realErr := errors.New("database unreachable")

	a1 := &mockAuthenticator{err: realErr}
	a2 := &mockAuthenticator{user: &store.User{ID: "should-not-reach"}}

	c := auth.NewCompositeAuthenticator(a1, a2)

	_, err := c.Authenticate(context.Background(), "x@example.com", "any")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if errors.Is(err, auth.ErrInvalidCredentials) {
		t.Error("real error must not be mapped to ErrInvalidCredentials")
	}
	if !errors.Is(err, realErr) {
		t.Errorf("realErr must be preserved in the error chain; got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Compile-time interface canaries
// ---------------------------------------------------------------------------

func TestOIDCAuthenticator_ImplementsAuthenticator(t *testing.T) {
	var _ auth.Authenticator = (*auth.OIDCAuthenticator)(nil)
}

func TestCompositeAuthenticator_ImplementsAuthenticator(t *testing.T) {
	var _ auth.Authenticator = (*auth.CompositeAuthenticator)(nil)
}
