package auth_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/achetronic/minecrauth/internal/auth"
	"github.com/achetronic/minecrauth/internal/store"
	"github.com/achetronic/minecrauth/internal/store/sqlite"
)

// newTestStore opens a fresh SQLite database under t.TempDir and runs all migrations.
// The store is closed automatically when the test finishes.
func newTestStore(t *testing.T) store.Store {
	t.Helper()
	st, err := sqlite.New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("creating test store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("migrating test store: %v", err)
	}
	return st
}

// seedUser inserts a minimal User into st so foreign-key constraints on tokens are satisfied.
func seedUser(t *testing.T, st store.Store, id, email, passwordHash string) *store.User {
	t.Helper()
	u := &store.User{
		ID:                id,
		Email:             email,
		PasswordHash:      passwordHash,
		PreferredLanguage: "en",
		EmailVerified:     true,
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}
	if err := st.CreateUser(context.Background(), u); err != nil {
		t.Fatalf("seeding user %q: %v", id, err)
	}
	return u
}

// seedPlayer inserts a Player owned by userID so foreign-key constraints on tokens that
// carry a playerID are satisfied.
func seedPlayer(t *testing.T, st store.Store, playerID, userID, name, uuid string) *store.Player {
	t.Helper()
	p := &store.Player{
		ID:        playerID,
		UserID:    userID,
		Name:      name,
		UUID:      uuid,
		CreatedAt: time.Now(),
	}
	if err := st.CreatePlayer(context.Background(), p); err != nil {
		t.Fatalf("seeding player %q: %v", playerID, err)
	}
	return p
}

// TestTokenService_IssueAndValidate verifies that a freshly issued token is immediately
// valid with the matching clientToken and also with an empty clientToken (optional).
func TestTokenService_IssueAndValidate(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	seedUser(t, st, "u1", "u1@example.com", "hash")

	svc := auth.NewTokenService(st, time.Hour, nil)
	tok, err := svc.Issue(ctx, "u1", nil, "client-abc")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if tok.AccessToken == "" {
		t.Fatal("AccessToken must not be empty")
	}
	if tok.ClientToken != "client-abc" {
		t.Fatalf("ClientToken: got %q, want %q", tok.ClientToken, "client-abc")
	}

	// Matching clientToken must succeed.
	if err := svc.Validate(ctx, tok.AccessToken, "client-abc"); err != nil {
		t.Fatalf("Validate with matching clientToken: %v", err)
	}

	// Empty clientToken is optional and must also succeed.
	if err := svc.Validate(ctx, tok.AccessToken, ""); err != nil {
		t.Fatalf("Validate with empty clientToken: %v", err)
	}
}

// TestTokenService_ValidateWrongClientToken verifies that providing a mismatched
// clientToken yields ErrTokenInvalid, not a success or a different error.
func TestTokenService_ValidateWrongClientToken(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	seedUser(t, st, "u2", "u2@example.com", "hash")

	svc := auth.NewTokenService(st, time.Hour, nil)
	tok, err := svc.Issue(ctx, "u2", nil, "correct-client")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	err = svc.Validate(ctx, tok.AccessToken, "wrong-client")
	if !errors.Is(err, auth.ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid for wrong clientToken, got %v", err)
	}
}

// TestTokenService_ValidateUnknownToken verifies that looking up a token that was never
// issued returns ErrTokenInvalid, not a nil error or a store error.
func TestTokenService_ValidateUnknownToken(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	svc := auth.NewTokenService(st, time.Hour, nil)

	err := svc.Validate(ctx, "not-a-real-token", "")
	if !errors.Is(err, auth.ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid for unknown token, got %v", err)
	}
}

// TestTokenService_ValidateExpired verifies that a token is valid before its TTL
// elapses and returns ErrTokenExpired after the injected clock advances past ExpiresAt.
func TestTokenService_ValidateExpired(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	seedUser(t, st, "u-exp", "exp@example.com", "hash")

	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	ttl := 10 * time.Second

	svc := auth.NewTokenService(st, ttl, clock)
	tok, err := svc.Issue(ctx, "u-exp", nil, "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Token must be valid before the TTL elapses.
	if err := svc.Validate(ctx, tok.AccessToken, ""); err != nil {
		t.Fatalf("Validate before expiry: %v", err)
	}

	// Advance the clock past expiry; the closure captures now by reference.
	now = now.Add(ttl + time.Second)

	err = svc.Validate(ctx, tok.AccessToken, "")
	if !errors.Is(err, auth.ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired after TTL elapsed, got %v", err)
	}
}

// TestTokenService_NeverExpires verifies that a token issued with TTL=0 has a nil
// ExpiresAt and remains valid no matter how far the clock advances.
func TestTokenService_NeverExpires(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	seedUser(t, st, "u-noexp", "noexp@example.com", "hash")

	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	svc := auth.NewTokenService(st, 0, clock) // TTL=0 means never expire

	tok, err := svc.Issue(ctx, "u-noexp", nil, "cx")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if tok.ExpiresAt != nil {
		t.Fatalf("ExpiresAt must be nil when TTL=0, got %v", tok.ExpiresAt)
	}

	// Advance the clock by a large amount; the token must still be valid.
	now = now.Add(365 * 24 * time.Hour)

	if err := svc.Validate(ctx, tok.AccessToken, "cx"); err != nil {
		t.Fatalf("expected token to never expire, got: %v", err)
	}
}

// TestTokenService_GeneratesClientToken verifies that when no clientToken is supplied,
// Issue generates a non-empty one automatically.
func TestTokenService_GeneratesClientToken(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	seedUser(t, st, "u-ct", "ct@example.com", "hash")

	svc := auth.NewTokenService(st, time.Hour, nil)
	tok, err := svc.Issue(ctx, "u-ct", nil, "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if tok.ClientToken == "" {
		t.Fatal("ClientToken must be generated when none is provided")
	}
}

// TestTokenService_Refresh verifies that Refresh rotates the access token while
// preserving clientToken, userID, and playerID, and that the old token is no
// longer accepted.
func TestTokenService_Refresh(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	seedUser(t, st, "u-ref", "ref@example.com", "hash")
	player := seedPlayer(t, st, "p-ref", "u-ref", "RefPlayer", "uuid-ref-1")
	playerID := player.ID

	svc := auth.NewTokenService(st, time.Hour, nil)
	tok, err := svc.Issue(ctx, "u-ref", &playerID, "ref-client")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	newTok, err := svc.Refresh(ctx, tok.AccessToken, "ref-client", nil)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	// New token must differ from the old one.
	if newTok.AccessToken == tok.AccessToken {
		t.Fatal("Refresh must produce a different access token")
	}

	// Old token must no longer be valid.
	if err := svc.Validate(ctx, tok.AccessToken, ""); err == nil {
		t.Fatal("old access token must be invalid after Refresh")
	}

	// New token must be valid.
	if err := svc.Validate(ctx, newTok.AccessToken, "ref-client"); err != nil {
		t.Fatalf("new token must be valid after Refresh: %v", err)
	}

	// clientToken must be preserved.
	if newTok.ClientToken != "ref-client" {
		t.Fatalf("ClientToken: got %q, want %q", newTok.ClientToken, "ref-client")
	}

	// userID must be preserved.
	if newTok.UserID != "u-ref" {
		t.Fatalf("UserID: got %q, want %q", newTok.UserID, "u-ref")
	}

	// playerID must be preserved.
	if newTok.PlayerID == nil || *newTok.PlayerID != playerID {
		t.Fatalf("PlayerID: got %v, want %q", newTok.PlayerID, playerID)
	}
}

// TestTokenService_RefreshExpiredToken verifies that attempting to refresh an expired
// token returns ErrTokenExpired rather than silently issuing a new token.
func TestTokenService_RefreshExpiredToken(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	seedUser(t, st, "u-rexp", "rexp@example.com", "hash")

	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	ttl := 5 * time.Second

	svc := auth.NewTokenService(st, ttl, clock)
	tok, err := svc.Issue(ctx, "u-rexp", nil, "rexp-client")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	now = now.Add(ttl + time.Second)

	_, err = svc.Refresh(ctx, tok.AccessToken, "rexp-client", nil)
	if !errors.Is(err, auth.ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired on Refresh of expired token, got %v", err)
	}
}

// TestTokenService_RefreshInvalidToken verifies that Refresh on a token that does not
// exist returns ErrTokenInvalid.
func TestTokenService_RefreshInvalidToken(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	svc := auth.NewTokenService(st, time.Hour, nil)

	_, err := svc.Refresh(ctx, "ghost-token", "", nil)
	if !errors.Is(err, auth.ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid for non-existent token, got %v", err)
	}
}

// TestTokenService_Invalidate verifies that Invalidate removes exactly the named token
// while leaving other tokens for the same user untouched.
func TestTokenService_Invalidate(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	seedUser(t, st, "u-inv", "inv@example.com", "hash")

	svc := auth.NewTokenService(st, time.Hour, nil)

	tokA, err := svc.Issue(ctx, "u-inv", nil, "client-a")
	if err != nil {
		t.Fatalf("Issue tokA: %v", err)
	}
	tokB, err := svc.Issue(ctx, "u-inv", nil, "client-b")
	if err != nil {
		t.Fatalf("Issue tokB: %v", err)
	}

	if err := svc.Invalidate(ctx, tokA.AccessToken, "client-a"); err != nil {
		t.Fatalf("Invalidate tokA: %v", err)
	}

	// tokA must be gone.
	if err := svc.Validate(ctx, tokA.AccessToken, ""); err == nil {
		t.Fatal("tokA must be invalid after Invalidate")
	}

	// tokB must be unaffected.
	if err := svc.Validate(ctx, tokB.AccessToken, "client-b"); err != nil {
		t.Fatalf("tokB must remain valid after invalidating tokA: %v", err)
	}
}

// TestTokenService_InvalidateWrongClientToken verifies that Invalidate refuses to
// delete a token when the provided clientToken does not match.
func TestTokenService_InvalidateWrongClientToken(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	seedUser(t, st, "u-invwct", "invwct@example.com", "hash")

	svc := auth.NewTokenService(st, time.Hour, nil)
	tok, err := svc.Issue(ctx, "u-invwct", nil, "real-client")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	err = svc.Invalidate(ctx, tok.AccessToken, "wrong-client")
	if !errors.Is(err, auth.ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid for mismatched clientToken, got %v", err)
	}

	// Token must remain valid because Invalidate was rejected.
	if err := svc.Validate(ctx, tok.AccessToken, "real-client"); err != nil {
		t.Fatalf("token must remain valid after failed Invalidate: %v", err)
	}
}

// TestTokenService_InvalidateAllByUser verifies that InvalidateAllByUser (signout) removes
// every token belonging to the target user without touching tokens of other users.
func TestTokenService_InvalidateAllByUser(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	seedUser(t, st, "u-signout", "signout@example.com", "hash")
	seedUser(t, st, "u-other", "other@example.com", "hash")

	svc := auth.NewTokenService(st, time.Hour, nil)

	tok1, err := svc.Issue(ctx, "u-signout", nil, "c1")
	if err != nil {
		t.Fatalf("Issue tok1: %v", err)
	}
	tok2, err := svc.Issue(ctx, "u-signout", nil, "c2")
	if err != nil {
		t.Fatalf("Issue tok2: %v", err)
	}
	tokOther, err := svc.Issue(ctx, "u-other", nil, "co")
	if err != nil {
		t.Fatalf("Issue tokOther: %v", err)
	}

	if err := svc.InvalidateAllByUser(ctx, "u-signout"); err != nil {
		t.Fatalf("InvalidateAllByUser: %v", err)
	}

	// All tokens for u-signout must be gone.
	if err := svc.Validate(ctx, tok1.AccessToken, ""); err == nil {
		t.Fatal("tok1 must be invalid after InvalidateAllByUser")
	}
	if err := svc.Validate(ctx, tok2.AccessToken, ""); err == nil {
		t.Fatal("tok2 must be invalid after InvalidateAllByUser")
	}

	// Other user's token must be unaffected.
	if err := svc.Validate(ctx, tokOther.AccessToken, "co"); err != nil {
		t.Fatalf("other user's token must remain valid: %v", err)
	}
}

// TestTokenService_InvalidateAllByUserIdempotent verifies that signing out a user
// with no tokens does not return an error.
func TestTokenService_InvalidateAllByUserIdempotent(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	svc := auth.NewTokenService(st, time.Hour, nil)

	if err := svc.InvalidateAllByUser(ctx, "ghost-user"); err != nil {
		t.Fatalf("InvalidateAllByUser on user with no tokens must not error: %v", err)
	}
}

// TestHashPassword verifies that HashPassword produces a non-empty hash that differs
// from the plain-text input.
func TestHashPassword(t *testing.T) {
	hash, err := auth.HashPassword("super-secret-pass")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if hash == "" {
		t.Fatal("hash must not be empty")
	}
	if hash == "super-secret-pass" {
		t.Fatal("hash must not equal the plain-text password")
	}
}

// TestCheckPassword verifies the correct password succeeds and an incorrect one
// returns ErrInvalidCredentials.
func TestCheckPassword(t *testing.T) {
	const plain = "my-password-123"

	hash, err := auth.HashPassword(plain)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	tests := []struct {
		name    string
		input   string
		wantErr error
	}{
		{"correct password", plain, nil},
		{"wrong password", "totally-wrong", auth.ErrInvalidCredentials},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := auth.CheckPassword(hash, tc.input)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("CheckPassword(%q): got %v, want %v", tc.input, err, tc.wantErr)
			}
		})
	}
}

// TestPasswordAuthenticator_Success verifies that the correct email+password pair
// returns the matching user with no error.
func TestPasswordAuthenticator_Success(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	const plain = "correct-password-123"
	hash, err := auth.HashPassword(plain)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	seedUser(t, st, "u-auth", "auth@example.com", hash)

	pa := auth.NewPasswordAuthenticator(st)
	u, err := pa.Authenticate(ctx, "auth@example.com", plain)
	if err != nil {
		t.Fatalf("Authenticate with correct credentials: %v", err)
	}
	if u.ID != "u-auth" {
		t.Fatalf("returned wrong user: got ID %q, want %q", u.ID, "u-auth")
	}
}

// TestPasswordAuthenticator_WrongPassword verifies that a known email with the wrong
// password returns ErrInvalidCredentials, not a nil error.
func TestPasswordAuthenticator_WrongPassword(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	hash, err := auth.HashPassword("real-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	seedUser(t, st, "u-wp", "wp@example.com", hash)

	pa := auth.NewPasswordAuthenticator(st)
	_, err = pa.Authenticate(ctx, "wp@example.com", "wrong-password")
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials for wrong password, got %v", err)
	}
}

// TestPasswordAuthenticator_UnknownEmail verifies that an email that does not exist
// returns ErrInvalidCredentials, the same error as wrong password, preventing enumeration.
func TestPasswordAuthenticator_UnknownEmail(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	pa := auth.NewPasswordAuthenticator(st)
	_, err := pa.Authenticate(ctx, "nobody@example.com", "any-password")
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials for unknown email, got %v", err)
	}
}

// TestPasswordAuthenticator_ImplementsAuthenticator is a compile-time canary that fails
// if PasswordAuthenticator stops satisfying the Authenticator interface.
func TestPasswordAuthenticator_ImplementsAuthenticator(t *testing.T) {
	var _ auth.Authenticator = (*auth.PasswordAuthenticator)(nil)
}

func TestPasswordAuthenticator_EmailVerificationAndBlock(t *testing.T) {
	ctx := context.Background()

	t.Run("verified + correct pass -> ok", func(t *testing.T) {
		st := newTestStore(t)
		hash, err := auth.HashPassword("password123")
		if err != nil {
			t.Fatalf("HashPassword: %v", err)
		}
		u := seedUser(t, st, "u-verified", "verified@example.com", hash)
		u.EmailVerified = true
		if err := st.UpdateUser(ctx, u); err != nil {
			t.Fatalf("failed to update user: %v", err)
		}

		pa := auth.NewPasswordAuthenticator(st)
		res, err := pa.Authenticate(ctx, "verified@example.com", "password123")
		if err != nil {
			t.Fatalf("expected successful authentication, got: %v", err)
		}
		if res.ID != "u-verified" {
			t.Errorf("expected user ID u-verified, got: %s", res.ID)
		}
	})

	t.Run("unverified + correct pass -> ErrEmailNotVerified", func(t *testing.T) {
		st := newTestStore(t)
		hash, err := auth.HashPassword("password123")
		if err != nil {
			t.Fatalf("HashPassword: %v", err)
		}
		u := seedUser(t, st, "u-unverified", "unverified@example.com", hash)
		u.EmailVerified = false
		if err := st.UpdateUser(ctx, u); err != nil {
			t.Fatalf("failed to update user: %v", err)
		}

		pa := auth.NewPasswordAuthenticator(st)
		_, err = pa.Authenticate(ctx, "unverified@example.com", "password123")
		if !errors.Is(err, auth.ErrEmailNotVerified) {
			t.Errorf("expected ErrEmailNotVerified, got: %v", err)
		}
	})

	t.Run("unverified + wrong pass -> ErrInvalidCredentials", func(t *testing.T) {
		st := newTestStore(t)
		hash, err := auth.HashPassword("password123")
		if err != nil {
			t.Fatalf("HashPassword: %v", err)
		}
		u := seedUser(t, st, "u-unverified-wrong", "unverified-wrong@example.com", hash)
		u.EmailVerified = false
		if err := st.UpdateUser(ctx, u); err != nil {
			t.Fatalf("failed to update user: %v", err)
		}

		pa := auth.NewPasswordAuthenticator(st)
		_, err = pa.Authenticate(ctx, "unverified-wrong@example.com", "wrongpassword")
		if !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Errorf("expected ErrInvalidCredentials, got: %v", err)
		}
	})

	t.Run("blocked + unverified -> ErrInvalidCredentials", func(t *testing.T) {
		st := newTestStore(t)
		hash, err := auth.HashPassword("password123")
		if err != nil {
			t.Fatalf("HashPassword: %v", err)
		}
		u := seedUser(t, st, "u-blocked-unverified", "blocked@example.com", hash)
		u.EmailVerified = false
		u.Blocked = true
		if err := st.UpdateUser(ctx, u); err != nil {
			t.Fatalf("failed to update user: %v", err)
		}

		pa := auth.NewPasswordAuthenticator(st)
		_, err = pa.Authenticate(ctx, "blocked@example.com", "password123")
		if !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Errorf("expected ErrInvalidCredentials for blocked user, got: %v", err)
		}
	})
}
