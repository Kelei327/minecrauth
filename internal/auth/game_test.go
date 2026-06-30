package auth_test

import (
	"context"
	"errors"
	"testing"

	"github.com/achetronic/minecrauth/internal/auth"
)

func TestGameAuthenticator(t *testing.T) {
	ctx := context.Background()

	// Helper to generate passwords we can hash
	hashAcct, _ := auth.HashPassword("account_secret_123")
	hashGame, _ := auth.HashPassword("game_secret_456")

	t.Run("no game password - falls back to account password", func(t *testing.T) {
		st := newTestStore(t)
		// Seed a verified user with only an account password
		u := seedUser(t, st, "u1", "user@example.com", hashAcct)

		authenticator := auth.NewGameAuthenticator(st)

		// Correct account password must succeed
		resolved, err := authenticator.Authenticate(ctx, "user@example.com", "account_secret_123")
		if err != nil {
			t.Fatalf("expected success, got: %v", err)
		}
		if resolved.ID != u.ID {
			t.Errorf("expected user ID %s, got %s", u.ID, resolved.ID)
		}

		// Wrong account password must fail
		_, err = authenticator.Authenticate(ctx, "user@example.com", "wrong_secret")
		if !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Errorf("expected ErrInvalidCredentials, got: %v", err)
		}
	})

	t.Run("game password set - requires game password, account password ceases working", func(t *testing.T) {
		st := newTestStore(t)
		u := seedUser(t, st, "u1", "user@example.com", hashAcct)

		// Set game password hash
		u.GamePasswordHash = hashGame
		if err := st.UpdateUser(ctx, u); err != nil {
			t.Fatalf("updating user with game password hash: %v", err)
		}

		authenticator := auth.NewGameAuthenticator(st)

		// Correct game password must succeed
		resolved, err := authenticator.Authenticate(ctx, "user@example.com", "game_secret_456")
		if err != nil {
			t.Fatalf("expected successful auth with game password, got: %v", err)
		}
		if resolved.ID != u.ID {
			t.Errorf("expected user ID %s, got %s", u.ID, resolved.ID)
		}

		// Account password must now FAIL
		_, err = authenticator.Authenticate(ctx, "user@example.com", "account_secret_123")
		if !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Errorf("expected ErrInvalidCredentials for account password after game password is set, got: %v", err)
		}

		// Wrong game password must fail
		_, err = authenticator.Authenticate(ctx, "user@example.com", "wrong_game_secret")
		if !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Errorf("expected ErrInvalidCredentials, got: %v", err)
		}
	})

	t.Run("blocked user - returns ErrInvalidCredentials", func(t *testing.T) {
		st := newTestStore(t)
		u := seedUser(t, st, "u1", "user@example.com", hashAcct)
		u.Blocked = true
		u.GamePasswordHash = hashGame
		if err := st.UpdateUser(ctx, u); err != nil {
			t.Fatalf("updating user: %v", err)
		}

		authenticator := auth.NewGameAuthenticator(st)

		// Correct game password on a blocked user must still return ErrInvalidCredentials
		_, err := authenticator.Authenticate(ctx, "user@example.com", "game_secret_456")
		if !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Errorf("expected blocked user to fail with ErrInvalidCredentials, got: %v", err)
		}

		// No game password fallback on a blocked user must still return ErrInvalidCredentials
		u.GamePasswordHash = ""
		if err := st.UpdateUser(ctx, u); err != nil {
			t.Fatalf("updating user: %v", err)
		}
		_, err = authenticator.Authenticate(ctx, "user@example.com", "account_secret_123")
		if !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Errorf("expected blocked user with account password to fail with ErrInvalidCredentials, got: %v", err)
		}
	})

	t.Run("unverified email - returns ErrEmailNotVerified", func(t *testing.T) {
		st := newTestStore(t)
		u := seedUser(t, st, "u1", "user@example.com", hashAcct)
		u.EmailVerified = false
		u.GamePasswordHash = hashGame
		if err := st.UpdateUser(ctx, u); err != nil {
			t.Fatalf("updating user: %v", err)
		}

		authenticator := auth.NewGameAuthenticator(st)

		// Correct game password on an unverified user must return ErrEmailNotVerified
		_, err := authenticator.Authenticate(ctx, "user@example.com", "game_secret_456")
		if !errors.Is(err, auth.ErrEmailNotVerified) {
			t.Errorf("expected unverified user to fail with ErrEmailNotVerified, got: %v", err)
		}

		// Falls back to account password, but still returns ErrEmailNotVerified
		u.GamePasswordHash = ""
		if err := st.UpdateUser(ctx, u); err != nil {
			t.Fatalf("updating user: %v", err)
		}
		_, err = authenticator.Authenticate(ctx, "user@example.com", "account_secret_123")
		if !errors.Is(err, auth.ErrEmailNotVerified) {
			t.Errorf("expected unverified user to fail with ErrEmailNotVerified, got: %v", err)
		}
	})

	t.Run("unknown email - returns ErrInvalidCredentials", func(t *testing.T) {
		st := newTestStore(t)
		authenticator := auth.NewGameAuthenticator(st)

		_, err := authenticator.Authenticate(ctx, "nonexistent@example.com", "secret")
		if !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Errorf("expected unknown email to fail with ErrInvalidCredentials, got: %v", err)
		}
	})
}
