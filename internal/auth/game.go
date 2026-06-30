package auth

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"

	"github.com/achetronic/minecrauth/internal/store"
)

// GameAuthenticator authenticates the Yggdrasil/launcher plane. It uses the user's
// dedicated game password when set, and falls back to the account password otherwise.
// OIDC is intentionally NOT part of this plane (a Minecraft launcher only sends
// username+password), so this authenticator is password-only.
type GameAuthenticator struct {
	store store.Store
}

// NewGameAuthenticator returns a GameAuthenticator backed by st.
func NewGameAuthenticator(st store.Store) *GameAuthenticator {
	return &GameAuthenticator{store: st}
}

var _ Authenticator = (*GameAuthenticator)(nil)

// Authenticate looks up the user by email, and uses the dedicated game password
// if set, otherwise falling back to the account password.
func (a *GameAuthenticator) Authenticate(ctx context.Context, email, password string) (*store.User, error) {
	u, err := a.store.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("game authenticate: looking up user: %w", err)
	}

	// Choose which hash to check: the game password if set, else the account password.
	hash := u.PasswordHash
	if u.GamePasswordHash != "" {
		hash = u.GamePasswordHash
	}

	if err := CheckPassword(hash, password); err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("game authenticate: %w", err)
	}

	if u.Blocked {
		return nil, ErrInvalidCredentials
	}

	if !u.EmailVerified {
		return nil, ErrEmailNotVerified
	}

	return u, nil
}
