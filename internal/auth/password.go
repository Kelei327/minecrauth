// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"

	"github.com/achetronic/minecrauth/internal/store"
)

// Ensure PasswordAuthenticator satisfies the Authenticator interface at compile time.
var _ Authenticator = (*PasswordAuthenticator)(nil)

// bcryptCost is the work factor used when hashing passwords.
// bcrypt.DefaultCost (10) balances security and response latency on current hardware.
const bcryptCost = bcrypt.DefaultCost

// dummyHash is a pre-computed bcrypt hash used for constant-time dummy comparisons
// when no user is found by email. Without it, the "unknown email" path would return
// faster than the "wrong password" path, leaking user existence via timing analysis.
var dummyHash []byte

func init() {
	var err error
	dummyHash, err = bcrypt.GenerateFromPassword([]byte("minecrauth-dummy-constant-time"), bcryptCost)
	if err != nil {
		panic("auth: failed to initialize dummy bcrypt hash: " + err.Error())
	}
}

// HashPassword hashes plain using bcrypt at bcryptCost.
func HashPassword(plain string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), bcryptCost)
	if err != nil {
		return "", fmt.Errorf("hashing password: %w", err)
	}
	return string(hash), nil
}

// CheckPassword verifies hash against plain. Returns ErrInvalidCredentials on mismatch.
func CheckPassword(hash, plain string) error {
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return ErrInvalidCredentials
		}
		return fmt.Errorf("comparing password hash: %w", err)
	}
	return nil
}

// Authenticator authenticates a management-plane identity by email and credential,
// returning the matching user on success. The MVP ships PasswordAuthenticator.
// Future OIDC connectors implement this same interface without touching the Yggdrasil
// token flow, as decided in P3.
type Authenticator interface {
	Authenticate(ctx context.Context, email, password string) (*store.User, error)
}

// PasswordAuthenticator implements Authenticator using bcrypt-hashed passwords
// stored in the database.
type PasswordAuthenticator struct {
	store store.Store
}

// NewPasswordAuthenticator returns a PasswordAuthenticator backed by st.
func NewPasswordAuthenticator(st store.Store) *PasswordAuthenticator {
	return &PasswordAuthenticator{store: st}
}

// Authenticate looks up the user by email and bcrypt-compares the provided password.
// Both an unknown email and a wrong password return ErrInvalidCredentials.
// This is deliberate: returning the same error for both cases prevents callers or
// attackers from distinguishing "no such user" from "wrong password" (user enumeration).
// A blocked user also returns ErrInvalidCredentials after performing the dummy bcrypt
// comparison, so the response time is indistinguishable from a normal failure.
func (a *PasswordAuthenticator) Authenticate(ctx context.Context, email, password string) (*store.User, error) {
	u, err := a.store.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Perform a dummy bcrypt comparison so the response time matches the
			// found-but-wrong-password path, making timing-based enumeration harder.
			_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("authenticate: looking up user: %w", err)
	}

	if err := CheckPassword(u.PasswordHash, password); err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("authenticate: %w", err)
	}

	// blocked users are rejected like bad credentials so the block state is not leaked on the login path.
	if u.Blocked {
		return nil, ErrInvalidCredentials
	}

	if !u.EmailVerified {
		return nil, ErrEmailNotVerified
	}

	return u, nil
}
