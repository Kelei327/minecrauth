// Copyright 2025 - Alby Hernández and the minecrauth contributors
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/achetronic/minecrauth/internal/store"
)

// CompositeAuthenticator tries each Authenticator in order and returns the first
// success. If an authenticator returns a real (non-ErrInvalidCredentials) error,
// that error is propagated immediately without consulting further authenticators.
// If every authenticator returns ErrInvalidCredentials, ErrInvalidCredentials is
// returned.
//
// Typical wiring (per DECISIONS.md §OIDC connector shape):
//
//	NewCompositeAuthenticator(passwordAuthn, oidcAuthn)
//
// This keeps local password auth as the primary path and OIDC token auth as the
// secondary path, so password authentication keeps working alongside OIDC.
type CompositeAuthenticator struct {
	authenticators []Authenticator
}

// Ensure CompositeAuthenticator satisfies the Authenticator interface at compile time.
var _ Authenticator = (*CompositeAuthenticator)(nil)

// NewCompositeAuthenticator returns a CompositeAuthenticator that tries each
// authenticator in the supplied order.
func NewCompositeAuthenticator(authenticators ...Authenticator) *CompositeAuthenticator {
	return &CompositeAuthenticator{authenticators: authenticators}
}

// Authenticate tries each configured authenticator in registration order.
//
//   - First success → (user, nil).
//   - Real (non-ErrInvalidCredentials) error → short-circuit, propagate wrapped.
//   - All return ErrInvalidCredentials → ErrInvalidCredentials.
func (c *CompositeAuthenticator) Authenticate(ctx context.Context, email, password string) (*store.User, error) {
	for _, a := range c.authenticators {
		u, err := a.Authenticate(ctx, email, password)
		if err == nil {
			return u, nil
		}
		if !errors.Is(err, ErrInvalidCredentials) {
			// Real error: short-circuit and surface it to the caller.
			return nil, fmt.Errorf("composite authenticator: %w", err)
		}
	}
	return nil, ErrInvalidCredentials
}
