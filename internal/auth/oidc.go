// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	gooidc "github.com/coreos/go-oidc/v3/oidc"

	"github.com/achetronic/minecrauth/internal/store"
)

// Provisioner is a minimal interface for auto-provisioning a local user account
// from a verified OIDC identity. It is intentionally defined here (in the auth
// package) rather than in accounts to avoid an import cycle: the accounts package
// already imports auth (for HashPassword), so auth must never import accounts.
// Wire this at server startup via an adapter over accounts.Service in main.
type Provisioner interface {
	// CreateProvisionedUser creates a non-admin local account for the given email.
	// It is called only when OIDC auto-provisioning is enabled and the email is
	// not yet known in the local store.
	CreateProvisionedUser(ctx context.Context, email string) (*store.User, error)
}

// OIDCAuthenticator verifies OIDC ID tokens and maps the verified email claim to
// a local user. It implements the Authenticator interface for the management plane
// only; it never touches Yggdrasil tokens (per DECISIONS.md §OIDC connector shape).
//
// The "password" field in Authenticate is treated as a raw OIDC ID token
// (bearer-as-password pattern). Signature and claims verification is delegated to
// github.com/coreos/go-oidc/v3, which fetches the issuer JWKS endpoint – we never
// hand-roll JWT/JWKS signature verification.
//
// Ref: https://openid.net/specs/openid-connect-core-1_0.html
type OIDCAuthenticator struct {
	verifier      *gooidc.IDTokenVerifier
	store         store.Store
	autoProvision bool
	provisioner   Provisioner
}

// Ensure OIDCAuthenticator satisfies the Authenticator interface at compile time.
var _ Authenticator = (*OIDCAuthenticator)(nil)

// NewOIDCAuthenticator creates an OIDCAuthenticator by running OIDC discovery
// against issuer. Returns an error if discovery fails (e.g. IdP is unreachable or
// returns a non-2xx status). The caller should treat this error as fatal and refuse
// to start, because the operator explicitly enabled OIDC by setting the issuer.
//
// Ref: https://openid.net/specs/openid-connect-discovery-1_0.html
func NewOIDCAuthenticator(
	ctx context.Context,
	issuer, clientID string,
	st store.Store,
	autoProvision bool,
	provisioner Provisioner,
) (*OIDCAuthenticator, error) {
	provider, err := gooidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: discovering provider %q: %w", issuer, err)
	}
	verifier := provider.Verifier(&gooidc.Config{ClientID: clientID})
	return &OIDCAuthenticator{
		verifier:      verifier,
		store:         st,
		autoProvision: autoProvision,
		provisioner:   provisioner,
	}, nil
}

// oidcClaims holds the subset of OIDC ID token claims that OIDCAuthenticator inspects.
// Ref: https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
type oidcClaims struct {
	Email         string `json:"email"`
	EmailVerified *bool  `json:"email_verified"`
}

// Authenticate treats idToken (the "password" parameter) as a raw OIDC ID token.
//
// Steps:
//  1. Verify signature, expiry, issuer and audience via go-oidc (backed by JWKS).
//  2. Extract the email and email_verified claims from the verified token.
//  3. Reject the token if email_verified is explicitly false.
//  4. Require the token's email claim to case-insensitively equal the supplied email.
//  5. Look up the local user; auto-provision if configured and the user is absent.
//
// Any verification failure returns ErrInvalidCredentials. Real infrastructure
// errors (e.g. store failures) are propagated wrapped.
func (a *OIDCAuthenticator) Authenticate(ctx context.Context, email, idToken string) (*store.User, error) {
	tok, err := a.verifier.Verify(ctx, idToken)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	var claims oidcClaims
	if err := tok.Claims(&claims); err != nil {
		return nil, ErrInvalidCredentials
	}

	// Reject tokens whose email has not been verified by the IdP.
	if claims.EmailVerified != nil && !*claims.EmailVerified {
		return nil, ErrInvalidCredentials
	}

	// The token's email claim must match the identity the caller presented.
	if !strings.EqualFold(claims.Email, email) {
		return nil, ErrInvalidCredentials
	}

	// Look up the local user by the verified email.
	u, err := a.store.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			if a.autoProvision && a.provisioner != nil {
			_, provErr := a.provisioner.CreateProvisionedUser(ctx, email)
			if provErr != nil {
				return nil, fmt.Errorf("oidc: auto-provisioning user %q: %w", email, provErr)
			}
		// The new account was provisioned as pending, so it must not authenticate yet.
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("oidc: looking up user: %w", err)
	}
if u.Blocked || !IsApprovedUser(u) || !u.EmailVerified {
	return nil, ErrInvalidCredentials
}
	return u, nil
}
