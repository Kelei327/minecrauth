// Copyright 2025 - Alby Hernández and the minecrauth contributors
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/achetronic/minecrauth/internal/store"
)

// OIDCBrowserFlow implements the OIDC authorization-code flow with PKCE for browser login.
type OIDCBrowserFlow struct {
	verifier      *gooidc.IDTokenVerifier
	oauth2Config  oauth2.Config
	store         store.Store
	autoProvision bool
	provisioner   Provisioner
}

// NewOIDCBrowserFlow creates an OIDCBrowserFlow by running OIDC discovery against issuer.
func NewOIDCBrowserFlow(ctx context.Context, issuer, clientID, clientSecret, redirectURL string, st store.Store, autoProvision bool, prov Provisioner) (*OIDCBrowserFlow, error) {
	provider, err := gooidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	return &OIDCBrowserFlow{
		verifier: provider.Verifier(&gooidc.Config{ClientID: clientID}),
		oauth2Config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{gooidc.ScopeOpenID, "email", "profile"},
		},
		store:         st,
		autoProvision: autoProvision,
		provisioner:   prov,
	}, nil
}

// AuthCodeURL builds the IdP redirect URL with PKCE S256.
func (f *OIDCBrowserFlow) AuthCodeURL(state, challenge string) string {
	return f.oauth2Config.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

// Exchange swaps the auth code for tokens, verifies the id_token, and maps to a local user.
func (f *OIDCBrowserFlow) Exchange(ctx context.Context, code, codeVerifier string) (*store.User, error) {
	tok, err := f.oauth2Config.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	if err != nil {
		return nil, fmt.Errorf("oidc token exchange: %w", err)
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		return nil, ErrInvalidCredentials
	}
	idTok, err := f.verifier.Verify(ctx, rawID)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	var claims struct {
		Email         string `json:"email"`
		EmailVerified *bool  `json:"email_verified"`
	}
	if err := idTok.Claims(&claims); err != nil {
		return nil, fmt.Errorf("parsing id token claims: %w", err)
	}
	if claims.EmailVerified != nil && !*claims.EmailVerified {
		return nil, ErrInvalidCredentials
	}
	if claims.Email == "" {
		return nil, ErrInvalidCredentials
	}
	user, err := f.store.GetUserByEmail(ctx, claims.Email)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			if f.autoProvision && f.provisioner != nil {
				u, perr := f.provisioner.CreateProvisionedUser(ctx, claims.Email)
				if perr != nil {
					return nil, fmt.Errorf("provisioning user: %w", perr)
				}
				return u, nil
			}
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("looking up user: %w", err)
	}
	if user.Blocked {
		return nil, ErrInvalidCredentials
	}
	return user, nil
}

// GeneratePKCE returns a high-entropy verifier and its S256 challenge.
func GeneratePKCE() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", fmt.Errorf("reading random: %w", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

// GenerateState returns a random opaque state value.
func GenerateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("reading random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
