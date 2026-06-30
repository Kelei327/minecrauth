// Copyright 2025 - Alby Hernández and the minecrauth contributors
// SPDX-License-Identifier: Apache-2.0

// Package httpserver manages the HTTP server lifecycle, routing, and middleware.
package httpserver

import (
	"context"

	"github.com/achetronic/minecrauth/internal/store"
)

// contextKey is a package-local type for context keys, preventing collisions with
// keys from other packages.
type contextKey int

const (
	contextKeyUser contextKey = iota
	contextKeySession
)

// contextWithUser returns a derived context carrying the authenticated user.
func contextWithUser(ctx context.Context, u *store.User) context.Context {
	return context.WithValue(ctx, contextKeyUser, u)
}

// userFromContext retrieves the authenticated store.User placed in the context by the
// basicAuth middleware. Returns false when no user has been set.
func userFromContext(ctx context.Context) (*store.User, bool) {
	u, ok := ctx.Value(contextKeyUser).(*store.User)
	return u, ok
}

// contextWithSession returns a derived context carrying the current session.
func contextWithSession(ctx context.Context, s *store.Session) context.Context {
	return context.WithValue(ctx, contextKeySession, s)
}

// sessionFromContext retrieves the current store.Session placed in the context by the
// sessionOrBasicAuth middleware. Returns false when no session has been set.
func sessionFromContext(ctx context.Context) (*store.Session, bool) {
	s, ok := ctx.Value(contextKeySession).(*store.Session)
	return s, ok
}
