// Copyright 2025 - Alby Hernández and the minecrauth contributors
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/achetronic/minecrauth/internal/store"
)

// sessionTokenBytes is the number of random bytes used for each session or CSRF token.
// 32 bytes = 256 bits, well above any brute-force threshold.
const sessionTokenBytes = 32

// SessionManager creates, validates, and revokes browser UI sessions.
// These sessions are independent of Yggdrasil access tokens and are used
// exclusively by the Vue Web UI (see DECISIONS.md §Web UI: Vue 3 without a build step).
type SessionManager struct {
	store store.Store
	ttl   time.Duration
	clock func() time.Time
}

// NewSessionManager constructs a SessionManager backed by st.
// ttl controls how long sessions remain valid (e.g. 7 * 24 * time.Hour).
// clock is an injectable time source; nil defaults to time.Now, which allows
// deterministic expiry testing without sleeping.
func NewSessionManager(st store.Store, ttl time.Duration, clock func() time.Time) *SessionManager {
	if clock == nil {
		clock = time.Now
	}
	return &SessionManager{store: st, ttl: ttl, clock: clock}
}

// generateSessionToken returns a cryptographically random URL-safe base64 string
// with no padding, suitable for use as an opaque session or CSRF token.
func generateSessionToken() (string, error) {
	b := make([]byte, sessionTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("reading random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Create generates a new session for userID, persists it, and returns the record.
// Both the session token and a separate CSRF token are derived from
// crypto/rand so they are unpredictable even under concurrent load.
func (sm *SessionManager) Create(ctx context.Context, userID string, impersonatedBy *string) (*store.Session, error) {
	token, err := generateSessionToken()
	if err != nil {
		return nil, fmt.Errorf("session create: generating token: %w", err)
	}

	csrfToken, err := generateSessionToken()
	if err != nil {
		return nil, fmt.Errorf("session create: generating csrf token: %w", err)
	}

	now := sm.clock()
	sess := &store.Session{
		Token:          token,
		UserID:         userID,
		CSRFToken:      csrfToken,
		ImpersonatedBy: impersonatedBy,
		CreatedAt:      now,
		ExpiresAt:      now.Add(sm.ttl),
	}

	if err := sm.store.CreateSession(ctx, sess); err != nil {
		return nil, fmt.Errorf("session create: persisting: %w", err)
	}

	return sess, nil
}

// Validate looks up the session by token and checks whether it has expired.
// Returns ErrInvalidSession if the token is not found or has passed its ExpiresAt.
func (sm *SessionManager) Validate(ctx context.Context, token string) (*store.Session, error) {
	sess, err := sm.store.GetSession(ctx, token)
	if err != nil {
		// Treat not-found the same as invalid so callers need not import store.
		return nil, ErrInvalidSession
	}

	if !sm.clock().Before(sess.ExpiresAt) {
		// Opportunistically clean up the expired session; ignore errors.
		_ = sm.store.DeleteSession(ctx, token)
		return nil, ErrInvalidSession
	}

	return sess, nil
}

// Revoke deletes the session identified by token. The call is idempotent:
// deleting a non-existent token is not an error.
func (sm *SessionManager) Revoke(ctx context.Context, token string) error {
	if err := sm.store.DeleteSession(ctx, token); err != nil {
		return fmt.Errorf("session revoke: %w", err)
	}
	return nil
}

// RevokeAllByUser deletes every session belonging to userID.
// Used when an account is blocked or a password is changed to force re-authentication.
func (sm *SessionManager) RevokeAllByUser(ctx context.Context, userID string) error {
	if err := sm.store.DeleteSessionsByUser(ctx, userID); err != nil {
		return fmt.Errorf("session revoke all by user: %w", err)
	}
	return nil
}

// ValidCSRF performs a constant-time comparison of the session CSRF and the provided CSRF string.
func ValidCSRF(sessionCSRF, provided string) bool {
	if provided == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(sessionCSRF), []byte(provided)) == 1
}

// CompareCSRF performs a constant-time comparison between the CSRF token stored in
// the session and the value supplied by the caller (from the X-CSRF-Token header).
// Returns true only when both values are equal. Using crypto/subtle prevents
// timing attacks that could otherwise leak the CSRF token byte by byte.
func CompareCSRF(session *store.Session, provided string) bool {
	expected := []byte(session.CSRFToken)
	got := []byte(provided)
	// subtle.ConstantTimeCompare requires equal lengths; pad to avoid short-circuit.
	if len(expected) != len(got) {
		return false
	}
	return subtle.ConstantTimeCompare(expected, got) == 1
}
