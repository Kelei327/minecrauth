package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/achetronic/minecrauth/internal/store"
)

// tokenBytes is the number of random bytes used in each generated opaque token (256 bits).
// This matches the security margin recommended for session tokens.
const tokenBytes = 32

// TokenService manages the lifecycle of opaque Yggdrasil access tokens.
// Tokens are stored in the database; validation is always a DB round-trip, which
// makes invalidate and signout trivially correct (P3 decision: no JWT).
type TokenService struct {
	store store.Store
	ttl   time.Duration
	clock func() time.Time
}

// NewTokenService constructs a TokenService backed by st.
// ttl controls token lifetime; 0 means tokens never expire automatically.
// clock is an injectable time source used for expiry; nil defaults to time.Now,
// which allows deterministic expiry testing without sleep.
func NewTokenService(st store.Store, ttl time.Duration, clock func() time.Time) *TokenService {
	if clock == nil {
		clock = time.Now
	}
	return &TokenService{store: st, ttl: ttl, clock: clock}
}

// generateToken returns a cryptographically random opaque string of tokenBytes bytes
// encoded as base64 URL-safe without padding. Suitable for both accessToken and clientToken.
func generateToken() (string, error) {
	buf := make([]byte, tokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("reading random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// Issue creates and persists a new Yggdrasil token for userID with an optional playerID.
// If clientToken is empty, one is generated. ExpiresAt is derived from the service TTL;
// a nil ExpiresAt means the token never expires (TTL == 0).
func (s *TokenService) Issue(ctx context.Context, userID string, playerID *string, clientToken string) (*store.YggdrasilToken, error) {
	accessToken, err := generateToken()
	if err != nil {
		return nil, fmt.Errorf("issue: generating access token: %w", err)
	}

	if clientToken == "" {
		clientToken, err = generateToken()
		if err != nil {
			return nil, fmt.Errorf("issue: generating client token: %w", err)
		}
	}

	now := s.clock()
	var expiresAt *time.Time
	if s.ttl > 0 {
		t := now.Add(s.ttl)
		expiresAt = &t
	}

	tok := &store.YggdrasilToken{
		AccessToken: accessToken,
		ClientToken: clientToken,
		UserID:      userID,
		PlayerID:    playerID,
		CreatedAt:   now,
		ExpiresAt:   expiresAt,
	}

	if err := s.store.CreateToken(ctx, tok); err != nil {
		return nil, fmt.Errorf("issue: persisting token: %w", err)
	}

	return tok, nil
}

// Validate checks that accessToken exists in the store, that clientToken matches when
// non-empty, and that the token has not passed ExpiresAt according to the injected clock.
// Returns ErrTokenInvalid or ErrTokenExpired so handlers can map them to Yggdrasil
// error responses at the protocol boundary.
func (s *TokenService) Validate(ctx context.Context, accessToken, clientToken string) error {
	tok, err := s.store.GetToken(ctx, accessToken)
	if err != nil {
		return ErrTokenInvalid
	}

	if clientToken != "" && tok.ClientToken != clientToken {
		return ErrTokenInvalid
	}

	if tok.ExpiresAt != nil && !s.clock().Before(*tok.ExpiresAt) {
		return ErrTokenExpired
	}

	return nil
}

// Refresh validates the existing token pair, deletes the old access token, and issues
// a new one preserving the original clientToken and userID. This is the Yggdrasil token
// rotation endpoint. Returns ErrTokenInvalid or ErrTokenExpired if the pair cannot be
// validated before rotation.
//
// selectedPlayerID drives the Yggdrasil profile-selection step: when a user owns several
// players, authenticate leaves the token without a profile and the launcher re-sends a
// refresh carrying the chosen profile. When selectedPlayerID is non-nil the new token is
// bound to that player, which MUST belong to the token's user (otherwise ErrProfileNotOwned).
// When nil, the original token's playerID is preserved.
func (s *TokenService) Refresh(ctx context.Context, accessToken, clientToken string, selectedPlayerID *string) (*store.YggdrasilToken, error) {
	tok, err := s.store.GetToken(ctx, accessToken)
	if err != nil {
		return nil, ErrTokenInvalid
	}

	if clientToken != "" && tok.ClientToken != clientToken {
		return nil, ErrTokenInvalid
	}

	if tok.ExpiresAt != nil && !s.clock().Before(*tok.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	// Default: preserve whatever profile the token already had.
	playerID := tok.PlayerID
	if selectedPlayerID != nil {
		// Profile selection: the chosen player must belong to this token's user, so a
		// token cannot be bound to someone else's profile.
		player, perr := s.store.GetPlayerByID(ctx, *selectedPlayerID)
		if perr != nil || player.UserID != tok.UserID {
			return nil, ErrProfileNotOwned
		}
		playerID = selectedPlayerID
	}

	if err := s.store.DeleteToken(ctx, accessToken); err != nil {
		return nil, fmt.Errorf("refresh: removing old token: %w", err)
	}

	// Issue uses tok.ClientToken so the client retains its original token identifier.
	newTok, err := s.Issue(ctx, tok.UserID, playerID, tok.ClientToken)
	if err != nil {
		return nil, fmt.Errorf("refresh: %w", err)
	}

	return newTok, nil
}

// Invalidate deletes the named access token. This is the Yggdrasil /invalidate endpoint.
// clientToken is optional; when provided it must match the stored value.
func (s *TokenService) Invalidate(ctx context.Context, accessToken, clientToken string) error {
	tok, err := s.store.GetToken(ctx, accessToken)
	if err != nil {
		return ErrTokenInvalid
	}

	if clientToken != "" && tok.ClientToken != clientToken {
		return ErrTokenInvalid
	}

	if err := s.store.DeleteToken(ctx, accessToken); err != nil {
		return fmt.Errorf("invalidate: %w", err)
	}

	return nil
}

// InvalidateAllByUser deletes every token belonging to userID. This is the Yggdrasil
// /signout endpoint. The operation is idempotent: no error is returned when userID has
// no active tokens.
func (s *TokenService) InvalidateAllByUser(ctx context.Context, userID string) error {
	if err := s.store.DeleteTokensByUser(ctx, userID); err != nil {
		return fmt.Errorf("invalidate all by user: %w", err)
	}
	return nil
}
