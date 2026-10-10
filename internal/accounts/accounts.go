// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

// Package accounts manages user and player domain logic, credentials, and relations.
package accounts

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/achetronic/minecrauth/internal/auth"
	"github.com/achetronic/minecrauth/internal/store"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
)

// Sentinel errors representing domain boundary failures.
var (
	ErrEmailTaken         = errors.New("email already taken")
	ErrPlayerNameTaken    = errors.New("player name already taken")
	ErrPlayerUUIDTaken    = errors.New("player UUID already taken")
	ErrInvalidInvite      = errors.New("invalid, expired or already used invite code")
	ErrPlayerLimitReached = errors.New("player limit per user reached")
	ErrWeakPassword       = errors.New("password does not meet the minimum length requirement")
	ErrInvalidPlayerName  = errors.New("player name does not match regex requirement")
	ErrInvalidPlayerUUID  = errors.New("player UUID is invalid")
	ErrNotAdmin           = errors.New("user is not an admin")
	ErrInvalidToken       = errors.New("invalid, expired or already used token")
	ErrNotFound           = store.ErrNotFound
	ErrInvalidTOTP        = errors.New("invalid or expired authentication code")
	ErrTOTPNotPending     = errors.New("TOTP setup is not pending for this user")
	ErrTOTPNotEnabled     = errors.New("TOTP is not enabled for this user")
	ErrInvalidApprovalStatus = errors.New("invalid account approval status")
	ErrInvalidInviteTTL      = errors.New("invite TTL must be between 1 second and 7 days")
)

const maxInviteTTL = 7 * 24 * time.Hour

// Policy defines validation and generation rules for the accounts service.
type Policy struct {
	MinPasswordLength        int
	MaxPlayersPerUser        int // -1 means unlimited
	PlayerNameRegex          *regexp.Regexp
	UUIDGeneration           string // "random" or "offline"
	RequireInvite            bool
	RequireEmailVerification bool
}

// Service manages the domain logic for users, players, and invites.
type Service struct {
	store  store.Store
	policy Policy
}

// NewService constructs a new accounts Service backed by the provided store and policy.
func NewService(st store.Store, p Policy) *Service {
	return &Service{
		store:  st,
		policy: p,
	}
}

// Register registers a new physical user self-service.
// The username is the user's email address.
func (s *Service) Register(ctx context.Context, email, password, inviteCode string) (*store.User, error) {
	if email == "" {
		return nil, fmt.Errorf("email is required")
	}
	if len(password) < s.policy.MinPasswordLength {
		return nil, ErrWeakPassword
	}

	if s.policy.RequireInvite {
		if inviteCode == "" {
			return nil, ErrInvalidInvite
		}
		inv, err := s.store.GetInvite(ctx, inviteCode)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, ErrInvalidInvite
			}
			return nil, fmt.Errorf("retrieving invite: %w", err)
		}
		if inv.UsedBy != nil {
			return nil, ErrInvalidInvite
		}
		if inv.ExpiresAt != nil && time.Now().After(*inv.ExpiresAt) {
			return nil, ErrInvalidInvite
		}
	}

	hashed, err := auth.HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}

	userID := uuid.NewString()
	u := &store.User{
		ID:                userID,
		Email:             email,
		PasswordHash:      hashed,
		IsAdmin:           false,
		ApprovalStatus: store.ApprovalPending,
		EmailVerified:     s.policy.RequireInvite || !s.policy.RequireEmailVerification,
		PreferredLanguage: "en",
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	if err := s.store.CreateUser(ctx, u); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return nil, ErrEmailTaken
		}
		return nil, fmt.Errorf("creating user: %w", err)
	}

	if s.policy.RequireInvite {
		if err := s.store.MarkInviteUsed(ctx, inviteCode, userID); err != nil {
			_ = s.store.DeleteUser(ctx, userID)
			if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrNotFound) {
				return nil, ErrInvalidInvite
			}
			return nil, fmt.Errorf("consuming invite: %w", err)
		}
	}

	return u, nil
}

// GetUser retrieves an existing user by their ID.
func (s *Service) GetUser(ctx context.Context, id string) (*store.User, error) {
	u, err := s.store.GetUserByID(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("getting user by id: %w", err)
	}
	return u, nil
}

// ListUsers lists all registered physical users.
func (s *Service) ListUsers(ctx context.Context) ([]*store.User, error) {
	users, err := s.store.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing users: %w", err)
	}
	return users, nil
}

// UpdateUserEmail updates the email for a physical user.
func (s *Service) UpdateUserEmail(ctx context.Context, id, newEmail string) error {
	if newEmail == "" {
		return fmt.Errorf("email is required")
	}
	u, err := s.store.GetUserByID(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("getting user: %w", err)
	}

	u.Email = newEmail
	u.UpdatedAt = time.Now()

	if err := s.store.UpdateUser(ctx, u); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return ErrEmailTaken
		}
		return fmt.Errorf("updating user email: %w", err)
	}
	return nil
}

// ChangePassword changes the password for a physical user after validating strength.
func (s *Service) ChangePassword(ctx context.Context, id, newPassword string) error {
	if len(newPassword) < s.policy.MinPasswordLength {
		return ErrWeakPassword
	}
	u, err := s.store.GetUserByID(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("getting user: %w", err)
	}

	hashed, err := auth.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}

	u.PasswordHash = hashed
	u.UpdatedAt = time.Now()

	if err := s.store.UpdateUser(ctx, u); err != nil {
		return fmt.Errorf("updating password: %w", err)
	}
	return nil
}

// SetGamePassword sets (or changes) the user's dedicated game password. An empty
// string is rejected here (use ClearGamePassword to remove it). Enforces MinPasswordLength.
func (s *Service) SetGamePassword(ctx context.Context, userID, plaintext string) error {
	if len(plaintext) < s.policy.MinPasswordLength {
		return ErrWeakPassword
	}
	u, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("getting user: %w", err)
	}

	hashed, err := auth.HashPassword(plaintext)
	if err != nil {
		return fmt.Errorf("hashing game password: %w", err)
	}

	u.GamePasswordHash = hashed
	u.UpdatedAt = time.Now()

	if err := s.store.UpdateUser(ctx, u); err != nil {
		return fmt.Errorf("updating game password: %w", err)
	}
	return nil
}

// ClearGamePassword removes the game password so the account password is used again.
func (s *Service) ClearGamePassword(ctx context.Context, userID string) error {
	u, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("getting user: %w", err)
	}

	u.GamePasswordHash = ""
	u.UpdatedAt = time.Now()

	if err := s.store.UpdateUser(ctx, u); err != nil {
		return fmt.Errorf("clearing game password: %w", err)
	}
	return nil
}

// DeleteUser deletes a physical user.
func (s *Service) DeleteUser(ctx context.Context, id string) error {
	if err := s.store.DeleteUser(ctx, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("deleting user: %w", err)
	}
	return nil
}

// SetBlocked sets the blocked flag for a user.
// A blocked user cannot log in via password or cookie session.
func (s *Service) SetBlocked(ctx context.Context, id string, blocked bool) error {
	u, err := s.store.GetUserByID(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("getting user: %w", err)
	}

	u.Blocked = blocked
	u.UpdatedAt = time.Now()

	if err := s.store.UpdateUser(ctx, u); err != nil {
		return fmt.Errorf("updating blocked status: %w", err)
	}
	return nil
}

// SetApprovalStatus changes a user's moderation state. An administrator account cannot
// be moved out of approved state, preventing an accidental lockout of the control plane.
func (s *Service) SetApprovalStatus(ctx context.Context, id, status string) error {
	if !store.IsValidApprovalStatus(status) {
		return ErrInvalidApprovalStatus
	}
	u, err := s.store.GetUserByID(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("getting user for approval update: %w", err)
	}
	if u.IsAdmin && status != store.ApprovalApproved {
		return ErrInvalidApprovalStatus
	}

	u.ApprovalStatus = status
	u.UpdatedAt = time.Now()
	if err := s.store.UpdateUser(ctx, u); err != nil {
		return fmt.Errorf("updating approval status: %w", err)
	}
	return nil
}

// SetAdmin sets the admin flag for a user.
func (s *Service) SetAdmin(ctx context.Context, id string, isAdmin bool) error {
	u, err := s.store.GetUserByID(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("getting user: %w", err)
	}

	u.IsAdmin = isAdmin
	u.UpdatedAt = time.Now()

	if err := s.store.UpdateUser(ctx, u); err != nil {
		return fmt.Errorf("updating admin status: %w", err)
	}
	return nil
}

// AdminCreateUser is a privileged path to create users bypassing invite requirements.
// Admin-created users are approved immediately so bootstrap administrators remain usable.
func (s *Service) AdminCreateUser(ctx context.Context, email, password string, isAdmin bool) (*store.User, error) {
	return s.createUser(ctx, email, password, isAdmin, store.ApprovalApproved)
}

// CreateProvisionedPendingUser creates a non-admin OIDC account that must be approved
// by an administrator before it can be used. The password should be random/unusable.
func (s *Service) CreateProvisionedPendingUser(ctx context.Context, email, password string) (*store.User, error) {
	return s.createUser(ctx, email, password, false, store.ApprovalPending)
}

// createUser centralizes creation so all trusted creation paths set approval state explicitly.
func (s *Service) createUser(ctx context.Context, email, password string, isAdmin bool, status string) (*store.User, error) {
	if email == "" {
		return nil, fmt.Errorf("email is required")
	}
	if len(password) < s.policy.MinPasswordLength {
		return nil, ErrWeakPassword
	}
	if !store.IsValidApprovalStatus(status) {
		return nil, ErrInvalidApprovalStatus
	}

	hashed, err := auth.HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}

	now := time.Now()
	u := &store.User{
		ID:                uuid.NewString(),
		Email:             email,
		PasswordHash:      hashed,
		IsAdmin:           isAdmin,
		ApprovalStatus:    status,
		EmailVerified:     true,
		PreferredLanguage: "en",
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if err := s.store.CreateUser(ctx, u); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return nil, ErrEmailTaken
		}
		return nil, fmt.Errorf("creating user: %w", err)
	}
	return u, nil
}

// CreatePlayer creates a new player profile associated with a user.
func (s *Service) CreatePlayer(ctx context.Context, userID, name string, chosenUUID string) (*store.Player, error) {
	if s.policy.PlayerNameRegex != nil && !s.policy.PlayerNameRegex.MatchString(name) {
		return nil, ErrInvalidPlayerName
	}

	_, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("associated user not found: %w", ErrNotFound)
		}
		return nil, fmt.Errorf("fetching user: %w", err)
	}

	if s.policy.MaxPlayersPerUser != -1 {
		count, err := s.store.CountPlayersByUser(ctx, userID)
		if err != nil {
			return nil, fmt.Errorf("counting players: %w", err)
		}
		if count >= s.policy.MaxPlayersPerUser {
			return nil, ErrPlayerLimitReached
		}
	}

	var profileUUID string
	if chosenUUID != "" {
		parsed, err := uuid.Parse(chosenUUID)
		if err != nil {
			return nil, fmt.Errorf("invalid chosen UUID: %w", ErrInvalidPlayerUUID)
		}
		profileUUID = parsed.String()
	} else {
		if s.policy.UUIDGeneration == "offline" {
			profileUUID = offlineProfileUUID(name)
		} else {
			profileUUID = randomProfileUUID()
		}
	}

	// Pre-emptive checks for helpful error messaging
	existingByName, err := s.store.GetPlayerByName(ctx, name)
	if err == nil && existingByName != nil {
		return nil, ErrPlayerNameTaken
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("checking player name conflict: %w", err)
	}

	existingByUUID, err := s.store.GetPlayerByUUID(ctx, profileUUID)
	if err == nil && existingByUUID != nil {
		return nil, ErrPlayerUUIDTaken
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("checking player UUID conflict: %w", err)
	}

	p := &store.Player{
		ID:            uuid.NewString(),
		UserID:        userID,
		Name:          name,
		UUID:          profileUUID,
		CreatedAt:     time.Now(),
		NameChangedAt: nil,
	}

	if err := s.store.CreatePlayer(ctx, p); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return nil, ErrPlayerNameTaken
		}
		return nil, fmt.Errorf("creating player: %w", err)
	}

	return p, nil
}

// GetPlayer retrieves a player by ID.
func (s *Service) GetPlayer(ctx context.Context, id string) (*store.Player, error) {
	p, err := s.store.GetPlayerByID(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("getting player by id: %w", err)
	}
	return p, nil
}

// GetPlayerByName retrieves a player by name.
func (s *Service) GetPlayerByName(ctx context.Context, name string) (*store.Player, error) {
	p, err := s.store.GetPlayerByName(ctx, name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("getting player by name: %w", err)
	}
	return p, nil
}

// GetPlayerByUUID retrieves a player by Minecraft UUID.
func (s *Service) GetPlayerByUUID(ctx context.Context, uuidStr string) (*store.Player, error) {
	p, err := s.store.GetPlayerByUUID(ctx, uuidStr)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("getting player by uuid: %w", err)
	}
	return p, nil
}

// ListPlayersByUser lists all players owned by a user.
func (s *Service) ListPlayersByUser(ctx context.Context, userID string) ([]*store.Player, error) {
	players, err := s.store.ListPlayersByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("listing players by user: %w", err)
	}
	return players, nil
}

// RenamePlayer renames a player and sets the NameChangedAt timestamp.
func (s *Service) RenamePlayer(ctx context.Context, playerID, newName string) error {
	if s.policy.PlayerNameRegex != nil && !s.policy.PlayerNameRegex.MatchString(newName) {
		return ErrInvalidPlayerName
	}

	p, err := s.store.GetPlayerByID(ctx, playerID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("getting player for rename: %w", err)
	}

	if p.Name != newName {
		existing, err := s.store.GetPlayerByName(ctx, newName)
		if err == nil && existing != nil {
			return ErrPlayerNameTaken
		} else if err != nil && !errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("checking name conflict: %w", err)
		}

		p.Name = newName
		now := time.Now()
		p.NameChangedAt = &now

		if err := s.store.UpdatePlayer(ctx, p); err != nil {
			if errors.Is(err, store.ErrConflict) {
				return ErrPlayerNameTaken
			}
			return fmt.Errorf("updating player rename: %w", err)
		}
	}

	return nil
}

// ChangePlayerUUID sets a new profile UUID for an existing player.
//
// This is a destructive identity change: a Minecraft player's UUID is how every
// server keys inventories, permissions and progress, so changing it makes the player
// a different identity to any server it has joined. The new UUID may be provided
// explicitly; an empty value regenerates one according to the configured policy
// (the offline strategy derives it from the player name). The change is rejected if
// the resulting UUID is already taken by another player.
func (s *Service) ChangePlayerUUID(ctx context.Context, playerID, chosenUUID string) (*store.Player, error) {
	p, err := s.store.GetPlayerByID(ctx, playerID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("getting player for uuid change: %w", err)
	}

	var newUUID string
	if chosenUUID != "" {
		parsed, parseErr := uuid.Parse(chosenUUID)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid chosen UUID: %w", ErrInvalidPlayerUUID)
		}
		newUUID = parsed.String()
	} else if s.policy.UUIDGeneration == "offline" {
		newUUID = OfflineUUID(p.Name)
	} else {
		newUUID = randomProfileUUID()
	}

	if newUUID == p.UUID {
		return p, nil
	}

	existing, err := s.store.GetPlayerByUUID(ctx, newUUID)
	if err == nil && existing != nil {
		return nil, ErrPlayerUUIDTaken
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("checking player UUID conflict: %w", err)
	}

	p.UUID = newUUID
	if err := s.store.UpdatePlayer(ctx, p); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return nil, ErrPlayerUUIDTaken
		}
		return nil, fmt.Errorf("updating player uuid: %w", err)
	}

	return p, nil
}

// DeletePlayer deletes a player profile.
func (s *Service) DeletePlayer(ctx context.Context, id string) error {
	if err := s.store.DeletePlayer(ctx, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("deleting player: %w", err)
	}
	return nil
}

// SetPlayerSkin updates the stored skin hash and model for a player.
// skinModel should be "classic" or "slim"; the caller validates the value.
func (s *Service) SetPlayerSkin(ctx context.Context, playerID, skinHash, skinModel string) error {
	p, err := s.store.GetPlayerByID(ctx, playerID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("getting player for skin update: %w", err)
	}
	p.SkinHash = &skinHash
	p.SkinModel = &skinModel
	if err := s.store.UpdatePlayer(ctx, p); err != nil {
		return fmt.Errorf("updating player skin: %w", err)
	}
	return nil
}

// SetPlayerSkinModel changes only the arm model (classic/slim) of a player's existing
// skin, leaving the texture itself untouched. Returns ErrNotFound when the player has
// no skin set. skinModel should be "classic" or "slim"; the caller validates the value.
func (s *Service) SetPlayerSkinModel(ctx context.Context, playerID, skinModel string) error {
	p, err := s.store.GetPlayerByID(ctx, playerID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("getting player for skin model update: %w", err)
	}
	if p.SkinHash == nil {
		return ErrNotFound
	}
	p.SkinModel = &skinModel
	if err := s.store.UpdatePlayer(ctx, p); err != nil {
		return fmt.Errorf("updating player skin model: %w", err)
	}
	return nil
}

// ClearPlayerSkin removes the skin from a player.
func (s *Service) ClearPlayerSkin(ctx context.Context, playerID string) error {
	p, err := s.store.GetPlayerByID(ctx, playerID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("getting player for skin clear: %w", err)
	}
	p.SkinHash = nil
	p.SkinModel = nil
	if err := s.store.UpdatePlayer(ctx, p); err != nil {
		return fmt.Errorf("clearing player skin: %w", err)
	}
	return nil
}

// SetPlayerCape updates the stored cape hash for a player.
func (s *Service) SetPlayerCape(ctx context.Context, playerID, capeHash string) error {
	p, err := s.store.GetPlayerByID(ctx, playerID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("getting player for cape update: %w", err)
	}
	p.CapeHash = &capeHash
	if err := s.store.UpdatePlayer(ctx, p); err != nil {
		return fmt.Errorf("updating player cape: %w", err)
	}
	return nil
}

// ClearPlayerCape removes the cape from a player.
func (s *Service) ClearPlayerCape(ctx context.Context, playerID string) error {
	p, err := s.store.GetPlayerByID(ctx, playerID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("getting player for cape clear: %w", err)
	}
	p.CapeHash = nil
	if err := s.store.UpdatePlayer(ctx, p); err != nil {
		return fmt.Errorf("clearing player cape: %w", err)
	}
	return nil
}

// CreateInvite generates and stores a random invite code.
func (s *Service) CreateInvite(ctx context.Context, adminUserID string, ttl time.Duration) (*store.Invite, error) {
	admin, err := s.store.GetUserByID(ctx, adminUserID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("admin user not found: %w", ErrNotFound)
		}
		return nil, fmt.Errorf("getting admin user: %w", err)
	}
	if !admin.IsAdmin {
		return nil, ErrNotAdmin
	}

	code, err := generateInviteCode()
	if err != nil {
		return nil, fmt.Errorf("generating invite code: %w", err)
	}

	if ttl <= 0 || ttl > maxInviteTTL {
		return nil, ErrInvalidInviteTTL
	}
	expires := time.Now().Add(ttl)
	expiresAt := &expires

	inv := &store.Invite{
		Code:      code,
		CreatedBy: adminUserID,
		UsedBy:    nil,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
	}

	if err := s.store.CreateInvite(ctx, inv); err != nil {
		return nil, fmt.Errorf("saving invite: %w", err)
	}

	return inv, nil
}

// ListInvites lists all generated invites.
func (s *Service) ListInvites(ctx context.Context) ([]*store.Invite, error) {
	invs, err := s.store.ListInvites(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing invites: %w", err)
	}
	return invs, nil
}

// DeleteInvite deletes an invite.
func (s *Service) DeleteInvite(ctx context.Context, code string) error {
	if err := s.store.DeleteInvite(ctx, code); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("deleting invite: %w", err)
	}
	return nil
}

// randomProfileUUID returns a random canonical dashed V4 UUID.
func randomProfileUUID() string {
	return uuid.NewString()
}

// offlineProfileUUID generates the Minecraft offline-mode UUID for a player name.
// This is Java's UUID.nameUUIDFromBytes("OfflinePlayer:" + name).
// It computes the MD5 hash of the ASCII bytes of "OfflinePlayer:" + name,
// then sets the version nibble to 3 and the IETF variant bits,
// formatting as a canonical dashed UUID string.
// This matches the algorithm vanilla servers use in offline mode so migrated players keep their UUID.
func offlineProfileUUID(name string) string {
	hasher := md5.New()
	_, _ = hasher.Write([]byte("OfflinePlayer:" + name))
	hash := hasher.Sum(nil)

	// Set version to 3 (MD5-based UUID)
	hash[6] = (hash[6] & 0x0f) | 0x30
	// Set variant to IETF (RFC 4122)
	hash[8] = (hash[8] & 0x3f) | 0x80

	u, _ := uuid.FromBytes(hash)
	return u.String()
}

// OfflineUUID returns the Minecraft offline-mode UUID for the given player name.
// This is the same deterministic algorithm vanilla offline servers use so callers
// that need to map a name -> UUID without database access can import just this helper.
func OfflineUUID(name string) string {
	return offlineProfileUUID(name)
}

// GetPlayerByOfflineUUID finds the first player whose computed offline UUID matches
// the supplied dashed UUID string. Offline UUIDs are deterministic (MD5 of the name),
// so this lets offline-mode servers resolve skins even when players were created with
// random UUIDs. The scan is O(n) in the player count; acceptable for the typical small
// server this product targets.
func (s *Service) GetPlayerByOfflineUUID(ctx context.Context, dashedUUID string) (*store.Player, error) {
	all, err := s.store.ListAllPlayers(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing all players for offline UUID lookup: %w", err)
	}
	for _, p := range all {
		if offlineProfileUUID(p.Name) == dashedUUID {
			return p, nil
		}
	}
	return nil, ErrNotFound
}

// generateInviteCode creates a cryptographically secure random url-safe string.
func generateInviteCode() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("reading random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// CreatePasswordResetToken creates a single-use password reset token for the user
// and returns the PLAINTEXT token (caller builds the link). Only the hash is stored.
func (s *Service) CreatePasswordResetToken(ctx context.Context, userID string, ttl time.Duration) (string, error) {
	// verify the user exists
	_, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("verifying user exists: %w", err)
	}

	// generate 32 random bytes via crypto/rand -> base64.RawURLEncoding -> plaintext
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating random bytes: %w", err)
	}
	plaintext := base64.RawURLEncoding.EncodeToString(b)

	// hash := sha256 hex of plaintext
	h := sha256.Sum256([]byte(plaintext))
	tokenHash := hex.EncodeToString(h[:])

	// optional housekeeping: DeleteAuthTokensByUser first so only the latest works
	if err := s.store.DeleteAuthTokensByUser(ctx, userID, store.AuthTokenPasswordReset); err != nil {
		return "", fmt.Errorf("deleting old reset tokens: %w", err)
	}

	now := time.Now()
	t := &store.AuthToken{
		TokenHash: tokenHash,
		UserID:    userID,
		Purpose:   store.AuthTokenPasswordReset,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
		UsedAt:    nil,
	}

	if err := s.store.CreateAuthToken(ctx, t); err != nil {
		return "", fmt.Errorf("creating auth token: %w", err)
	}

	return plaintext, nil
}

// ResetPassword consumes a password-reset token and sets a new password.
// Returns the associated userID on success.
func (s *Service) ResetPassword(ctx context.Context, plaintextToken, newPassword string) (string, error) {
	if len(newPassword) < s.policy.MinPasswordLength {
		return "", ErrWeakPassword
	}

	// hash the plaintext token (sha256 hex)
	h := sha256.Sum256([]byte(plaintextToken))
	tokenHash := hex.EncodeToString(h[:])

	tok, err := s.store.GetAuthToken(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "", ErrInvalidToken
		}
		return "", fmt.Errorf("getting auth token: %w", err)
	}

	if tok.Purpose != store.AuthTokenPasswordReset {
		return "", ErrInvalidToken
	}
	if tok.UsedAt != nil {
		return "", ErrInvalidToken
	}
	if time.Now().After(tok.ExpiresAt) {
		return "", ErrInvalidToken
	}

	// ConsumeAuthToken
	if err := s.store.ConsumeAuthToken(ctx, tokenHash); err != nil {
		if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrNotFound) {
			return "", ErrInvalidToken
		}
		return "", fmt.Errorf("consuming auth token: %w", err)
	}

	// load user
	user, err := s.store.GetUserByID(ctx, tok.UserID)
	if err != nil {
		return "", fmt.Errorf("loading user: %w", err)
	}

	// set PasswordHash
	hashed, err := auth.HashPassword(newPassword)
	if err != nil {
		return "", fmt.Errorf("hashing password: %w", err)
	}
	user.PasswordHash = hashed
	user.UpdatedAt = time.Now()

	if err := s.store.UpdateUser(ctx, user); err != nil {
		return "", fmt.Errorf("updating user password: %w", err)
	}

	return tok.UserID, nil
}

// CreateEmailVerifyToken creates a single-use email verification token for the user
// and returns the PLAINTEXT token (caller builds the link). Only the hash is stored.
func (s *Service) CreateEmailVerifyToken(ctx context.Context, userID string, ttl time.Duration) (string, error) {
	// verify the user exists
	_, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("verifying user exists: %w", err)
	}

	// generate 32 random bytes via crypto/rand -> base64.RawURLEncoding -> plaintext
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating random bytes: %w", err)
	}
	plaintext := base64.RawURLEncoding.EncodeToString(b)

	// hash := sha256 hex of plaintext
	h := sha256.Sum256([]byte(plaintext))
	tokenHash := hex.EncodeToString(h[:])

	// housekeeping: DeleteAuthTokensByUser first so only the latest works
	if err := s.store.DeleteAuthTokensByUser(ctx, userID, store.AuthTokenEmailVerify); err != nil {
		return "", fmt.Errorf("deleting old verification tokens: %w", err)
	}

	now := time.Now()
	t := &store.AuthToken{
		TokenHash: tokenHash,
		UserID:    userID,
		Purpose:   store.AuthTokenEmailVerify,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
		UsedAt:    nil,
	}

	if err := s.store.CreateAuthToken(ctx, t); err != nil {
		return "", fmt.Errorf("creating auth token: %w", err)
	}

	return plaintext, nil
}

// VerifyEmail consumes an email verification token and sets EmailVerified = true on the user.
// Returns the associated userID on success.
func (s *Service) VerifyEmail(ctx context.Context, plaintextToken string) (string, error) {
	// hash the plaintext token (sha256 hex)
	h := sha256.Sum256([]byte(plaintextToken))
	tokenHash := hex.EncodeToString(h[:])

	tok, err := s.store.GetAuthToken(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "", ErrInvalidToken
		}
		return "", fmt.Errorf("getting auth token: %w", err)
	}

	if tok.Purpose != store.AuthTokenEmailVerify {
		return "", ErrInvalidToken
	}
	if tok.UsedAt != nil {
		return "", ErrInvalidToken
	}
	if time.Now().After(tok.ExpiresAt) {
		return "", ErrInvalidToken
	}

	// ConsumeAuthToken
	if err := s.store.ConsumeAuthToken(ctx, tokenHash); err != nil {
		if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrNotFound) {
			return "", ErrInvalidToken
		}
		return "", fmt.Errorf("consuming auth token: %w", err)
	}

	// load user
	user, err := s.store.GetUserByID(ctx, tok.UserID)
	if err != nil {
		return "", fmt.Errorf("loading user: %w", err)
	}

	// set EmailVerified = true
	user.EmailVerified = true
	user.UpdatedAt = time.Now()

	if err := s.store.UpdateUser(ctx, user); err != nil {
		return "", fmt.Errorf("updating user email verification: %w", err)
	}

	return tok.UserID, nil
}

// GetUserByEmail retrieves an existing user by their email address.
func (s *Service) GetUserByEmail(ctx context.Context, email string) (*store.User, error) {
	u, err := s.store.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("getting user by email: %w", err)
	}
	return u, nil
}

// BeginTOTPSetup generates a new TOTP secret for the user (NOT yet enabled) and
// returns the otpauth:// provisioning URI and the base32 secret.
func (s *Service) BeginTOTPSetup(ctx context.Context, userID string) (string, string, error) {
	user, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "", "", ErrNotFound
		}
		return "", "", fmt.Errorf("getting user: %w", err)
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "minecrauth",
		AccountName: user.Email,
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to generate TOTP key: %w", err)
	}

	user.TOTPSecret = key.Secret()
	user.TOTPEnabled = false
	user.UpdatedAt = time.Now()

	if err := s.store.UpdateUser(ctx, user); err != nil {
		return "", "", fmt.Errorf("updating user: %w", err)
	}

	return key.URL(), key.Secret(), nil
}

// ConfirmTOTP validates a code against the pending secret; on success sets
// TOTPEnabled=true, generates N=10 single-use recovery codes, stores their SHA-256
// hashes, and returns the PLAINTEXT recovery codes.
func (s *Service) ConfirmTOTP(ctx context.Context, userID, code string) ([]string, error) {
	user, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("getting user: %w", err)
	}

	if user.TOTPSecret == "" {
		return nil, ErrTOTPNotPending
	}

	if !totp.Validate(code, user.TOTPSecret) {
		return nil, ErrInvalidTOTP
	}

	user.TOTPEnabled = true
	user.UpdatedAt = time.Now()

	if err := s.store.UpdateUser(ctx, user); err != nil {
		return nil, fmt.Errorf("updating user: %w", err)
	}

	plaintextCodes := make([]string, 10)
	hashedCodes := make([]string, 10)
	for i := 0; i < 10; i++ {
		b := make([]byte, 5)
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("generating recovery codes: %w", err)
		}
		codeVal := hex.EncodeToString(b)
		plaintextCodes[i] = codeVal

		h := sha256.Sum256([]byte(codeVal))
		hashedCodes[i] = hex.EncodeToString(h[:])
	}

	if err := s.store.DeleteRecoveryCodes(ctx, userID); err != nil {
		return nil, fmt.Errorf("deleting old recovery codes: %w", err)
	}

	if err := s.store.CreateRecoveryCodes(ctx, userID, hashedCodes); err != nil {
		return nil, fmt.Errorf("storing recovery codes: %w", err)
	}

	return plaintextCodes, nil
}

// DisableTOTP turns 2FA off after verifying a current TOTP code OR a recovery code.
// Clears TOTPSecret, sets TOTPEnabled=false, deletes recovery codes.
func (s *Service) DisableTOTP(ctx context.Context, userID, codeOrRecovery string) error {
	user, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("getting user: %w", err)
	}

	if !user.TOTPEnabled {
		return ErrTOTPNotEnabled
	}

	// Try TOTP code first
	valid := totp.Validate(codeOrRecovery, user.TOTPSecret)
	if !valid {
		// Try recovery code: hash the input and attempt ConsumeRecoveryCode
		h := sha256.Sum256([]byte(codeOrRecovery))
		hashHex := hex.EncodeToString(h[:])
		err = s.store.ConsumeRecoveryCode(ctx, userID, hashHex)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return ErrInvalidTOTP
			}
			return fmt.Errorf("consuming recovery code: %w", err)
		}
	}

	user.TOTPSecret = ""
	user.TOTPEnabled = false
	user.UpdatedAt = time.Now()

	if err := s.store.UpdateUser(ctx, user); err != nil {
		return fmt.Errorf("updating user: %w", err)
	}

	if err := s.store.DeleteRecoveryCodes(ctx, userID); err != nil {
		return fmt.Errorf("deleting recovery codes: %w", err)
	}

	return nil
}

// VerifyTOTP returns nil if code is a valid current TOTP code for the user's enabled
// secret OR a valid unused recovery code (which it then consumes).
func (s *Service) VerifyTOTP(ctx context.Context, userID, code string) error {
	user, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("getting user: %w", err)
	}

	if !user.TOTPEnabled {
		return ErrTOTPNotEnabled
	}

	if totp.Validate(code, user.TOTPSecret) {
		return nil
	}

	h := sha256.Sum256([]byte(code))
	hashHex := hex.EncodeToString(h[:])
	err = s.store.ConsumeRecoveryCode(ctx, userID, hashHex)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrInvalidTOTP
		}
		return fmt.Errorf("consuming recovery code: %w", err)
	}

	return nil
}

// AdminDisableTOTP force-disables without a code (for the impersonation/admin path).
func (s *Service) AdminDisableTOTP(ctx context.Context, userID string) error {
	user, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("getting user: %w", err)
	}

	user.TOTPSecret = ""
	user.TOTPEnabled = false
	user.UpdatedAt = time.Now()

	if err := s.store.UpdateUser(ctx, user); err != nil {
		return fmt.Errorf("updating user: %w", err)
	}

	if err := s.store.DeleteRecoveryCodes(ctx, userID); err != nil {
		return fmt.Errorf("deleting recovery codes: %w", err)
	}

	return nil
}

// CreateTOTPPendingToken creates a short-lived pending login token.
func (s *Service) CreateTOTPPendingToken(ctx context.Context, userID string, ttl time.Duration) (string, error) {
	_, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("verifying user exists: %w", err)
	}

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating random bytes: %w", err)
	}
	plaintext := base64.RawURLEncoding.EncodeToString(b)

	h := sha256.Sum256([]byte(plaintext))
	tokenHash := hex.EncodeToString(h[:])

	if err := s.store.DeleteAuthTokensByUser(ctx, userID, store.AuthTokenTOTPPending); err != nil {
		return "", fmt.Errorf("deleting old totp pending tokens: %w", err)
	}

	now := time.Now()
	t := &store.AuthToken{
		TokenHash: tokenHash,
		UserID:    userID,
		Purpose:   store.AuthTokenTOTPPending,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
		UsedAt:    nil,
	}

	if err := s.store.CreateAuthToken(ctx, t); err != nil {
		return "", fmt.Errorf("creating auth token: %w", err)
	}

	return plaintext, nil
}

// ValidateTOTPPendingToken validates a pending TOTP token and returns the userID on success.
// It does NOT consume the token.
func (s *Service) ValidateTOTPPendingToken(ctx context.Context, plaintextToken string) (string, error) {
	h := sha256.Sum256([]byte(plaintextToken))
	tokenHash := hex.EncodeToString(h[:])

	tok, err := s.store.GetAuthToken(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "", ErrInvalidToken
		}
		return "", fmt.Errorf("getting auth token: %w", err)
	}

	if tok.Purpose != store.AuthTokenTOTPPending {
		return "", ErrInvalidToken
	}
	if tok.UsedAt != nil {
		return "", ErrInvalidToken
	}
	if time.Now().After(tok.ExpiresAt) {
		return "", ErrInvalidToken
	}

	return tok.UserID, nil
}

// ConsumeTOTPPendingToken consumes a pending TOTP token.
func (s *Service) ConsumeTOTPPendingToken(ctx context.Context, plaintextToken string) error {
	h := sha256.Sum256([]byte(plaintextToken))
	tokenHash := hex.EncodeToString(h[:])

	if err := s.store.ConsumeAuthToken(ctx, tokenHash); err != nil {
		if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrNotFound) {
			return ErrInvalidToken
		}
		return fmt.Errorf("consuming auth token: %w", err)
	}

	return nil
}
