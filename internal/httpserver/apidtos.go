// Copyright 2025 - Alby Hernández and the minecrauth contributors
// SPDX-License-Identifier: Apache-2.0

package httpserver

// RegisterRequest defines the JSON body for self-service registration.
type RegisterRequest struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	InviteCode string `json:"inviteCode"`
}

// UpdateEmailRequest defines the JSON body for updating the current user's email.
type UpdateEmailRequest struct {
	Email string `json:"email"`
}

// UpdatePasswordRequest defines the JSON body for updating the current user's password.
type UpdatePasswordRequest struct {
	Password string `json:"password"`
}

// CreatePlayerRequest defines the JSON body for creating a Minecraft player profile.
type CreatePlayerRequest struct {
	Name string `json:"name"`
	UUID string `json:"uuid"`
}

// RenamePlayerRequest defines the JSON body for renaming a Minecraft player profile.
type RenamePlayerRequest struct {
	Name string `json:"name"`
}

// ChangePlayerUUIDRequest defines the JSON body for changing a player's profile UUID.
// An empty uuid regenerates one according to the configured generation policy.
type ChangePlayerUUIDRequest struct {
	UUID string `json:"uuid"`
}

// SetSkinModelRequest defines the JSON body for overriding a skin's arm model.
type SetSkinModelRequest struct {
	Model string `json:"model"`
}

// AdminCreateUserRequest defines the JSON body for admin-created users.
type AdminCreateUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	IsAdmin  bool   `json:"isAdmin"`
}

// SetAdminRequest defines the JSON body for setting a user's admin privilege level.
type SetAdminRequest struct {
	IsAdmin bool `json:"isAdmin"`
}

// SetBlockedRequest defines the JSON body for blocking or unblocking a user.
type SetBlockedRequest struct {
	Blocked bool `json:"blocked"`
}

// CreateInviteRequest defines the JSON body for creating registration invites.
type CreateInviteRequest struct {
	TTLSeconds int `json:"ttlSeconds"`
}

// LoginRequest defines the JSON body for browser UI login.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// SkinURLRequest defines the JSON body for setting player skins from an external URL.
type SkinURLRequest struct {
	URL   string `json:"url"`
	Model string `json:"model"`
}

// CapeURLRequest defines the JSON body for setting player capes from an external URL.
type CapeURLRequest struct {
	URL string `json:"url"`
}

// ResetTokenResponse defines the JSON body returned when an admin creates a password reset token.
type ResetTokenResponse struct {
	ResetURL         string `json:"resetUrl"`
	ExpiresInSeconds int    `json:"expiresInSeconds"`
}

// ResetPasswordRequest defines the JSON body for resetting a user's password using a token.
type ResetPasswordRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

// ForgotPasswordRequest defines the JSON body for requesting a password reset email.
type ForgotPasswordRequest struct {
	Email string `json:"email"`
}

// VerifyEmailRequest defines the JSON body for verifying an email using a token.
type VerifyEmailRequest struct {
	Token string `json:"token"`
}

// ResendVerificationRequest defines the JSON body for requesting a new verification email.
type ResendVerificationRequest struct {
	Email string `json:"email"`
}

// SetGamePasswordRequest defines the JSON body for updating the current user's dedicated game password.
type SetGamePasswordRequest struct {
	Password string `json:"password"`
}

// LoginTOTPRequest defines the JSON body for TOTP-based web login.
type LoginTOTPRequest struct {
	TotpToken string `json:"totpToken"`
	Code      string `json:"code"`
}

// TOTPConfirmRequest defines the JSON body for confirming TOTP setup.
type TOTPConfirmRequest struct {
	Code string `json:"code"`
}

// TOTPDisableRequest defines the JSON body for disabling TOTP.
type TOTPDisableRequest struct {
	Code string `json:"code"`
}
