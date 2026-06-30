// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

package auth

import "errors"

// Sentinel errors that callers can branch on with errors.Is.
var (
	// ErrInvalidCredentials is returned when an email/password pair does not authenticate.
	ErrInvalidCredentials = errors.New("invalid credentials")

	// ErrEmailNotVerified is returned when a user tries to authenticate but their email is not verified.
	ErrEmailNotVerified = errors.New("email address not verified")

	// ErrTokenInvalid is returned when a token does not exist or the clientToken does not match.
	ErrTokenInvalid = errors.New("token invalid")

	// ErrTokenExpired is returned when a token exists but has passed its expiry time.
	ErrTokenExpired = errors.New("token expired")

	// ErrProfileNotOwned is returned when a refresh request selects a profile that
	// does not belong to the token's user (or does not exist).
	ErrProfileNotOwned = errors.New("selected profile does not belong to the token's user")

	// ErrInvalidSession is returned when a browser session token is missing, expired, or invalid.
	ErrInvalidSession = errors.New("invalid or expired session")
)
