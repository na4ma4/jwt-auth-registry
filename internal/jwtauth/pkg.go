// Package jwtauth is an authentication function to be used by the httpauth package
//
// it has a background runner and channel plus caching for authentication request
package jwtauth

import "errors"

var (
	// ErrInvalidToken is returned when a token is invalid.
	ErrInvalidToken = errors.New("invalid token")

	// ErrUsernameIsEmpty is used for debug reporting.
	ErrUsernameIsEmpty = errors.New("username is empty")
)
