package authitem

import "crypto/subtle"

// AuthItem is a single authentication item for use with legacy auth.
type AuthItem struct {
	Username []byte
	Password []byte
}

// NewAuthItem returns a new AuthItem from a username and password combination.
func NewAuthItem(username, password string) *AuthItem {
	return &AuthItem{
		Username: []byte(username),
		Password: []byte(password),
	}
}

// Authenticate attempts to authenticate a password against an AuthItem.
func (i *AuthItem) Authenticate(pw []byte) bool {
	return (subtle.ConstantTimeCompare(i.Password, pw) == 1)
}
