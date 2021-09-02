package jwtauth

import (
	"strings"

	"github.com/na4ma4/jwt-auth-registry/internal/authitem"
	"github.com/na4ma4/jwt-auth-registry/internal/regauth"
	"github.com/na4ma4/jwt/v2"
)

// Basic is a JWT authentication helper for use with regauth.Server.
type Basic struct {
	v      jwt.Verifier
	legacy authitem.Store
}

// NewBasic returns a new Basic Authentication helper.
func NewBasic(v jwt.Verifier, legacy authitem.Store) *Basic {
	return &Basic{
		v:      v,
		legacy: legacy,
	}
}

// Authenticate tests a username and password against a legacy user set and then attempts
// to use them as tokens, if the token is parsed but has an empty subject field, it returns an error.
func (b *Basic) Authenticate(req *regauth.AuthorizationRequest, username, password string) (err error) {
	if b.legacy.Authenticate(username, password) {
		return nil
	}

	var result jwt.VerifyResult

	if result, err = b.v.Verify([]byte(password)); err != nil {
		if result, err = b.v.Verify([]byte(username)); err != nil {
			return ErrInvalidToken
		}
	}

	if strings.EqualFold(result.Subject, "") {
		return ErrUsernameIsEmpty
	}

	req.Account = result.Subject

	return nil
}
