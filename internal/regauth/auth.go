package regauth

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/docker/libtrust"
	uuid "github.com/satori/go.uuid"
)

// Token rep the JWT token that'll be created when authentication/authorizations succeeds.
//nolint:tagliatelle // matching docker/distribution requirements.
type Token struct {
	Token       string `json:"token"`
	AccessToken string `json:"access_token"`
}

// Authenticator should be implemented to perform authentication.
// An implementation should return a non-nil error when authentication is not successful, otherwise
// a nil error should be returned.
type Authenticator interface {
	Authenticate(req *AuthorizationRequest, username, password string) error
}

// Authorizer should be implemented to perform authorization.
// req.Actions should be checked against the user's authorized action on the repository,
// this function should return the list of authorized actions and a nil error. an empty list must be returned
// if requesting user is unauthorized.
type Authorizer interface {
	Authorize(req *AuthorizationRequest) ([]string, error)
}

// TokenGenerator an implementation should create a valid JWT according to the spec here
// https://github.com/docker/distribution/blob/1b9ab303a477ded9bdd3fc97e9119fa8f9e58fca/docs/spec/auth/jwt.md
// a default implementation that follows the spec is used when it is not provided.
type TokenGenerator interface {
	Generate(req *AuthorizationRequest, actions []string) (*Token, error)
}

// DefaultAuthenticator makes authentication successful by default.
type DefaultAuthenticator struct{}

// Authenticate is the default authenticator (allows any authentication request).
func (d *DefaultAuthenticator) Authenticate(req *AuthorizationRequest, username, password string) error {
	return nil
}

// DefaultAuthorizer makes authorization successful by default.
type DefaultAuthorizer struct{}

// Authorize returns the default set of abilities for an AuthorizationRequest.
func (d *DefaultAuthorizer) Authorize(req *AuthorizationRequest) ([]string, error) {
	return []string{"pull", "push"}, nil
}

type tokenGenerator struct {
	privateKey libtrust.PrivateKey
	pubKey     libtrust.PublicKey
	tokenOpt   *TokenOption
}

func newTokenGenerator(pk libtrust.PublicKey, prk libtrust.PrivateKey, opt *TokenOption) TokenGenerator {
	return &tokenGenerator{pubKey: pk, privateKey: prk, tokenOpt: opt}
}

func (tg *tokenGenerator) Generate(req *AuthorizationRequest, actions []string) (*Token, error) {
	// sign any string to get the used signing Algorithm for the private key
	_, algo, err := tg.privateKey.Sign(strings.NewReader(signAuth), 0)
	if err != nil {
		return nil, fmt.Errorf("unable to sign authorization request: %w", err)
	}

	header := Header{
		Type:       "JWT",
		SigningAlg: algo,
		KeyID:      tg.pubKey.KeyID(),
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal JSON: %w", err)
	}

	now := time.Now().Unix()
	claim := ClaimSet{
		Issuer:     tg.tokenOpt.Issuer,
		Subject:    req.Account,
		Audience:   req.Service,
		Expiration: now + tg.tokenOpt.Expire,
		NotBefore:  now - defaultNotBeforeLeeway,
		IssuedAt:   now,
		JWTID:      uuid.Must(uuid.NewV4()).String(),
		Access:     []*ResourceActions{},
	}
	claim.Access = append(claim.Access, &ResourceActions{
		Type:    req.Type,
		Name:    req.Name,
		Actions: actions,
	})

	claimJSON, err := json.Marshal(claim)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal JSON: %w", err)
	}

	payload := fmt.Sprintf("%s%s%s", encodeBase64(headerJSON), TokenSeparator, encodeBase64(claimJSON))

	sig, sigAlgo, err := tg.privateKey.Sign(strings.NewReader(payload), 0)
	if err != nil && sigAlgo != algo {
		return nil, fmt.Errorf("unable to sign payload: %w", err)
	}

	tk := fmt.Sprintf("%s%s%s", payload, TokenSeparator, encodeBase64(sig))

	return &Token{Token: tk, AccessToken: tk}, nil
}

func loadCertAndKey(certFile, keyFile string) (libtrust.PublicKey, libtrust.PrivateKey, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to load keypair: %w", err)
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse certificates: %w", err)
	}

	pk, err := libtrust.FromCryptoPublicKey(x509Cert.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to build public key from x509.PublicKey: %w", err)
	}

	prk, err := libtrust.FromCryptoPrivateKey(cert.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to build private key from x509.PublicKey.PrivateKey: %w", err)
	}

	return pk, prk, nil
}
