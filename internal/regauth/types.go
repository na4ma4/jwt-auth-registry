package regauth

// Option is the registry token authorization server configuration options.
type Option struct {
	// Authorizer is an Authorizer implementation to authorize registry users.
	Authorizer Authorizer
	// Authenticator is an Authenticator implementation to authenticate registry users.
	Authenticator Authenticator
	// TokenGenerator is the pluggable TokenGenerator.
	TokenGenerator TokenGenerator
	// Certfile .crt & .key file to sign JWT tokens.
	Certfile string
	// Keyfile .crt & .key file to sign JWT tokens.
	Keyfile string
	// TokenExpiration is the token expiration time.
	TokenExpiration int64
	// TokenIssuer is the token issuer specified in docker registry configuration file.
	TokenIssuer string
}

// TokenOption is the options used on a token.
type TokenOption struct {
	Expire int64
	Issuer string
}

// AuthorizationRequest is the authorization request data.
type AuthorizationRequest struct {
	Account string
	Service string
	Type    string
	Name    string
	IP      string
	Actions []string
}
