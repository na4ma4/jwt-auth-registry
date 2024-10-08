package regauth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

const (
	signAuth            = "AUTH"
	defaultReadTimeout  = 10 * time.Second
	defaultWriteTimeout = 10 * time.Second
	defaultIdleTimeout  = 10 * time.Second
)

// AuthServer is the token authentication server.
type AuthServer struct {
	logger         *zap.Logger
	authorizer     Authorizer
	authenticator  Authenticator
	tokenGenerator TokenGenerator
	httpServer     *http.Server
	httpMux        *http.ServeMux
}

// NewAuthServer creates a new AuthServer.
func NewAuthServer(logger *zap.Logger, opt *Option) (*AuthServer, error) {
	if opt.Authenticator == nil {
		opt.Authenticator = &DefaultAuthenticator{}
	}

	if opt.Authorizer == nil {
		opt.Authorizer = &DefaultAuthorizer{}
	}

	pb, prk, err := loadCertAndKey(opt.Certfile, opt.Keyfile)
	if err != nil {
		return nil, err
	}

	tk := &TokenOption{Expire: opt.TokenExpiration, Issuer: opt.TokenIssuer}
	if opt.TokenGenerator == nil {
		opt.TokenGenerator = newTokenGenerator(pb, prk, tk)
	}

	mux := http.NewServeMux()
	srv := &http.Server{
		ReadTimeout:  defaultReadTimeout,
		WriteTimeout: defaultWriteTimeout,
		IdleTimeout:  defaultIdleTimeout,
		Handler:      mux,
	}

	return &AuthServer{
		logger:         logger,
		authorizer:     opt.Authorizer,
		authenticator:  opt.Authenticator,
		tokenGenerator: opt.TokenGenerator,
		httpServer:     srv,
		httpMux:        mux,
	}, nil
}

func (srv *AuthServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	req := srv.parseRequest(r)

	// grab user's auth parameters
	username, password, ok := r.BasicAuth()
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)

		return
	}

	if err := srv.authenticator.Authenticate(req, username, password); err != nil {
		http.Error(w, "unauthorized: invalid auth credentials", http.StatusUnauthorized)

		return
	}

	actions, err := srv.authorizer.Authorize(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)

		return
	}
	// create token for this user using the actions returned
	// from the authorization check
	tk, err := srv.tokenGenerator.Generate(req, actions)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)

		return
	}

	r.Header.Set("X-Logging-Username", req.Account)
	srv.logger.Info("authorization granted",
		zap.String("docker.auth.account", req.Account),
		zap.String("docker.auth.service", req.Service),
		zap.String("docker.auth.type", req.Type),
		zap.String("docker.auth.name", req.Name),
		zap.Strings("docker.auth.actions", req.Actions),
	)

	srv.ok(w, tk)
}

//nolint:mnd // segmenting request token
func (srv *AuthServer) parseRequest(r *http.Request) *AuthorizationRequest {
	q := r.URL.Query()
	req := &AuthorizationRequest{
		Service: q.Get("service"),
		Account: q.Get("account"),
	}

	parts := strings.Split(r.URL.Query().Get("scope"), ":")
	if len(parts) > 0 {
		req.Type = parts[0]
	}

	if len(parts) > 1 {
		req.Name = parts[1]
	}

	if len(parts) > 2 {
		req.Actions = strings.Split(parts[2], ",")
	}

	if req.Account == "" {
		req.Account = req.Name
	}

	return req
}

// Run is the method that starts the HTTP server and blocks until it is finished.
func (srv *AuthServer) Run(addr string) error {
	srv.httpMux.Handle("/", srv)
	// fmt.Printf("Authentication server running at %s", addr)

	srv.httpServer.Addr = addr

	if err := srv.httpServer.ListenAndServe(); err != nil {
		return fmt.Errorf("http server returned error: %w", err)
	}

	return nil
}

func (srv *AuthServer) ok(w http.ResponseWriter, tk *Token) {
	data, _ := json.Marshal(tk)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func encodeBase64(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}
