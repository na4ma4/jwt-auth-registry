package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/na4ma4/config"
	"github.com/na4ma4/go-httplog"
	"github.com/na4ma4/jwt-auth-registry/internal/authitem"
	"github.com/na4ma4/jwt-auth-registry/internal/jwtauth"
	"github.com/na4ma4/jwt-auth-registry/internal/mainconfig"
	"github.com/na4ma4/jwt-auth-registry/internal/regauth"
	"github.com/na4ma4/jwt/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

//nolint:gochecknoglobals // cobra uses globals in main
var rootCmd = &cobra.Command{
	Use: "jwt-auth-registry-tokenprovider",
	Run: mainCommand,
}

//nolint:gochecknoinits,gomnd // init is used in main for cobra
func init() {
	cobra.OnInitialize(mainconfig.ConfigInit)

	rootCmd.PersistentFlags().StringP("audience", "a", "tls-web-client-auth", "Authentication Token Audience")
	_ = viper.BindPFlag("server.auth.audience", rootCmd.PersistentFlags().Lookup("audience"))
	_ = viper.BindEnv("server.auth.audience", "AUDIENCE")

	rootCmd.PersistentFlags().StringP("issuer", "i", "docker-registry-auth-token", "Registry Token issuer")
	_ = viper.BindPFlag("server.sign.issuer", rootCmd.PersistentFlags().Lookup("issuer"))
	_ = viper.BindEnv("server.sign.issuer", "ISSUER")

	rootCmd.PersistentFlags().IntP("port", "p", 80, "HTTP Port")
	_ = viper.BindPFlag("server.port", rootCmd.PersistentFlags().Lookup("port"))
	_ = viper.BindEnv("server.port", "HTTP_PORT")

	rootCmd.PersistentFlags().StringSliceP(
		"legacy-user",
		"l",
		[]string{},
		"List of legacy users (username:password) that can authenticate, designed "+
			"for allowing migration from a system with an old common login (allows it to work *temporarily*)",
	)

	_ = viper.BindPFlag("server.legacy-users", rootCmd.PersistentFlags().Lookup("legacy-user"))
	_ = viper.BindEnv("server.legacy-users", "LEGACY_USERS")

	rootCmd.PersistentFlags().BoolP("debug", "d", false, "Debug output")
	_ = viper.BindPFlag("debug", rootCmd.PersistentFlags().Lookup("debug"))
	_ = viper.BindEnv("debug", "DEBUG")

	rootCmd.PersistentFlags().Bool("watchdog", false, "Enable systemd watchdog functionality")
	_ = viper.BindPFlag("watchdog.enabled", rootCmd.PersistentFlags().Lookup("watchdog"))
	_ = viper.BindEnv("watchdog.enabled", "WATCHDOG")
}

func main() {
	_ = rootCmd.Execute()
}

func showHelp(cmd *cobra.Command) {
	_ = cmd.Help()
}

func verifierOrBust(cmd *cobra.Command, cfg config.Conf, logger *zap.Logger) jwt.Verifier {
	var (
		verifier jwt.Verifier
		err      error
	)

	if verifier, err = jwt.NewRSAVerifierFromFile(
		cfg.GetStringSlice("server.auth.audience"),
		cfg.GetString("server.auth.ca"),
	); err != nil {
		logger.Error("starting jwt verifier", zap.Error(err))
		showHelp(cmd)
		os.Exit(1)
	}

	return verifier
}

func mainCommand(cmd *cobra.Command, args []string) {
	cfg := config.NewViperConfigFromViper(viper.GetViper(), "jwtauth")

	logger, _ := cfg.ZapConfig().Build()
	defer logger.Sync() //nolint:errcheck

	verifier := verifierOrBust(cmd, cfg, logger)
	legacyUsers := authitem.NewStoreFromCLI(cfg.GetStringSlice("server.legacy-users"))

	rs, err := regauth.NewAuthServer(logger, &regauth.Option{
		Authenticator: jwtauth.NewBasic(verifier, legacyUsers),
		Certfile:      cfg.GetString("server.sign.cert"),
		Keyfile:       cfg.GetString("server.sign.key"),
		TokenIssuer:   cfg.GetString("server.sign.issuer"),
	})
	if err != nil {
		logger.Panic("unable to create registry auth server", zap.Error(err))
	}

	s := http.NewServeMux()

	s.Handle("/", httplog.LoggingHandler(logger, rs))

	bindAddr := fmt.Sprintf("%s:%d", cfg.GetString("server.address"), cfg.GetInt("server.port"))

	logger.Debug("starting server",
		zap.String("audience", cfg.GetString("server.auth.audience")),
		zap.String("bind-addr", bindAddr),
		zap.String("proxy-uri", cfg.GetString("server.backend-uri")),
	)

	if err := http.ListenAndServe(bindAddr, s); err != nil {
		logger.Fatal("HTTP Server Error", zap.Error(err))
	}
}
