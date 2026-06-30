// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"github.com/achetronic/minecrauth/internal/accounts"
	"github.com/achetronic/minecrauth/internal/auth"
	"github.com/achetronic/minecrauth/internal/backup"
	"github.com/achetronic/minecrauth/internal/config"
	"github.com/achetronic/minecrauth/internal/fallback"
	"github.com/achetronic/minecrauth/internal/httpserver"
	"github.com/achetronic/minecrauth/internal/logging"
	"github.com/achetronic/minecrauth/internal/mailer"
	"github.com/achetronic/minecrauth/internal/signing"
	"github.com/achetronic/minecrauth/internal/store"
	sqlitestore "github.com/achetronic/minecrauth/internal/store/sqlite"
	"github.com/achetronic/minecrauth/internal/textures"
	"github.com/achetronic/minecrauth/internal/yggdrasil"
)

// Build metadata, stamped by goreleaser ldflags (-X main.Version, etc.).
// Defaults apply for non-release builds (e.g. go build, make build).
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// @title           minecrauth API
// @version         1.0
// @description     Yggdrasil-compatible Minecraft authentication server. Management endpoints accept either an HTTP Basic credential or a browser session cookie; cookie-authenticated mutating requests also require the X-CSRF-Token header.
// @license.name    Apache-2.0
// @license.url     https://www.apache.org/licenses/LICENSE-2.0
// @BasePath        /
// @securityDefinitions.basic  BasicAuth
// @securityDefinitions.apikey CSRFToken
// @in              header
// @name            X-CSRF-Token
func main() {
	// Set up structured logging as early as possible.
	logger := logging.Setup("", "")
	slog.SetDefault(logger)

	slog.Info("initializing minecrauth server")
	slog.Info("build info", "version", Version, "commit", Commit, "date", Date)

	configPath := flag.String("config", "", "path to the YAML configuration file (required)")
	flag.Parse()
	if *configPath == "" {
		slog.Error("the --config flag is required", "example", "minecrauth --config /etc/minecrauth/config.yaml")
		os.Exit(1)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	// Reconfigure structured logging based on loaded configuration.
	logger = logging.Setup(cfg.LogFormat, cfg.LogLevel)
	slog.SetDefault(logger)

	slog.Info("configuration loaded",
		"config_path", *configPath,
		"base_url", cfg.BaseURL,
		"domain", cfg.Domain,
		"listen_addr", cfg.ListenAddr,
		"state_dir", cfg.StateDir,
		"server_name", cfg.ServerName,
		"yggdrasil_prefix", cfg.YggdrasilPrefix,
		"api_prefix", cfg.ApiPrefix,
		"admin_prefix", cfg.AdminPrefix,
		"require_invite", cfg.RequireInvite,
		"max_players_per_user", cfg.MaxPlayersPerUser,
		"uuid_generation", cfg.UUIDGeneration,
		"oidc_enabled", cfg.OIDCIssuer != "",
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Ensure StateDir exists before handling restore
	if err := os.MkdirAll(cfg.StateDir, 0o755); err != nil {
		slog.Error("failed to create state directory", "path", cfg.StateDir, "error", err)
		os.Exit(1)
	}

	pendingPath := filepath.Join(cfg.StateDir, ".restore-pending.tar.gz")
	if _, statErr := os.Stat(pendingPath); statErr == nil {
		slog.Warn("applying pending restore before startup", "archive", pendingPath)
		f, openErr := os.Open(pendingPath)
		if openErr != nil {
			slog.Error("opening pending restore", "error", openErr)
			os.Exit(1)
		}
		applyErr := backup.Apply(f, cfg.StateDir, *configPath)
		_ = f.Close()
		if applyErr != nil {
			slog.Error("applying pending restore", "error", applyErr)
			os.Exit(1)
		}
		if rmErr := os.Remove(pendingPath); rmErr != nil {
			slog.Warn("removing pending restore marker", "error", rmErr)
		}
		slog.Info("pending restore applied; continuing startup")
	}

	// SQLite database.
	dbPath := filepath.Join(cfg.StateDir, "minecrauth.db")
	st, err := sqlitestore.New(dbPath)
	if err != nil {
		slog.Error("failed to open database", "path", dbPath, "error", err)
		os.Exit(1)
	}
	defer func() {
		if err := st.Close(); err != nil {
			slog.Error("closing database", "error", err)
		}
	}()

	if err := st.Migrate(ctx); err != nil {
		slog.Error("database migration failed", "error", err)
		os.Exit(1)
	}
	slog.Info("database migrations applied")

	// RSA signing key used for Yggdrasil profile-property signatures.
	keyPath := filepath.Join(cfg.StateDir, "signing.key")
	km, err := signing.New(keyPath)
	if err != nil {
		slog.Error("failed to initialize signing key", "path", keyPath, "error", err)
		os.Exit(1)
	}

	// Build the accounts service first – the OIDC auto-provisioner adapter needs it.
	ttl := time.Duration(cfg.TokenExpirySeconds) * time.Second
	tokenSvc := auth.NewTokenService(st, ttl, nil)

	nameRegex := regexp.MustCompile(cfg.PlayerNameRegex)
	svc := accounts.NewService(st, accounts.Policy{
		MinPasswordLength:        cfg.MinPasswordLength,
		MaxPlayersPerUser:        cfg.MaxPlayersPerUser,
		PlayerNameRegex:          nameRegex,
		UUIDGeneration:           cfg.UUIDGeneration,
		RequireInvite:            cfg.RequireInvite,
		RequireEmailVerification: cfg.RequireEmailVerification,
	})

	// Bootstrap DefaultAdmins before opening the HTTP port.
	if len(cfg.DefaultAdmins) > 0 {
		ensureDefaultAdmins(ctx, svc, st, cfg.DefaultAdmins)
	}

	// Management-plane authenticator.
	// Password authentication is always active (local bcrypt hash).
	// OIDC is layered on top when configured – off by default (per DECISIONS.md).
	passwordAuthn := auth.NewPasswordAuthenticator(st)
	var authn auth.Authenticator = passwordAuthn

	var oidcBrowser *auth.OIDCBrowserFlow
	if cfg.OIDCIssuer != "" {
		slog.Info("OIDC authentication enabled; running discovery",
			"issuer", cfg.OIDCIssuer,
			"auto_provision", cfg.OIDCAutoProvision,
		)
		prov := &oidcProvisioner{svc: svc}
		oidcAuthn, oidcErr := auth.NewOIDCAuthenticator(
			ctx,
			cfg.OIDCIssuer,
			cfg.OIDCClientID,
			st,
			cfg.OIDCAutoProvision,
			prov,
		)
		if oidcErr != nil {
			slog.Error("failed to initialize OIDC authenticator; verify oidc_issuer is reachable",
				"issuer", cfg.OIDCIssuer,
				"error", oidcErr,
			)
			os.Exit(1)
		}
		authn = auth.NewCompositeAuthenticator(passwordAuthn, oidcAuthn)
		slog.Info("composite authenticator active (local password + OIDC ID token)")

		if cfg.OIDCClientSecret != "" {
			var oidcBrowserErr error
			oidcBrowser, oidcBrowserErr = auth.NewOIDCBrowserFlow(
				ctx,
				cfg.OIDCIssuer,
				cfg.OIDCClientID,
				cfg.OIDCClientSecret,
				cfg.OIDCRedirectURL,
				st,
				cfg.OIDCAutoProvision,
				prov,
			)
			if oidcBrowserErr != nil {
				slog.Error("failed to initialize OIDC browser flow; verify oidc_issuer is reachable",
					"issuer", cfg.OIDCIssuer,
					"error", oidcBrowserErr,
				)
				os.Exit(1)
			}
			slog.Info("OIDC browser login enabled", "redirect_url", cfg.OIDCRedirectURL)
		} else {
			slog.Warn("OIDC browser login disabled (set oidc_client_secret)")
		}
	} else {
		slog.Info("OIDC authentication disabled (set oidc_issuer to enable)")
	}

	// Content-addressed texture store for skins and capes.
	textureDir := filepath.Join(cfg.StateDir, "textures")
	textureSt, err := textures.New(textureDir)
	if err != nil {
		slog.Error("failed to initialize texture store", "path", textureDir, "error", err)
		os.Exit(1)
	}
	slog.Info("texture store ready", "dir", textureDir)

	// Yggdrasil protocol handler and HTTP server.
	// Build optional fallback client from config; nil when no servers are configured
	// so all interop features remain OFF by default.
	var fbClient *fallback.Client
	if len(cfg.FallbackAPIServers) > 0 {
		fbClient = fallback.NewClient(cfg.FallbackAPIServers)
		slog.Info("fallback API servers configured", "count", len(cfg.FallbackAPIServers))
	}

	gameAuthn := auth.NewGameAuthenticator(st)
	yggH := yggdrasil.NewHandler(tokenSvc, gameAuthn, svc, km, cfg.ServerName, cfg.Domain, cfg.BaseURL,
		fbClient, cfg.ForwardSkins, cfg.OfflineSkins, cfg.AllowSkins, cfg.AllowCapes, Version)

	// Browser session manager for the Vue Web UI.
	sessionTTL := time.Duration(cfg.SessionTTLSeconds) * time.Second
	sessionMgr := auth.NewSessionManager(st, sessionTTL, nil)

	// Mailer initialization.
	var theMailer mailer.Mailer
	if cfg.SMTPHost != "" {
		smtpCfg := mailer.SMTPConfig{
			Host:     cfg.SMTPHost,
			Port:     cfg.SMTPPort,
			Username: cfg.SMTPUsername,
			Password: cfg.SMTPPassword,
			From:     cfg.SMTPFrom,
			TLSMode:  cfg.SMTPTLSMode,
		}
		var err error
		theMailer, err = mailer.NewSMTPMailer(smtpCfg)
		if err != nil {
			slog.Error("failed to initialize SMTP mailer", "error", err)
			os.Exit(1)
		}
		slog.Info("email delivery enabled (SMTP)", "host", cfg.SMTPHost, "port", cfg.SMTPPort, "from", cfg.SMTPFrom, "tls_mode", cfg.SMTPTLSMode)
	} else {
		theMailer = &mailer.NoopMailer{}
		slog.Info("email delivery disabled (set smtp_host to enable)")
	}

	srv, err := httpserver.New(cfg, httpserver.Deps{
		Accounts:    svc,
		Tokens:      tokenSvc,
		Authn:       authn,
		Keys:        km,
		YggHandler:  yggH,
		Textures:    textureSt,
		Sessions:    sessionMgr,
		Store:       st,
		OIDCBrowser: oidcBrowser,
		Mailer:      theMailer,
		ConfigPath:  *configPath,
	})
	if err != nil {
		slog.Error("failed to build HTTP server", "error", err)
		os.Exit(1)
	}

	slog.Info("starting minecrauth server")
	if err := srv.Start(ctx); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}

	slog.Info("minecrauth server stopped")
}

// oidcProvisioner adapts *accounts.Service to the auth.Provisioner interface.
// This adapter lives in main (not in auth) to avoid an import cycle: the accounts
// package already imports auth (for HashPassword), so auth must not import accounts.
type oidcProvisioner struct {
	svc *accounts.Service
}

// CreateProvisionedUser creates a non-admin local account with a random, effectively
// unusable password for an OIDC identity not yet known locally. The user can only
// log in via OIDC; direct password login is not possible with the random password.
func (p *oidcProvisioner) CreateProvisionedUser(ctx context.Context, email string) (*store.User, error) {
	u, err := p.svc.AdminCreateUser(ctx, email, generateBootstrapPassword(), false /* isAdmin */)
	if err != nil {
		return nil, err
	}
	return u, nil
}

// ensureDefaultAdmins guarantees that every email in emails exists in the store and has
// the admin flag set. Missing accounts are created with a generated password that is
// logged once at WARN level so the operator can copy it; the password must be changed
// immediately after first login. Existing non-admin accounts are promoted.
func ensureDefaultAdmins(ctx context.Context, svc *accounts.Service, st store.Store, emails []string) {
	for _, email := range emails {
		u, err := st.GetUserByEmail(ctx, email)
		if err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				slog.Error("ensureDefaultAdmins: looking up email", "email", email, "error", err)
				continue
			}
			// User does not exist: create with a generated password.
			pass := generateBootstrapPassword()
			if _, createErr := svc.AdminCreateUser(ctx, email, pass, true); createErr != nil {
				slog.Error("ensureDefaultAdmins: creating admin account", "email", email, "error", createErr)
				continue
			}
			// Log the generated password once so the operator can authenticate.
			// This is intentional and documented behavior for the bootstrap path.
			slog.Warn("created default admin account; change the password immediately",
				"email", email,
				"generated_password", pass,
			)
			continue
		}

		if !u.IsAdmin {
			if promoteErr := svc.SetAdmin(ctx, u.ID, true); promoteErr != nil {
				slog.Error("ensureDefaultAdmins: promoting user to admin", "email", email, "error", promoteErr)
				continue
			}
			slog.Info("promoted existing user to admin", "email", email)
		} else {
			slog.Debug("default admin already configured", "email", email)
		}
	}
}

// generateBootstrapPassword produces a cryptographically random password long enough to
// satisfy any reasonable MinPasswordLength setting (64 base64-URL characters).
func generateBootstrapPassword() string {
	b := make([]byte, 48) // 48 bytes -> 64 base64-URL characters
	if _, err := rand.Read(b); err != nil {
		// rand.Read on any supported OS should never fail; if it does, the system is
		// in a fundamentally broken state.
		slog.Error("generateBootstrapPassword: reading random bytes", "error", err)
		os.Exit(1)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
