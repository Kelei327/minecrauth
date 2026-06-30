// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

// Package config defines the typed configuration and environment parsing for the application.
package config

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// FallbackAPIServer describes one upstream Yggdrasil-compatible server to delegate to
// when a player or profile is not known locally.
// Ref: https://minecraft.wiki/w/Mojang_API
type FallbackAPIServer struct {
	// Nickname is a human-readable label used in logs.
	Nickname string `yaml:"nickname"`

	// AccountURL is the base URL of the account service (e.g. https://api.mojang.com).
	// Used for name-to-UUID lookups: GET {AccountURL}/users/profiles/minecraft/{name}.
	AccountURL string `yaml:"account_url"`

	// SessionURL is the base URL of the session service (e.g. https://sessionserver.mojang.com).
	// Used for hasJoined and profile lookups.
	SessionURL string `yaml:"session_url"`

	// SkinDomains lists the texture CDN domains this server serves skins from.
	// Informational only at this layer; used by authlib-injector for client-side verification.
	SkinDomains []string `yaml:"skin_domains"`

	// CacheTTLSeconds is how long responses from this server are cached in memory.
	// 0 means no cache.
	CacheTTLSeconds int `yaml:"cache_ttl_seconds"`

	// DenyUnknownUsers, when true, makes this server act as a whitelist: only players
	// who also have a local account on this minecrauth instance are authenticated via
	// this fallback. Players authenticated against the fallback but absent locally are
	// rejected (hasJoined returns 204).
	DenyUnknownUsers bool `yaml:"deny_unknown_users"`

	// EnableAuthentication controls whether this server is queried during the
	// hasJoined handshake (join/hasJoined session flow). When false the server
	// is only used for profile and name-to-UUID lookups.
	// A nil pointer means the value was omitted in YAML; it is defaulted to true
	// during load so that auth is enabled unless the operator explicitly disables it.
	EnableAuthentication *bool `yaml:"enable_authentication"`
}

// AuthEnabled reports whether authentication is enabled for this server (default true).
func (f *FallbackAPIServer) AuthEnabled() bool {
	return f.EnableAuthentication == nil || *f.EnableAuthentication
}

// Config holds the application configuration loaded from a YAML configuration file.
type Config struct {
	// BaseURL is the external HTTP/HTTPS base URL of the auth server.
	// Required because clients (launchers, servers) use it to request resources and verify texture domains.
	// Ref: https://github.com/yushijinhun/authlib-injector/wiki/Yggdrasil-%E6%9C%8D%E5%8A%A1%E7%AB%AF%E6%8A%80%E6%9C%AF%E8%A7%84%E8%8C%83
	BaseURL string `yaml:"base_url"`

	// Domain is the hostname derived from the BaseURL. Used for specifying valid skin domains.
	// Ref: https://github.com/yushijinhun/authlib-injector/wiki/Yggdrasil-%E6%9C%8D%E5%8A%A1%E7%AB%AF%E6%8A%80%E6%9C%AF%E8%A7%84%E8%8C%83#%E5%85%83%E6%95%B0%E6%8D%AE
	Domain string `yaml:"-"`

	// ListenAddr is the TCP address the HTTP server listens on.
	// Default: 0.0.0.0:25585
	ListenAddr string `yaml:"listen_addr"`

	// StateDir is the path to the directory where stateful assets (such as the SQLite database) are stored.
	// Default: ./data
	StateDir string `yaml:"state_dir"`

	// TokenExpirySeconds is the duration in seconds until an opaque Yggdrasil access token expires.
	// Set to 0 to mean the token never expires automatically.
	// Default: 0
	TokenExpirySeconds int `yaml:"token_expiry_seconds"`

	// RateLimitRPS is the allowed requests per second per client IP address.
	// Default: 25.0
	// Ref: https://pkg.go.dev/golang.org/x/time/rate
	RateLimitRPS float64 `yaml:"rate_limit_rps"`

	// RateLimitBurst is the burst limit of requests allowed for the rate limiter.
	// Default: 100
	// Ref: https://pkg.go.dev/golang.org/x/time/rate
	RateLimitBurst int `yaml:"rate_limit_burst"`

	// BodyLimitBytes is the maximum size in bytes allowed for incoming request bodies.
	// Default: 1048576 (1MB)
	BodyLimitBytes int `yaml:"body_limit_bytes"`

	// MinPasswordLength is the minimum password length required during user registration.
	// Default: 8
	MinPasswordLength int `yaml:"min_password_length"`

	// PlayerNameRegex is the regular expression that all player names must match.
	// Default: ^[a-zA-Z0-9_]{2,16}$
	// Ref: https://minecraft.wiki/w/Player_profile
	PlayerNameRegex string `yaml:"player_name_regex"`

	// ServerName is the human-readable name of the Minecraft auth server advertised in the
	// authlib-injector metadata document.
	// Default: "minecrauth"
	// Ref: https://github.com/yushijinhun/authlib-injector/wiki/Yggdrasil-%E6%9C%8D%E5%8A%A1%E7%AB%AF%E6%8A%80%E6%9C%AF%E8%A7%84%E8%8C%83
	ServerName string `yaml:"server_name"`

	// YggdrasilPrefix is the URL path prefix under which the Yggdrasil API is mounted.
	// Operators give the concatenation of BaseURL and YggdrasilPrefix to authlib-injector as
	// the API root. Example: https://auth.example.com/authlib-injector
	// Default: "/authlib-injector"
	// Ref: https://github.com/yushijinhun/authlib-injector/blob/master/README.md
	YggdrasilPrefix string `yaml:"yggdrasil_prefix"`

	// MaxPlayersPerUser is the maximum number of Minecraft player profiles one user may own.
	// Set to -1 for unlimited.
	// Default: 3
	MaxPlayersPerUser int `yaml:"max_players_per_user"`

	// UUIDGeneration controls how player UUIDs are generated when no UUID is supplied.
	// "random" generates a cryptographically random V4 UUID.
	// "offline" derives the UUID from the player name using the offline-mode algorithm so
	// migrated players retain the same UUID vanilla offline servers assign.
	// Default: "random"
	// Ref: https://minecraft.wiki/w/Java_Edition_server_properties#online-mode
	UUIDGeneration string `yaml:"uuid_generation"`

	// RequireInvite enforces that every new self-service registration must supply a valid invite
	// code generated by an admin. Registrations without a code are rejected with 403.
	// Default: false
	RequireInvite bool `yaml:"require_invite"`

	// DefaultAdmins is the list of email addresses that must exist and have admin rights at
	// startup. The server creates missing accounts with a generated password logged once.
	DefaultAdmins []string `yaml:"default_admins"`

	// AdminPrefix is the URL path prefix for the privileged admin management API surface.
	// Keep this separate from ApiPrefix so operators can restrict it at the reverse-proxy level.
	// Default: "/admin"
	AdminPrefix string `yaml:"admin_prefix"`

	// ApiPrefix is the URL path prefix for the public management API surface.
	// Default: "/api"
	ApiPrefix string `yaml:"api_prefix"`

	// SkinSizeLimit is the maximum skin width in pixels accepted on upload.
	// 0 means unlimited (high-res skins allowed).
	// Default: 64
	// Ref: https://minecraft.wiki/w/Skin
	SkinSizeLimit int `yaml:"skin_size_limit"`

	// AllowSkins controls whether self-service skin uploads are accepted.
	// Admins can still manage skins via the service layer regardless.
	// Default: true
	AllowSkins bool `yaml:"allow_skins"`

	// AllowCapes controls whether self-service cape uploads are accepted.
	// Default: true
	AllowCapes bool `yaml:"allow_capes"`

	// AllowTextureFromURL permits fetching a texture from an arbitrary HTTP/S URL
	// instead of a direct upload. Disabled by default to prevent SSRF.
	// Default: false
	// Ref: https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
	AllowTextureFromURL bool `yaml:"allow_texture_from_url"`

	// FallbackAPIServers is the list of upstream Yggdrasil-compatible servers to consult
	// when a player or profile is not known locally. Enables mixed-auth (e.g. local + Mojang).
	// Ref: https://minecraft.wiki/w/Mojang_API
	FallbackAPIServers []FallbackAPIServer `yaml:"fallback_api_servers"`

	// ForwardSkins enables skin forwarding: when a local player has no skin assigned,
	// minecrauth fetches their profile from the first configured fallback server and
	// injects the fallback's texture properties into the profile response verbatim.
	// The injected textures are signed by the fallback server's key, not ours. Clients
	// must therefore trust the fallback's key (e.g. via authlib-injector skinDomains).
	// Requires at least one FallbackAPIServer to be configured. Default: false.
	ForwardSkins bool `yaml:"forward_skins"`

	// OfflineSkins enables offline-UUID skin lookup: when a profile is requested by UUID
	// and that UUID is not found in the local store, minecrauth scans all local players
	// and checks whether their Minecraft offline UUID (deterministic from name) matches.
	// Lets offline-mode servers fetch skins for players whose stored UUID is random but
	// whose offline UUID is what the server computed. Default: false.
	OfflineSkins bool `yaml:"offline_skins"`

	// OIDCIssuer is the OIDC provider discovery URL
	// (e.g. https://accounts.google.com or https://login.microsoftonline.com/<tenant>/v2.0).
	// When non-empty, OIDC ID-token authentication is enabled for the management plane
	// (bearer-as-password pattern, per DECISIONS.md §OIDC connector shape). The server
	// performs OIDC discovery at startup; startup fails if the provider is unreachable.
	// Default: "" (OIDC disabled; no external IdP required to run the server).
	// Ref: https://openid.net/specs/openid-connect-discovery-1_0.html
	OIDCIssuer string `yaml:"oidc_issuer"`

	// OIDCClientID is the OAuth 2.0 / OIDC client ID registered with the provider.
	// Required when OIDCIssuer is set; ignored otherwise.
	// Ref: https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.2
	OIDCClientID string `yaml:"oidc_client_id"`

	// OIDCClientSecret is the client secret.
	// Ref: https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
	OIDCClientSecret string `yaml:"oidc_client_secret"`

	// OIDCRedirectURL is the redirect URL.
	// Ref: https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
	OIDCRedirectURL string `yaml:"oidc_redirect_url"`

	// OIDCAutoProvision, when true, automatically creates a non-admin local user account
	// on the first successful OIDC login for an email not yet known in the local store.
	// When false (default), OIDC login returns ErrInvalidCredentials for unknown emails;
	// the operator must create the local account manually first.
	// Default: false.
	OIDCAutoProvision bool `yaml:"oidc_auto_provision"`

	// SessionTTLSeconds is the lifetime of a browser UI session in seconds.
	// The session cookie is set with this as its Max-Age. After expiry the user
	// must log in again via POST /web/api/login.
	// Default: 604800 (7 days).
	// Ref: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
	SessionTTLSeconds int `yaml:"session_ttl_seconds"`

	// SMTPHost is the SMTP host address for delivering emails.
	// Default: "" (email delivery disabled).
	SMTPHost string `yaml:"smtp_host"`

	// SMTPPort is the SMTP port number.
	// Default: 587
	SMTPPort int `yaml:"smtp_port"`

	// SMTPUsername is the SMTP username for authentication.
	// Default: ""
	SMTPUsername string `yaml:"smtp_username"`

	// SMTPPassword is the SMTP password for authentication.
	// Default: ""
	SMTPPassword string `yaml:"smtp_password"`

	// SMTPFrom is the "From" email address used as the sender.
	// Default: ""
	SMTPFrom string `yaml:"smtp_from"`

	// SMTPTLSMode sets the TLS connection policy. Allowed values: "starttls", "tls", "none".
	// Default: "starttls"
	// Ref: https://github.com/wneessen/go-mail
	SMTPTLSMode string `yaml:"smtp_tls_mode"`

	// RequireEmailVerification enforces that new self-service registrations must verify
	// their email address before they can log in or register players.
	// Default: false
	RequireEmailVerification bool `yaml:"require_email_verification"`

	// LogFormat specifies the logging output format. Valid values: "json" or "text".
	// Default: "json"
	// Ref: https://pkg.go.dev/log/slog
	LogFormat string `yaml:"log_format"`

	// LogLevel specifies the logging output level. Valid values: "debug", "info", "warn", "error".
	// Default: "info"
	// Ref: https://pkg.go.dev/log/slog
	LogLevel string `yaml:"log_level"`
}

// defaultConfig returns a Config pre-populated with ALL default values.
func defaultConfig() Config {
	return Config{
		ListenAddr:               "0.0.0.0:25585",
		StateDir:                 "./data",
		TokenExpirySeconds:       0,
		RateLimitRPS:             25.0,
		RateLimitBurst:           100,
		BodyLimitBytes:           1048576,
		MinPasswordLength:        8,
		PlayerNameRegex:          `^[a-zA-Z0-9_]{2,16}$`,
		ServerName:               "minecrauth",
		YggdrasilPrefix:          "/authlib-injector",
		MaxPlayersPerUser:        3,
		UUIDGeneration:           "random",
		RequireInvite:            false,
		AdminPrefix:              "/admin",
		ApiPrefix:                "/api",
		SkinSizeLimit:            64,
		AllowSkins:               true,
		AllowCapes:               true,
		AllowTextureFromURL:      false,
		ForwardSkins:             false,
		OfflineSkins:             false,
		OIDCAutoProvision:        false,
		SessionTTLSeconds:        604800,
		SMTPPort:                 587,
		SMTPTLSMode:              "starttls",
		RequireEmailVerification: false,
		LogFormat:                "json",
		LogLevel:                 "info",
	}
}

// Load loads the configuration from a YAML file, applying environment expansion,
// pre-populating sane defaults, and performing validation.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %q: %w", path, err)
	}

	expanded := os.ExpandEnv(string(data))

	cfg := defaultConfig()

	dec := yaml.NewDecoder(strings.NewReader(expanded))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		if errors.Is(err, io.EOF) {
			// empty file: keep defaults, but base_url will fail validation below
		} else {
			return nil, fmt.Errorf("parsing config YAML: %w", err)
		}
	}

	// Validation
	if cfg.BaseURL == "" {
		return nil, errors.New("base_url is required")
	}

	parsedURL, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base_url: %w", err)
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("invalid base_url scheme %q: must be http or https", parsedURL.Scheme)
	}
	cfg.Domain = parsedURL.Hostname()
	if cfg.Domain == "" {
		return nil, errors.New("invalid base_url: missing hostname")
	}

	if cfg.UUIDGeneration != "random" && cfg.UUIDGeneration != "offline" {
		return nil, fmt.Errorf("invalid uuid_generation %q: must be \"random\" or \"offline\"", cfg.UUIDGeneration)
	}

	if _, err := regexp.Compile(cfg.PlayerNameRegex); err != nil {
		return nil, fmt.Errorf("invalid player_name_regex: %w", err)
	}

	if err := validatePrefixes(cfg.YggdrasilPrefix, cfg.ApiPrefix, cfg.AdminPrefix); err != nil {
		return nil, err
	}

	cfg.SMTPTLSMode = strings.ToLower(cfg.SMTPTLSMode)
	switch cfg.SMTPTLSMode {
	case "starttls", "tls", "none":
		// valid
	default:
		return nil, fmt.Errorf("invalid smtp_tls_mode %q: must be \"starttls\", \"tls\" or \"none\"", cfg.SMTPTLSMode)
	}

	cfg.LogFormat = strings.ToLower(cfg.LogFormat)
	switch cfg.LogFormat {
	case "json", "text":
		// valid
	default:
		return nil, fmt.Errorf("invalid log_format %q: must be \"json\" or \"text\"", cfg.LogFormat)
	}

	cfg.LogLevel = strings.ToLower(cfg.LogLevel)
	switch cfg.LogLevel {
	case "debug", "info", "warn", "error":
		// valid
	default:
		return nil, fmt.Errorf("invalid log_level %q: must be \"debug\", \"info\", \"warn\" or \"error\"", cfg.LogLevel)
	}

	if cfg.SessionTTLSeconds <= 0 {
		cfg.SessionTTLSeconds = 604800
	}

	if cfg.OIDCIssuer != "" && cfg.OIDCClientID == "" {
		return nil, errors.New("oidc_client_id is required when oidc_issuer is set")
	}

	if cfg.OIDCRedirectURL == "" {
		cfg.OIDCRedirectURL = cfg.BaseURL + "/oauth/callback"
	}

	// Validate fallback servers
	for i := range cfg.FallbackAPIServers {
		srv := &cfg.FallbackAPIServers[i]
		if srv.AccountURL != "" {
			if err := validateHTTPURL(srv.AccountURL, fmt.Sprintf("fallback_api_servers[%d].account_url", i)); err != nil {
				return nil, err
			}
		}
		if srv.SessionURL != "" {
			if err := validateHTTPURL(srv.SessionURL, fmt.Sprintf("fallback_api_servers[%d].session_url", i)); err != nil {
				return nil, err
			}
		}
		if srv.EnableAuthentication == nil {
			v := true
			srv.EnableAuthentication = &v
		}
	}

	return &cfg, nil
}

// validatePrefixes returns an error if any path prefix is invalid or if two prefixes are equal.
func validatePrefixes(ygg, api, admin string) error {
	for _, pair := range [][2]string{
		{"YggdrasilPrefix", ygg},
		{"ApiPrefix", api},
		{"AdminPrefix", admin},
	} {
		if !strings.HasPrefix(pair[1], "/") {
			return fmt.Errorf("%s %q must start with '/'", pair[0], pair[1])
		}
	}
	if ygg == api {
		return fmt.Errorf("YggdrasilPrefix and ApiPrefix must differ (both are %q)", ygg)
	}
	if ygg == admin {
		return fmt.Errorf("YggdrasilPrefix and AdminPrefix must differ (both are %q)", ygg)
	}
	if api == admin {
		return fmt.Errorf("ApiPrefix and AdminPrefix must differ (both are %q)", api)
	}
	return nil
}

// validateHTTPURL returns an error if rawURL is not a valid http or https URL.
func validateHTTPURL(rawURL, label string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%s %q is not a valid URL: %w", label, rawURL, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("%s %q must use http or https scheme", label, rawURL)
	}
	if parsed.Hostname() == "" {
		return fmt.Errorf("%s %q is missing a hostname", label, rawURL)
	}
	return nil
}
