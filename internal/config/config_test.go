// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// writeConfig helper writes the yaml content to a temporary file and returns its path.
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}
	return path
}

func TestLoad_MinimalValid(t *testing.T) {
	content := `base_url: "https://auth.example.com"`
	path := writeConfig(t, content)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("expected no error for minimal valid config, got: %v", err)
	}

	if cfg.BaseURL != "https://auth.example.com" {
		t.Errorf("expected BaseURL https://auth.example.com, got %s", cfg.BaseURL)
	}
	if cfg.Domain != "auth.example.com" {
		t.Errorf("expected Domain auth.example.com, got %s", cfg.Domain)
	}

	// Verify defaults
	if cfg.ListenAddr != "0.0.0.0:25585" {
		t.Errorf("expected default ListenAddr, got %s", cfg.ListenAddr)
	}
	if cfg.StateDir != "./data" {
		t.Errorf("expected default StateDir, got %s", cfg.StateDir)
	}
	if cfg.ServerName != "minecrauth" {
		t.Errorf("expected ServerName minecrauth, got %s", cfg.ServerName)
	}
	if cfg.MaxPlayersPerUser != 3 {
		t.Errorf("expected MaxPlayersPerUser 3, got %d", cfg.MaxPlayersPerUser)
	}
	if !cfg.AllowSkins {
		t.Error("expected AllowSkins true by default")
	}
	if cfg.SessionTTLSeconds != 604800 {
		t.Errorf("expected SessionTTLSeconds 604800, got %d", cfg.SessionTTLSeconds)
	}
	if cfg.SMTPPort != 587 {
		t.Errorf("expected default SMTPPort 587, got %d", cfg.SMTPPort)
	}
	if cfg.SMTPTLSMode != "starttls" {
		t.Errorf("expected default SMTPTLSMode starttls, got %s", cfg.SMTPTLSMode)
	}
	if cfg.LogFormat != "json" {
		t.Errorf("expected default LogFormat json, got %s", cfg.LogFormat)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("expected default LogLevel info, got %s", cfg.LogLevel)
	}
	if cfg.ApiPrefix != "/api" {
		t.Errorf("expected default ApiPrefix /api, got %s", cfg.ApiPrefix)
	}
}

func TestLoad_MissingBaseURL(t *testing.T) {
	content := `
listen_addr: "127.0.0.1:25585"
`
	path := writeConfig(t, content)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error when base_url is missing, got nil")
	}
	if err.Error() != "base_url is required" {
		t.Errorf("expected error 'base_url is required', got: %v", err)
	}
}

func TestLoad_InvalidBaseURLScheme(t *testing.T) {
	content := `
base_url: "ftp://auth.example.com"
`
	path := writeConfig(t, content)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid scheme ftp://, got nil")
	}
}

func TestLoad_CustomValues(t *testing.T) {
	content := `
base_url: "http://local:8080"
listen_addr: "127.0.0.1:9000"
state_dir: "/var/lib/minecrauth"
token_expiry_seconds: 3600
rate_limit_rps: 5.5
rate_limit_burst: 15
body_limit_bytes: 2097152
min_password_length: 12
player_name_regex: "^[a-z]{3,10}$"
session_ttl_seconds: 12345
max_players_per_user: -1
allow_skins: false
`
	path := writeConfig(t, content)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected load error: %v", err)
	}

	if cfg.BaseURL != "http://local:8080" {
		t.Errorf("expected BaseURL http://local:8080, got %s", cfg.BaseURL)
	}
	if cfg.Domain != "local" {
		t.Errorf("expected Domain local, got %s", cfg.Domain)
	}
	if cfg.ListenAddr != "127.0.0.1:9000" {
		t.Errorf("expected ListenAddr 127.0.0.1:9000, got %s", cfg.ListenAddr)
	}
	if cfg.StateDir != "/var/lib/minecrauth" {
		t.Errorf("expected StateDir /var/lib/minecrauth, got %s", cfg.StateDir)
	}
	if cfg.TokenExpirySeconds != 3600 {
		t.Errorf("expected TokenExpirySeconds 3600, got %d", cfg.TokenExpirySeconds)
	}
	if cfg.RateLimitRPS != 5.5 {
		t.Errorf("expected RateLimitRPS 5.5, got %f", cfg.RateLimitRPS)
	}
	if cfg.RateLimitBurst != 15 {
		t.Errorf("expected RateLimitBurst 15, got %d", cfg.RateLimitBurst)
	}
	if cfg.BodyLimitBytes != 2097152 {
		t.Errorf("expected BodyLimitBytes 2097152, got %d", cfg.BodyLimitBytes)
	}
	if cfg.MinPasswordLength != 12 {
		t.Errorf("expected MinPasswordLength 12, got %d", cfg.MinPasswordLength)
	}
	if cfg.PlayerNameRegex != "^[a-z]{3,10}$" {
		t.Errorf("expected PlayerNameRegex ^[a-z]{3,10}$, got %s", cfg.PlayerNameRegex)
	}
	if cfg.SessionTTLSeconds != 12345 {
		t.Errorf("expected SessionTTLSeconds 12345, got %d", cfg.SessionTTLSeconds)
	}
	if cfg.MaxPlayersPerUser != -1 {
		t.Errorf("expected MaxPlayersPerUser -1, got %d", cfg.MaxPlayersPerUser)
	}
	if cfg.AllowSkins {
		t.Error("expected AllowSkins false")
	}
}

func TestLoad_UUIDGeneration(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		content := `
base_url: "https://auth.example.com"
uuid_generation: "sha256"
`
		path := writeConfig(t, content)
		_, err := Load(path)
		if err == nil {
			t.Fatal("expected error for invalid uuid_generation, got nil")
		}
	})

	t.Run("offline", func(t *testing.T) {
		content := `
base_url: "https://auth.example.com"
uuid_generation: "offline"
`
		path := writeConfig(t, content)
		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.UUIDGeneration != "offline" {
			t.Errorf("expected offline, got %s", cfg.UUIDGeneration)
		}
	})
}

func TestLoad_Prefixes(t *testing.T) {
	t.Run("equal api and admin prefix rejected", func(t *testing.T) {
		content := `
base_url: "https://auth.example.com"
api_prefix: "/manage"
admin_prefix: "/manage"
`
		path := writeConfig(t, content)
		_, err := Load(path)
		if err == nil {
			t.Fatal("expected error for equal api and admin prefix, got nil")
		}
	})

	t.Run("prefix without leading slash rejected", func(t *testing.T) {
		content := `
base_url: "https://auth.example.com"
api_prefix: "api"
`
		path := writeConfig(t, content)
		_, err := Load(path)
		if err == nil {
			t.Fatal("expected error for prefix without leading slash, got nil")
		}
	})
}

func TestLoad_DefaultAdmins(t *testing.T) {
	content := `
base_url: "https://auth.example.com"
default_admins:
  - "admin1@example.com"
  - "admin2@example.com"
`
	path := writeConfig(t, content)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.DefaultAdmins) != 2 {
		t.Fatalf("expected 2 default admins, got %d: %v", len(cfg.DefaultAdmins), cfg.DefaultAdmins)
	}
	if cfg.DefaultAdmins[0] != "admin1@example.com" {
		t.Errorf("unexpected first admin: %q", cfg.DefaultAdmins[0])
	}
	if cfg.DefaultAdmins[1] != "admin2@example.com" {
		t.Errorf("unexpected second admin: %q", cfg.DefaultAdmins[1])
	}
}

func TestLoad_FallbackAPIServers(t *testing.T) {
	t.Run("valid list", func(t *testing.T) {
		content := `
base_url: "https://auth.example.com"
fallback_api_servers:
  - nickname: "mojang"
    account_url: "https://api.mojang.com"
    session_url: "https://sessionserver.mojang.com"
    cache_ttl_seconds: 300
    deny_unknown_users: true
`
		path := writeConfig(t, content)
		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(cfg.FallbackAPIServers) != 1 {
			t.Fatalf("expected 1 fallback server, got %d", len(cfg.FallbackAPIServers))
		}
		s := cfg.FallbackAPIServers[0]
		if s.Nickname != "mojang" {
			t.Errorf("nickname = %q; want mojang", s.Nickname)
		}
		if s.AccountURL != "https://api.mojang.com" {
			t.Errorf("account_url = %q; want https://api.mojang.com", s.AccountURL)
		}
		if s.SessionURL != "https://sessionserver.mojang.com" {
			t.Errorf("session_url = %q; want https://sessionserver.mojang.com", s.SessionURL)
		}
		if s.CacheTTLSeconds != 300 {
			t.Errorf("cache_ttl_seconds = %d; want 300", s.CacheTTLSeconds)
		}
		if !s.DenyUnknownUsers {
			t.Error("deny_unknown_users should be true")
		}
		// omitted enable_authentication should default to true
		if !s.AuthEnabled() {
			t.Error("enable_authentication should default to true")
		}
	})

	t.Run("invalid fallback URL scheme", func(t *testing.T) {
		content := `
base_url: "https://auth.example.com"
fallback_api_servers:
  - nickname: "bad"
    session_url: "ftp://bad.example.com"
`
		path := writeConfig(t, content)
		_, err := Load(path)
		if err == nil {
			t.Fatal("expected error for fallback server invalid URL scheme, got nil")
		}
	})
}

func TestLoad_OIDC(t *testing.T) {
	t.Run("issuer without client id error", func(t *testing.T) {
		content := `
base_url: "https://auth.example.com"
oidc_issuer: "https://accounts.google.com"
`
		path := writeConfig(t, content)
		_, err := Load(path)
		if err == nil {
			t.Fatal("expected error when oidc_issuer is set without oidc_client_id")
		}
	})

	t.Run("valid custom and redirect defaults", func(t *testing.T) {
		content := `
base_url: "https://auth.example.com"
oidc_issuer: "https://accounts.google.com"
oidc_client_id: "my-client-id"
`
		path := writeConfig(t, content)
		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg.OIDCIssuer != "https://accounts.google.com" {
			t.Errorf("expected issuer accounts.google.com, got %s", cfg.OIDCIssuer)
		}
		if cfg.OIDCClientID != "my-client-id" {
			t.Errorf("expected client id my-client-id, got %s", cfg.OIDCClientID)
		}
		if cfg.OIDCRedirectURL != "https://auth.example.com/oauth/callback" {
			t.Errorf("expected default redirect URL, got %s", cfg.OIDCRedirectURL)
		}
	})

	t.Run("valid with custom redirect", func(t *testing.T) {
		content := `
base_url: "https://auth.example.com"
oidc_issuer: "https://accounts.google.com"
oidc_client_id: "my-client-id"
oidc_redirect_url: "https://auth.example.com/custom/callback"
`
		path := writeConfig(t, content)
		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg.OIDCRedirectURL != "https://auth.example.com/custom/callback" {
			t.Errorf("expected custom redirect URL, got %s", cfg.OIDCRedirectURL)
		}
	})
}

func TestLoad_SMTP(t *testing.T) {
	t.Run("custom valid and require verification", func(t *testing.T) {
		content := `
base_url: "https://auth.example.com"
smtp_host: "smtp.example.com"
smtp_port: 465
smtp_username: "user"
smtp_password: "password"
smtp_from: "noreply@example.com"
smtp_tls_mode: "tls"
require_email_verification: true
`
		path := writeConfig(t, content)
		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg.SMTPHost != "smtp.example.com" {
			t.Errorf("expected SMTPHost, got %s", cfg.SMTPHost)
		}
		if cfg.SMTPPort != 465 {
			t.Errorf("expected SMTPPort, got %d", cfg.SMTPPort)
		}
		if cfg.SMTPUsername != "user" {
			t.Errorf("expected SMTPUsername, got %s", cfg.SMTPUsername)
		}
		if cfg.SMTPPassword != "password" {
			t.Errorf("expected SMTPPassword, got %s", cfg.SMTPPassword)
		}
		if cfg.SMTPFrom != "noreply@example.com" {
			t.Errorf("expected SMTPFrom, got %s", cfg.SMTPFrom)
		}
		if cfg.SMTPTLSMode != "tls" {
			t.Errorf("expected SMTPTLSMode, got %s", cfg.SMTPTLSMode)
		}
		if !cfg.RequireEmailVerification {
			t.Error("expected RequireEmailVerification true")
		}
	})

	t.Run("invalid tls mode", func(t *testing.T) {
		content := `
base_url: "https://auth.example.com"
smtp_tls_mode: "badtls"
`
		path := writeConfig(t, content)
		_, err := Load(path)
		if err == nil {
			t.Fatal("expected error for invalid smtp_tls_mode, got nil")
		}
	})
}

func TestLoad_Logging(t *testing.T) {
	t.Run("invalid format", func(t *testing.T) {
		content := `
base_url: "https://auth.example.com"
log_format: "xml"
`
		path := writeConfig(t, content)
		_, err := Load(path)
		if err == nil {
			t.Fatal("expected error for invalid log_format, got nil")
		}
	})

	t.Run("invalid level", func(t *testing.T) {
		content := `
base_url: "https://auth.example.com"
log_level: "critical"
`
		path := writeConfig(t, content)
		_, err := Load(path)
		if err == nil {
			t.Fatal("expected error for invalid log_level, got nil")
		}
	})
}

func TestLoad_EnvExpansion(t *testing.T) {
	t.Setenv("TEST_SERVER_NAME", "ExpandedServerName")
	t.Setenv("TEST_SMTP_PASS", "SuperSecretPass")

	content := `
base_url: "https://auth.example.com"
server_name: "${TEST_SERVER_NAME}"
smtp_password: "$TEST_SMTP_PASS"
`
	path := writeConfig(t, content)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.ServerName != "ExpandedServerName" {
		t.Errorf("expected server_name to be expanded to 'ExpandedServerName', got %q", cfg.ServerName)
	}
	if cfg.SMTPPassword != "SuperSecretPass" {
		t.Errorf("expected smtp_password to be expanded to 'SuperSecretPass', got %q", cfg.SMTPPassword)
	}
}

func TestLoad_UnknownKeyRejected(t *testing.T) {
	content := `
base_url: "https://auth.example.com"
bogus_key: 123
`
	path := writeConfig(t, content)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error due to unknown key bogus_key (KnownFields(true)), got nil")
	}
}

func TestLoad_NonExistentFile(t *testing.T) {
	_, err := Load("/does/not/exist/config.yaml")
	if err == nil {
		t.Fatal("expected error when loading non-existent file path, got nil")
	}
}
