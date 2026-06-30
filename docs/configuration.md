# Configuration Reference

minecrauth is configured via a single YAML configuration file. The server requires this file to be specified at startup using the `--config` command-line flag.

## Key Concepts

- **Required Flag**: The binary requires `--config /path/to/config.yaml` to run. If absent, the binary exits with an error.
- **Environment Variable Expansion**: Before parsing the YAML, the server passes the file's raw content through environment variable expansion (`os.ExpandEnv`). Any reference like `${VAR}` or `$VAR` is substituted with the corresponding environment variable value. This allows you to securely inject secrets (like `smtp_password` or `oidc_client_secret`) at runtime without committing them to disk in plain text.
- **Strict Parsing**: Unknown YAML keys are rejected (`KnownFields` strict parsing). If you make a typo in a configuration key, the server will fail fast and exit with an error at startup.
- **Minimal Requirements**: `base_url` is the only required key. All other options have sensible, production-ready defaults.
- **No Old Env Vars**: The old `MINECRAUTH_*` environment variables, as well as `LOG_FORMAT` and `LOG_LEVEL` environment variables, are no longer supported. All configuration must be defined inside the YAML configuration file.

---

## Quick Start

Create a minimal configuration file named `config.yaml` with your externally reachable URL:

```yaml
base_url: "https://auth.example.com"
```

Start the minecrauth server:

```bash
minecrauth --config config.yaml
```

### Injecting Secrets

To avoid committing secrets to your configuration file, use environment variable expansion:

```yaml
base_url: "https://auth.example.com"
smtp_host: "smtp.mailgun.org"
smtp_username: "postmaster@example.com"
smtp_password: "${SMTP_PASSWORD}"
```

Then run the server with the environment variable set:

```bash
export SMTP_PASSWORD="super-secret-password"
minecrauth --config config.yaml
```

> **Caveat with `$`**: A literal `$` followed by a word-like pattern is treated as an environment variable and expanded. If you need a literal `$` in any field (other than the player-name regex, where a trailing quoted `$` is safe), escape it by doubling it (i.e. `$$`).

---

## Configuration Options

### Core/Server Settings

| Key           | Type   | Default           | Description                                                                                                                                                                                                     |
| :------------ | :----- | :---------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `base_url`    | String | `(Required)`      | The externally reachable HTTP or HTTPS base URL of your auth server. Used by launchers and servers to verify textures, request resources, and matches launcher verification. Must use `http` or `https` scheme. |
| `listen_addr` | String | `"0.0.0.0:25585"` | The TCP address and port the HTTP server listens on.                                                                                                                                                            |
| `state_dir`   | String | `"./data"`        | The local directory where stateful assets (such as the SQLite database, RSA signing key, and cached textures) are stored.                                                                                       |
| `server_name` | String | `"minecrauth"`    | The human-readable name of the Minecraft auth server. Advertised to launchers via the metadata document.                                                                                                        |

### URL Path Prefixes

| Key                | Type   | Default               | Description                                                                                                                                                                      |
| :----------------- | :----- | :-------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `yggdrasil_prefix` | String | `"/authlib-injector"` | The URL path prefix under which the Yggdrasil API is mounted. Must start with `/`.                                                                                               |
| `admin_prefix`     | String | `"/admin"`            | The URL path prefix for the privileged admin management API surface. Must start with `/`. Keep this separate from `api_prefix` to restrict it easily at the reverse-proxy level. |
| `api_prefix`       | String | `"/api"`              | The URL path prefix for the public management API surface. Must start with `/`.                                                                                                  |

### Accounts & Registration

| Key                    | Type            | Default | Description                                                                                                                                                                                        |
| :--------------------- | :-------------- | :------ | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `require_invite`       | Boolean         | `false` | Enforce that every new self-service registration must supply a valid invite code generated by an administrator. Registrations without a code will be rejected.                                     |
| `default_admins`       | List of Strings | `[]`    | A list of email addresses that must exist and have admin rights at startup. If they do not exist, they will be created automatically with a randomly generated password logged once on first boot. |
| `max_players_per_user` | Integer         | `3`     | The maximum number of Minecraft player profiles one user account may own. Set to `-1` for unlimited.                                                                                               |
| `min_password_length`  | Integer         | `8`     | The minimum password length required during user registration.                                                                                                                                     |

### Tokens & Sessions

| Key                    | Type    | Default  | Description                                                                                                                                                                    |
| :--------------------- | :------ | :------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `token_expiry_seconds` | Integer | `0`      | The duration in seconds until an opaque Yggdrasil access token expires. Set to `0` to mean the token never expires automatically (prevents "Invalid Session" launcher errors). |
| `session_ttl_seconds`  | Integer | `604800` | The lifetime of a browser Web UI session cookie in seconds. Defaults to `604800` (7 days) if set to 0 or less.                                                                 |

### Rate Limiting & Request Body

| Key                | Type    | Default   | Description                                                                    |
| :----------------- | :------ | :-------- | :----------------------------------------------------------------------------- |
| `rate_limit_rps`   | Float   | `25.0`    | The allowed requests per second per client IP address.                         |
| `rate_limit_burst` | Integer | `100`     | The burst limit of requests allowed for the rate limiter.                      |
| `body_limit_bytes` | Integer | `1048576` | The maximum size in bytes allowed for incoming request bodies (1048576 = 1MB). |

> **Note on Rate Limiting**: minecrauth determines the client IP address directly from the socket connection (`r.RemoteAddr`). It does not trust headers such as `X-Forwarded-For` to prevent header-spoofing attacks that bypass rate limits. When running behind a reverse proxy, you must ensure your proxy is configured to pass real client IPs down to the socket level (e.g. using Proxy Protocol), otherwise rate limits will apply globally to the reverse proxy's local IP address.

### Player Names & UUIDs

| Key                 | Type   | Default                  | Description                                                                                                                                                                                                                                        |
| :------------------ | :----- | :----------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `player_name_regex` | String | `"^[a-zA-Z0-9_]{2,16}$"` | Regular expression that all player profiles must match. Standard Minecraft names match this default.                                                                                                                                               |
| `uuid_generation`   | String | `"random"`               | Controls how player UUIDs are generated when no UUID is supplied. Allowed values: `"random"` (generates a cryptographically random V4 UUID) or `"offline"` (derives the UUID from the player name using the deterministic offline-mode algorithm). |

### Skins & Capes

| Key                      | Type    | Default | Description                                                                                                                                                           |
| :----------------------- | :------ | :------ | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `skin_size_limit`        | Integer | `64`    | The maximum skin/cape image width/height in pixels accepted on upload. Set to `0` for unlimited (allows high-res skins).                                              |
| `allow_skins`            | Boolean | `true`  | Controls whether self-service skin uploads are accepted in the user panel.                                                                                            |
| `allow_capes`            | Boolean | `true`  | Controls whether self-service cape uploads are accepted in the user panel.                                                                                            |
| `allow_texture_from_url` | Boolean | `false` | Permits fetching a texture from an arbitrary HTTP/HTTPS URL instead of direct upload. **WARNING**: Disabled by default to prevent Server-Side Request Forgery (SSRF). |

### Fallback / Mixed Authentication

| Key                    | Type            | Default | Description                                                                                                                                                                            |
| :--------------------- | :-------------- | :------ | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `fallback_api_servers` | List of Objects | `[]`    | Upstream Yggdrasil-compatible servers to consult when a player profile is not known locally. Enables mixed-auth setups (e.g. local + official Mojang).                                 |
| `forward_skins`        | Boolean         | `false` | Enable skin forwarding: when a local player has no skin assigned, fetch their profile from the first configured fallback server and inject the fallback's texture properties verbatim. |
| `offline_skins`        | Boolean         | `false` | Enable offline-UUID skin lookup: if a profile is requested by UUID and not found locally, scan all local players and check if their offline UUID matches.                              |

#### `fallback_api_servers` Configuration

To delegate authentication or lookups to upstream services, define the server list structure under the `fallback_api_servers` key:

```yaml
fallback_api_servers:
  - nickname: "mojang"
    account_url: "https://api.mojang.com"
    session_url: "https://sessionserver.mojang.com"
    skin_domains:
      - "textures.minecraft.net"
    cache_ttl_seconds: 300
    deny_unknown_users: false
    enable_authentication: true
```

Each server object in the list contains:

- `nickname` (String): A descriptive label used in logs.
- `account_url` (String): The base URL of the account/identity service (e.g., `https://api.mojang.com`). Used for name-to-UUID lookups.
- `session_url` (String): The base URL of the session service (e.g., `https://sessionserver.mojang.com`). Used for handshake validations and profile retrievals.
- `skin_domains` (List of Strings): The CDN domains from which this fallback server serves skins.
- `cache_ttl_seconds` (Integer): Duration to cache lookup results in memory. Set to `0` to disable caching.
- `deny_unknown_users` (Boolean): If set to `true`, the fallback acts as a whitelist. Only players who also have a local minecrauth account are authenticated against this fallback. Players not present in your local database are rejected.
- `enable_authentication` (Boolean): Controls whether this server is queried during the game join handshake. Defaults to `true`. If `false`, the server is only queried for static profile lookups and name-to-UUID conversions.

---

### OIDC Connector Shape

OIDC integration applies to the administrative API and the Web UI browser login flow. Yggdrasil game-session tokens remain opaque strings managed in the database.

| Key                   | Type    | Default | Description                                                                                                                 |
| :-------------------- | :------ | :------ | :-------------------------------------------------------------------------------------------------------------------------- |
| `oidc_issuer`         | String  | `""`    | The OIDC provider discovery URL (e.g. Keycloak, Google, Authentik). If left empty, OIDC integration is disabled.            |
| `oidc_client_id`      | String  | `""`    | The OAuth 2.0 / OIDC client ID registered with the provider. Required when `oidc_issuer` is set.                            |
| `oidc_client_secret`  | String  | `""`    | The OAuth 2.0 / OIDC client secret registered with the provider. Enabling this allows the Web UI's browser login flow.      |
| `oidc_redirect_url`   | String  | `""`    | The redirect URL registered with the OIDC provider. Defaults to `base_url` + `"/oauth/callback"`.                           |
| `oidc_auto_provision` | Boolean | `false` | Automatically create a non-admin local user account on successful OIDC login if the email is not yet known in the database. |

---

### Email & SMTP Settings

Email delivery is disabled by default: the server boots and runs with none of these set. When disabled, administrators can still mint single-use password-reset links from the admin panel (the link is shown to the admin, not emailed). Set `smtp_host` to enable outbound email, which unlocks self-service "forgot password" links and email verification.

| Key                          | Type    | Default              | Description                                                                                                       |
| :--------------------------- | :------ | :------------------- | :---------------------------------------------------------------------------------------------------------------- |
| `smtp_host`                  | String  | `""`                 | The SMTP host address for delivering emails. When empty, email delivery is disabled.                              |
| `smtp_port`                  | Integer | `587`                | The SMTP port number (typically `587` for STARTTLS, `465` for implicit TLS, or `25` for unencrypted local relay). |
| `smtp_username`              | String  | `""`                 | The SMTP username for authentication.                                                                             |
| `smtp_password`              | String  | `"${SMTP_PASSWORD}"` | The SMTP password for authentication.                                                                             |
| `smtp_from`                  | String  | `""`                 | The "From" email address used as the sender (e.g. `noreply@example.com`).                                         |
| `smtp_tls_mode`              | String  | `"starttls"`         | SMTP TLS connection policy. Valid values: `"starttls"`, `"tls"`, `"none"`.                                        |
| `require_email_verification` | Boolean | `false`              | Enforce that new self-service registrations must verify their email address before logging in.                    |

---

### Logging Settings

| Key          | Type   | Default  | Description                                                                                |
| :----------- | :----- | :------- | :----------------------------------------------------------------------------------------- |
| `log_format` | String | `"json"` | The structured log output format. Valid values: `"json"` or `"text"`.                      |
| `log_level`  | String | `"info"` | The minimum level of logs to emit. Valid values: `"debug"`, `"info"`, `"warn"`, `"error"`. |

---

## Rationale for Split Path Prefixes

By default, route paths are split into three distinct prefixes:

- `/authlib-injector`: Standard Yggdrasil protocol endpoints hit by launchers and game servers.
- `/api`: Public API for management tasks (such as self-service user registration and player skin uploads).
- `/admin`: Privileged administrator API (such as user lookups, user deletions, and registration invites).

This path splitting is a deliberate operational security decision. It allows operators to configure their reverse proxies (such as Nginx, Traefik, or Cloudflare) to selectively expose only what is absolutely necessary:

- The public and launchers must be able to reach `<base_url>/authlib-injector` (for authentication and gameplay) and `<base_url>/textures` (for in-game skins to render).
- If self-registration is allowed, you can choose to expose `<base_url>/api` to the internet.
- The administrator path `<base_url>/admin` can be completely firewalled at the reverse proxy level. It can be blocked from external access and restricted to local internal networks, specific VPN IPs, or specific management hosts, keeping privileged operations secure.

---

## Management Authentication Modes and CSRF Security

The Public Management API (under `/api`) and the Administrative API (under `/admin`) accept two modes of authentication:

1. **HTTP Basic Authentication**: Primarily used by external scripts, CLI tools, and automated API integrations. Authentication credentials (`email:password`) are sent directly in each request's `Authorization` header. Since Basic auth credentials are self-authenticating, no CSRF validation is performed.
2. **Session Cookie Authentication**: Used exclusively by the browser-based Web UI. Upon successful login via `/web/api/login` or the browser OIDC flow, the server returns an `HttpOnly` session cookie named `minecrauth_session` with a maximum lifetime specified by `session_ttl_seconds`.

### CSRF Protection

To protect against Cross-Site Request Forgery (CSRF) attacks when using session cookie authentication, minecrauth enforces a strict CSRF policy for state-changing (mutating) HTTP requests:

- Any `POST`, `PUT`, `PATCH`, or `DELETE` request authenticated via the `minecrauth_session` cookie **must** include an `X-CSRF-Token` header.
- The CSRF token value must match the token associated with the session, which can be retrieved from the `GET /web/api/session` endpoint.
- If the `X-CSRF-Token` header is missing, empty, or does not match the session's token, the request will be rejected with a `403 Forbidden` status code.
- This header requirement is omitted for programmatic HTTP Basic authenticated requests.

---

_Note: For the absolute ground truth on configuration keys, defaults, and structural layout, please refer directly to the annotated [config.example.yaml](../config.example.yaml) in the repository root._
