# Production Deployment Notes

Deploying minecrauth in a production environment is designed to be highly straightforward. This guide covers operational best practices, security hardening, backups, and networking.

## Embedded Web UI Deployment

Unlike other authentication servers that require compiling a frontend using heavy Node.js, npm, or TypeScript toolchains, minecrauth comes with a fully pre-compiled Single Page Application (SPA) Web UI embedded directly inside the main static Go binary.

- **No Separate Web Server**: You do not need a separate web server to host the static assets of the Web UI. The Go binary automatically serves them from the root route `/` and `/static/`.
- **Gated Access**: The user dashboard (`/players`) is accessible to any authenticated user. The administrative dashboard (`/admin-ui`) is strictly gated and accessible only by users with the admin role. An unauthenticated user browsing to `/` is automatically redirected to the `/login` page.

## Reverse Proxy and TLS Termination

In a production environment, you should always run minecrauth behind a secure reverse proxy (such as Nginx, Traefik, Caddy, or HAProxy) to handle HTTPS (TLS termination).

### The BaseURL Requirement

You must configure the `base_url` key in your configuration file to match the externally reachable HTTPS address of your authentication server.
Example: `base_url: "https://auth.my-server.com"`

If there is a mismatch between the externally requested domain and your `base_url`:

- **In-game skins will completely break.** When a game client requests a player profile, minecrauth returns absolute URLs pointing to the skin files (e.g. `https://auth.my-server.com/textures/<hash>`).
- Minecraft clients enforce a security check: they verify that the texture URL's host matches the allowed skin domains published in your server's metadata document (which is derived directly from the domain of `base_url`).
- If the domain does not match, the game client will silently discard the skin and fall back to the default Steve or Alex textures.

Furthermore, `base_url` is used for critical Web UI and OIDC security components:

- **OIDC Redirect URI**: The default OAuth 2.0 redirect URL used during browser OIDC logins is derived as `<base_url>/oauth/callback` unless `oidc_redirect_url` is explicitly configured.
- **Secure Cookie Flag**: If `base_url` uses the `https` scheme, minecrauth will automatically set the `Secure` attribute on browser session cookies (`minecrauth_session`) and OIDC temporary state cookies. This ensures that session cookies are never transmitted over unencrypted HTTP connections. Always use `https` in production.

### Rate Limiting and Client IPs

To protect against distributed denial-of-service and brute-force attacks, minecrauth uses a strict per-IP token-bucket rate limiter.

- For maximum security against IP-header spoofing, minecrauth reads the client's IP address directly from the socket connection (`r.RemoteAddr`).
- It completely ignores HTTP headers such as `X-Forwarded-For` or `X-Real-IP`.

If you run minecrauth behind a standard reverse proxy:

1. The proxy terminates TLS and opens a new connection to minecrauth.
2. minecrauth sees the local IP of your proxy (such as `127.0.0.1` or `172.18.0.2`) as the source of all requests.
3. This will cause all clients to share a single rate-limiting bucket, causing legitimate clients to be blocked under heavy load.

#### Recommended Solutions

- **Option A: Use Proxy Protocol.** Configure your reverse proxy to append the Proxy Protocol header to TCP connections and run minecrauth behind a proxy-protocol aware load balancer or direct network.
- **Option B: Direct TCP / Host Network.** If possible in your container environment, run minecrauth using Docker's host networking mode (`--net=host`) so that the socket connects directly to the outer interface.
- **Option C: Adjust Rate Limits.** If you must use a standard HTTP proxy without IP preservation, you must raise the rate-limiting values to represent the aggregate load of your entire player base:
  ```yaml
  rate_limit_rps: 200.0
  rate_limit_burst: 500
  ```

---

## State Directory Layout

All stateful data is kept inside the single directory specified by `state_dir` (default is `./data`).

```text
/data
├── minecrauth.db   # The SQLite database file
├── signing.key     # PEM-encoded RSA private key for profile signing
└── textures/       # Folder containing content-addressed skin and cape PNGs
    ├── 3b/bdf87ca...png
    └── e2/3ee7e49...png
```

### 1. SQLite Database (`minecrauth.db`)

Holds your registered users, player profiles, active session tokens, and invite codes.

### 2. Signing Key (`signing.key`)

An RSA private key generated automatically on first launch.

- **Important:** If this key is lost or deleted, minecrauth will generate a new one on restart.
- However, generating a new key invalidates all previously signed player texture payloads cached by game clients. If the client game has cached textures signed with your old key, the client will fail to render the skins and print signature validation errors until they restart their game launcher.
- Secure and back up this file.

### 3. Textures Directory (`textures/`)

Uploaded skins and capes are stored using content-addressed hashes. If two players upload identical skin files, they are stored as a single file on disk, minimizing space consumption.

---

## Backups

minecrauth has built-in backup and restore, so you don't need to script `sqlite3` or
`tar` yourself.

### Creating a backup

An admin can download a full backup as a single `.tar.gz` from the admin UI (the Backup
tab) or directly from the API:

```bash
curl -fsS https://auth.example.com/admin/backup \
  --user "admin@example.com:your-password" \
  -o minecrauth-backup.tar.gz
```

The archive is consistent even while the server is running: the database is captured
with SQLite's `VACUUM INTO` (a WAL-safe snapshot, no `-wal`/`-shm` files), bundled with
the signing key, the textures directory, and the config. Never copy `minecrauth.db`
file-by-file from under a running server; use this instead.

Schedule it from cron with the retention you want:

```bash
#!/bin/bash
set -euo pipefail
BACKUP_DIR="/var/backups/minecrauth"
DATE=$(date +%F-%H%M%S)
mkdir -p "$BACKUP_DIR"

curl -fsS https://auth.example.com/admin/backup \
  --user "admin@example.com:$ADMIN_PASSWORD" \
  -o "$BACKUP_DIR/minecrauth-$DATE.tar.gz"

# Retain only the last 7 days
find "$BACKUP_DIR" -type f -mtime +7 -delete
```

### Restoring

Upload an archive to `POST /admin/restore` (or use the Backup tab). The server validates
it and stages it as `.restore-pending.tar.gz` in the state directory; it does **not**
overwrite the live data on the fly. The restore is applied atomically on the next
startup, before the database is opened, then the staged file is consumed. So:

1. Upload the archive (admin UI or API).
2. Restart minecrauth.
3. On boot it detects the pending restore, swaps the state in, and starts on the
   restored data.

---

## Hardening and Firewalling the Admin API

As discussed in the configuration reference, the administrative management API is mounted under its own prefix (default `/admin`).

Since administrative actions (such as user deletion and invite generation) can disrupt services, you should block external public access to this path.

### Example Nginx Firewall Configuration

Add a rule to your Nginx virtual host to block all external requests to the admin prefix:

```nginx
server {
    listen 443 ssl;
    server_name auth.example.com;

    # Global proxy settings
    proxy_set_header Host $host;
    proxy_redirect off;

    # 1. Public textures (Must be publicly accessible)
    location /textures/ {
        proxy_pass http://127.0.0.1:25585;
    }

    # 2. Launchers and Game Servers (Must be publicly accessible)
    location /authlib-injector/ {
        proxy_pass http://127.0.0.1:25585;
    }

    # 3. Public User APIs (Self-service registration, skin updates)
    location /api/ {
        proxy_pass http://127.0.0.1:25585;
    }

    # 4. Administrative API (Firewalled)
    location /admin/ {
        # Allow connections only from secure management networks
        allow 192.168.1.0/24;
        allow 10.8.0.0/24;     # Management VPN range
        allow 127.0.0.1;       # Localhost
        deny all;              # Reject everyone else

        proxy_pass http://127.0.0.1:25585;
    }
}
```

---

## Fallback (Mixed Auth) and OIDC Integration

Detailed steps to enable advanced configurations.

### Enabling Fallback / Mixed Auth

By setting fallback servers, you can allow players with official Mojang accounts to join your game server alongside local players.

1. Ensure the fallback server array `fallback_api_servers` is configured in your config file (see the structure details in [Configuration Reference](configuration.md)).
2. To enable players to automatically load their Mojang skins without manual upload, set:
   ```yaml
   forward_skins: true
   ```
3. To resolve offline-UUID skin queries for offline servers, set:
   ```yaml
   offline_skins: true
   ```

### Enabling OIDC for Management

To integrate with your existing authentication provider (e.g. Keycloak):

1. Set the issuer discovery URL, client ID, and client secret:
   ```yaml
   oidc_issuer: "https://keycloak.example.com/realms/myrealm"
   oidc_client_id: "minecrauth-management"
   oidc_client_secret: "${OIDC_CLIENT_SECRET}"
   ```
   _(Using `${OIDC_CLIENT_SECRET}` allows you to pass secrets in via Docker/Kubernetes secrets/environment variables without committing them to the file.)_
2. Enable automatic account creation on first successful OIDC login:
   ```yaml
   oidc_auto_provision: true
   ```
   _Note:_ If `oidc_auto_provision` is set to `false`, users will not be able to log in via OIDC unless an administrator first creates a local user account matching their OIDC verified email.
