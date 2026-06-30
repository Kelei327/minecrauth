# AGENTS.md - minecrauth

A self-hostable, production-ready authentication server for Minecraft: Java Edition that speaks the Yggdrasil protocol and is compatible with authlib-injector. It acts as a drop-in replacement for Mojang's authentication infrastructure: launchers (Fjord/Freesm, HMCL, Prism) and vanilla Java servers point to this server instead of Mojang's.

Written in pure Go (no cgo, no C toolchain required), it compiles to a single static binary, ships with a prebuilt multi-arch Docker image, and serves its own Vue 3 web UI directly from memory via an embedded filesystem. No Node build steps or separate web/DB service stacks are needed; everything, including the SQLite database, runs inside a single process and a single state directory.

Module path: `github.com/achetronic/minecrauth`
License: Apache-2.0
Default port: 25585
Docker Image: `ghcr.io/achetronic/minecrauth`

## What it is and is NOT

* **It IS** a self-hostable auth server for Minecraft: Java Edition.
* **It IS** a single static binary with an embedded Vue 3 web UI, SQLite, and a zero-dependency build (no cgo, no Node).
* **It IS NOT** a Microsoft/Mojang account proxy. You cannot log in with real Microsoft accounts. However, it supports mixed-auth fallback: you can configure a real Mojang or other Yggdrasil server as a fallback so your game server accepts both local and Mojang accounts.
* **It IS NOT** compatible with Bedrock Edition.

## Why it exists (The Differentiator)

Self-hosting Minecraft auth tends to be operationally heavy: a C toolchain (cgo), a
Node/npm build for the web UI, no prebuilt image to pull, and dozens of config knobs,
or a PHP / multi-service stack with its own web server and database to babysit.

minecrauth takes the opposite approach: pure Go (no cgo), a single static binary, a
prebuilt multi-arch Docker image, a Vue web UI served from `embed.FS` with no build
step, and minimal config. `docker run` and walk away.

minecrauth provides a pure-Go alternative with a single static binary, uses `modernc.org/sqlite` for a zero-cgo embedded database, ships official multi-arch Docker images, serves an embedded Vue UI with no frontend build step, and keeps configuration minimal.

## Two Independent Auth Planes

The system operates with a critical mental model separating the game's authentication from the web/management administration:

1. **Minecraft Plane (Yggdrasil):** Uses opaque, random database-backed tokens (not JWT). The `/authserver/validate` endpoint uses an indexed `SELECT`, `/authserver/invalidate` performs a `DELETE`, and `/authserver/signout` executes a `DELETE WHERE user_id`. Profile and texture properties returned are RSA-signed (mandatory). If a user sets a dedicated game password, the launcher must use it, and the master account password is deactivated for game logins; otherwise, the master account password is the default for game authentication.
2. **Management Plane (Web UI & Admin/Public API):** Authentication is handled by a composite authenticator (local passwords and/or optional OIDC). Multi-factor authentication (TOTP/2FA) is enforced exclusively on this plane (the game launcher does not prompt for 2FA, utilizing the game password instead). OIDC authentication never enters the Yggdrasil game login flow.

## HTTP Surface

Path prefixes are configurable. The default paths are shown below:

### Yggdrasil Protocol (default prefix: `/authlib-injector`)
* `GET  /` - authlib-injector metadata document (advertises public keys, skin domains, and endpoint details)
* `POST /authserver/authenticate` - validates user + password and returns an `accessToken` and selected profile
* `POST /authserver/refresh` - refreshes an `accessToken`, optionally binding it to a new `selectedProfile` if owned by the user
* `POST /authserver/validate` - checks token validity
* `POST /authserver/invalidate` - invalidates a specific token
* `POST /authserver/signout` - invalidates all tokens associated with a user
* `POST /sessionserver/session/minecraft/join` - client-side handshake join registration
* `GET  /sessionserver/session/minecraft/hasJoined` - game server-side session verification
* `GET  /sessionserver/session/minecraft/profile/{uuid}` - returns player profile and signed textures
* `POST /api/profiles/minecraft` - bulk player name-to-UUID lookup

Reference specs:
* authlib-injector Yggdrasil server spec: https://github.com/yushijinhun/authlib-injector/wiki/Yggdrasil-%E6%9C%8D%E5%8A%A1%E7%AB%AF%E6%8A%80%E6%9C%AF%E8%A7%84%E8%8C%83
* Minecraft Wiki Yggdrasil: https://minecraft.wiki/w/Yggdrasil
* Minecraft Wiki Mojang API: https://minecraft.wiki/w/Mojang_API

### Public Management API (default prefix: `/api`)
* `/api/register` - self-service registration
* `/api/me` - self profile details and player/skin/cape CRUD
* `/api/me/totp/setup`, `/api/me/totp/confirm`, `/api/me/totp/disable` - 2FA enrollment/disabling
* Account recovery endpoints (forgot/reset password, verify/resend email, set/clear game password)

### Admin API (default prefix: `/admin`)
Requires the administrative role (`IsAdmin`). Located on a separate configurable prefix to permit firewall separation.
* User CRUD (paginated list, create, delete, block/unblock)
* Administrative grants (grant/revoke admin, TOTP disable)
* Reset token generation (mints a single-use password reset link, functional without SMTP configured)
* Account impersonation and backups (download and restore operations)

### Browser API (default prefix: `/web/api`)
* Login (two-step flow when TOTP is active: first returns `{totpRequired, totpToken}` with no session, then second endpoint verifies the code to establish the session)
* Session status, logout, frontend config, stop impersonation, and OIDC auth code/callback handlers

### Operations & Metrics
* `GET /healthz` - liveness probe
* `GET /readyz` - readiness probe (attempts a SQLite ping with a 2-second timeout)
* `GET /metrics` - Prometheus metrics (requests counter and latency histograms)
* `GET /openapi.json`, `GET /openapi.yaml` - generated OpenAPI 3.1 specification (swag v2)

### SPA Frontend & Static Assets
* `/`, `/login`, `/players`, `/account`, `/admin-ui`, `/reset`, `/verify`, `/oauth/callback` - SPA routing paths
* `/static/*` - vendored JavaScript and assets
* `/textures/*` - skin and cape media files

## Key Gotchas

1. **You cannot proxy real Microsoft accounts.** Users cannot log in with genuine Microsoft accounts directly. Local registrations, or delegating via mixed-auth fallbacks, are the only paths.
2. **RSA profile signing is mandatory.** Game clients verify texture signatures against the public key advertised in the metadata document. A missing or invalid key stops skins from rendering.
3. **`base_url` must be correct.** Misconfiguration of `base_url` in the config file causes authlib-injector clients to silently fail skin loading.
4. **No cgo, ever.** Compilation is strictly pure Go. The project uses `modernc.org/sqlite` to maintain a cross-compilation pipeline without a C toolchain.
5. **User vs Player are distinct 1:N entities.** Do not collapse users and players. A single user account can own and manage multiple players (1:N relationship).
6. **No Node build in the web UI.** The Vue 3 SPA is served entirely from an embedded filesystem (`embed.FS`). It uses a vendored, non-compiled Vue runtime with ES modules.

## Documentation Index

Explore the rest of the `.agents/` living documentation directory for deeper insights:
* [ARCHITECTURE.md](./ARCHITECTURE.md): Describes the design architecture, directory layout, and the handshake data-flow diagram.
* [CONVENTIONS.md](./CONVENTIONS.md): Codification of development rules, logging standards, testing, and formatting guidelines.
* [DECISIONS.md](./DECISIONS.md): Log of structural decisions, chosen libraries, and architectural compromises.
* [OBJECTIVES.md](./OBJECTIVES.md): Defines the milestones, goals, and delivery phases of the system.
* [TODO.md](./TODO.md): Active tracking list of remaining items and feature backlog.
