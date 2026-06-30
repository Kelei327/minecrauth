# Objectives

This document captures the scope and goals of minecrauth: a self-hostable, Yggdrasil-compatible authentication server for Minecraft Java Edition, designed to be trivially easy to deploy.

## North Star

The north star of minecrauth is to be the Minecraft auth server you deploy with a single `docker run` and forget.

Most self-hosted Minecraft auth servers fall short on operations, not features: they
need a C toolchain (cgo), a Node/npm/TypeScript build for the web front end, ship no
prebuilt Docker image, and pile up dozens of config options, or run as a PHP / heavier
multi-service stack.

minecrauth differentiates by being: **pure-Go, no cgo, single static binary, prebuilt multi-arch Docker image, and minimal config**. The web UI serves Vue 3 straight from Go's `embed.FS` with zero Node or bundler dependencies.

---

## Compatibility Reality

- **No Microsoft/Mojang proxy**: You cannot log in with a real Microsoft account to authenticate custom clients against official servers. That path is closed.
- **Yggdrasil protocol**: minecrauth implements the Yggdrasil protocol (used by Minecraft since 1.6) compatible with [authlib-injector](https://github.com/yushijinhun/authlib-injector), the de-facto standard javaagent for custom auth servers.
- **Drop-in replacement**: It functions as a drop-in replacement for Mojang's auth in launchers (Fjord/Freesm, HMCL, Prism) and on vanilla servers via JVM arguments.
- **Java Edition only**: Bedrock Edition is explicitly out of scope.

---

## Concept Glossary

- **User**: The account that logs in to the management plane (credentials, email/OIDC). Internal to the server.
- **Player**: The in-game character (name + UUID + skin/cape). What Minecraft sees.
- **User-to-Player cardinality (1:N)**: One user account can own multiple players. This supports "camera accounts" for spectating/content creation or multiple farming/AFK bots logged in simultaneously.
- **accessToken / clientToken**: Issued at login, presented by the launcher to join servers, and validated by the game server during the join handshake.
- **Profile signing (RSA)**: The server holds an RSA 4096 keypair to sign profile properties (textures) which the client verifies against the public key published in the metadata.
- **online-mode / offline UUID**: Deterministic UUID derivation from a player's name, matching offline-mode server behavior.

---

## Delivered Feature Set

### Yggdrasil Core
- Full Yggdrasil API: `/authserver/{authenticate,refresh,validate,invalidate,signout}`.
- Handshake endpoints: `/sessionserver/session/minecraft/{join,hasJoined}` and profile lookup.
- Bulk name-to-UUID resolution at `/api/profiles/minecraft`.
- RSA profile signing and authlib-injector metadata document at the API root.

### Accounts & Players (1:N)
- Self-service registration (username == email).
- Invite-only signup option (admin-generated invite tokens).
- Dynamic player CRUD under user accounts up to configurable limits.
- UUID generation policy (random or offline-mode deterministic).
- Custom UUID selection at player creation for migration convenience.
- Admin roles for user blocking, deletion, and elevated privileges.

### Skins & Capes
- Texture upload (skins and capes) via file or direct URL.
- High-resolution skin support (>64x64).
- Classic/slim arm-model autodetection and viewer toggle.
- `ForwardSkins`: Fallback forwarding to fetch textures from Mojang if the local player has none.
- `OfflineSkins`: Resolving textures for offline-mode UUIDs.

### Interop & Mixed-Auth
- `FallbackAPIServers`: Upstream delegation (e.g., to Mojang), enabling a single game server to accept both minecrauth accounts and real Microsoft accounts.
- `DenyUnknownUsers`: Use minecrauth as a whitelist, letting only registered users connect even if they authenticate via Mojang.

### OIDC (Federated Identity)
- Seamless login and registration on the management/web plane via OpenID Connect (Keycloak, Kanidm, Google, etc.).
- Dual-mode OIDC verification: browser-based Authorization Code Flow with state/PKCE, and API-based bearer-ID-token-as-password for non-browser tooling. OIDC is entirely a management-plane concern and never touches the Yggdrasil flow.

### Web UI
- Responsive, zero-build SPA built with Vue 3 and hand-written CSS, utilizing Go's `embed.FS`.
- Blocky Minecraft aesthetic (square corners, hard bevel box-shadows, grass/dirt/stone palette, Press Start 2P pixel font for wordmark).
- Dedicated interfaces for login (with OIDC and TOTP prompts), player management (with a 3D skin viewer), account settings (for 2FA, game password, and credential modification), and an admin panel (for User CRUD, invites, and backup downloads/restores).

### Operations, Hardening & Security
- **Game password**: A distinct game-only credential for the Yggdrasil plane. When set, only the game password is accepted by launchers, protecting the management password from being exposed to game clients.
- **TOTP/2FA**: Protects the web/management plane only (two-step login, recovery codes, server-side QR generation).
- **Password reset & email verification**: Admin-generated single-use reset links (which require no SMTP setup), alongside self-service "forgot password" and email verification gated behind SMTP with anti-enumeration protections.
- **Backup & Restore**: High-reliability .tar.gz backups (using SQLite VACUUM INTO for WAL consistency, capturing the database, signing key, textures, and config). Atomic restore applied automatically on startup if staged.
- **Observability**: Dedicated liveness (`/healthz`), readiness (`/readyz`), and Prometheus metrics (`/metrics`) endpoints with latency histograms.
- Rate limiting and request body size constraints.

---

## How It Was Built

The project was built in phases following a strict API-first constraint. The Yggdrasil protocol and management API were completely verified and stable before the Web UI was introduced. The Web UI avoids a Node/npm build step by serving standalone Vue 3 via `embed.FS`. The codebase is complete, with a few remaining backlog items documented in `TODO.md`.

---

## Non-Goals

- Bedrock Edition support.
- Functioning as a Microsoft/Mojang account proxy.
- Adding a Node/npm/Vite compilation pipeline.
- Introducing `cgo` dependencies.
