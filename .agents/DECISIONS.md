# Technical Decisions

Technical decisions made by the project owner. Any AI tool working on this repository **must respect these decisions** and not revert them without explicit approval.

---

## Pure Go, single static binary, no cgo

**Date**: 2026-06-27
**Status**: Decided

The entire reason this project exists is that self-hosting Minecraft auth is usually a pain to deploy: the common options need cgo (gcc), a Node/npm/TypeScript toolchain for their web UI, and ship no prebuilt Docker image. We will be pure Go, compile to a single static binary, and publish a prebuilt multi-arch Docker image from day one.

**Reasoning**: deployment simplicity is the product's differentiator, not its feature count. A no-toolchain build is what makes `docker run` and forget possible. SQLite via `modernc.org/sqlite` keeps us cgo-free.

**Do not**: introduce cgo dependencies (dqlite, mattn/go-sqlite3), a Node build step, or anything that prevents a static cross-compiled binary.

---

## API first, Web UI last

**Date**: 2026-06-27
**Status**: Decided

Build the HTTP API (Yggdrasil protocol + management) well-organized, compilable, usable and "perfect" first. Only after that is solid do we discuss a Web UI.

**Reasoning**: user directive. The API is the core; the UI is a convenience layer and also the part that, done wrong (Node/TS), would destroy the deployment story.

**Do not**: start any Web UI work before the API phases are complete. If/when built, the UI must use Go `embed.FS` + server-rendered HTML, never a Node toolchain.

---

## Java Edition first, Bedrock deferred

**Date**: 2026-06-27
**Status**: Decided

Target Minecraft Java Edition and the Yggdrasil + authlib-injector ecosystem. Bedrock is out of scope for now and will be discussed separately later.

**Reasoning**: Java Edition is where Yggdrasil and authlib-injector live and where the deployment pain the project addresses is felt. Bedrock uses a different auth model.

**Do not**: add Bedrock-specific code paths until Java Edition is feature-complete and Bedrock has been explicitly scoped.

---

## Persistence behind a Store interface, starting on SQLite

**Date**: 2026-06-27
**Status**: Decided

All persistence sits behind a `Store` interface. The first and default implementation is SQLite (`modernc.org/sqlite`). Distributed backends of similar simplicity (rqlite, Uhaha) may be added later as alternative implementations. dqlite is rejected (cgo).

**Reasoning**: an auth server is tiny and mostly read-heavy; SQLite covers ~95% of cases. Hiding it behind an interface lets us add HA later without rewriting the domain.

**Do not**: leak SQL above the store package, or pick a backend that requires cgo.

---

## Project name and Go module path

**Date**: 2026-06-27
**Status**: Decided

The project is named `minecrauth`, Go module path `github.com/achetronic/minecrauth`.

**Reasoning**: confirmed by the owner.

**Do not**: rename without explicit approval.

---

## Registration model: self-service with username=email, invites, split admin/public API

**Date**: 2026-06-27
**Status**: Decided

Users self-register with username + password, where the username **is** the email. Admins can generate invite links. Crucially, the **public API and the admin API live under distinct route paths** so an operator can restrict what is exposed to the outside (e.g. only expose the public surface through the reverse proxy, keep admin bound to localhost or behind separate auth).

**Reasoning**: owner directive. The path split is a security/exposure-control measure: an admin must be able to fence off privileged operations from the public internet.

**Do not**: mix admin and public routes under the same path prefix. Do not assume a separate display username distinct from the email (username == email for now).

---

## User to Player cardinality: 1:N from the start

**Date**: 2026-06-27
**Status**: Decided

The data model is 1:N (one user owns many players) from day one, not 1:1-with-room.

**Reasoning**: owner wants the full model designed in from the start so nothing has to be retrofitted (bots, camera accounts). Designing 1:N up front avoids a painful schema and domain migration later.

**Do not**: collapse user and player into a single entity or assume a single player per user anywhere in the schema, domain, or API.

---

## Skins/capes deferred to phase 2 (but fully planned)

**Date**: 2026-06-27
**Status**: Decided

Skins and capes are out of the MVP and land in phase 2. This is a sequencing decision, not a scope cut: the end state must include the full texture feature set with no concessions. Each phase's TODOs must be explicit so iteration converges on total feature parity.

**Reasoning**: owner directive. Get the Yggdrasil core and accounts perfect first; bring textures in deliberately afterwards without leaving anything behind.

**Do not**: treat "phase 2" as "maybe never". Skins/capes are committed scope; only their timing is deferred.

---

## Production-readiness is a committed final phase (Phase 4)

**Date**: 2026-06-27
**Status**: Decided

The project is not complete until it is production-ready: a prebuilt multi-arch Docker image, GitHub pipelines that publish release binaries and packages/images to GHCR, a root README, and user documentation under `docs/`. Pipelines follow the conventions already in use in other achetronic projects (baifo, request-validator): GoReleaser v2 with `dockers_v2` (buildx multi-arch + SBOM), pinned actions, `setup-go` with `go-version-file: go.mod`. The publish workflow has a **double trigger**: on release publish AND manual `workflow_dispatch` with a boolean flag controlling the checkout.

**Reasoning**: owner directive. Easy deployment is the product's whole reason to exist, so the release/packaging story is core scope, not an afterthought. Reusing the established pipeline shape keeps consistency across the owner's repos.

**Do not**: ship without a prebuilt Docker image (the exact gap that makes self-hosting painful elsewhere). Do not invent a new pipeline shape; mirror baifo / request-validator. Do not treat README or `docs/` as optional.

---

# Recently closed / scope notes

## Admin model: impersonation, not duplicated admin-scoped resource routes

**Date**: 2026-06-28
**Status**: Decided

In the web UI, the admin manages any user's own resources (players, skins, capes) by IMPERSONATING that user (POST /admin/users/{id}/impersonate swaps the session cookie to one bound to the target with impersonated_by = real admin id; POST /web/api/stop-impersonation returns to the admin). Impersonation reuses the /me routes verbatim, so the UI needs no extra resource handlers. The /admin user-CRUD panel has list (paginated), create, delete, block/unblock and grant/revoke-admin. The API also exposes admin-scoped resource routes (/admin/users/{id}/players, .../skin, .../cape), added later for direct management without a session swap; both mechanisms coexist.

**Reasoning**: far less code than duplicated admin-scoped routes, and it gives the admin full "manage everything" capability the owner asked for.

**Do not**: remove impersonation as the web UI's way to manage other users' resources; it is the mechanism the SPA relies on.

---

## Admin CLI removed; administration is API-only

**Date**: 2026-06-28
**Status**: Decided

The separate minecrauth-admin CLI was removed. With a full HTTP API (and the web UI on top) a second binary only complicated the distroless image. There is one binary now.

**Reasoning**: owner directive. The CLI binary is redundant given the web UI and administrative API. Keeping a single binary simplifies packaging and image maintenance.

**Do not**: reintroduce a CLI binary; expose new admin capability through the HTTP API.

---

## Web UI is Vue 3 with no build, OpenAPI via swag v2

**Date**: 2026-06-28
**Status**: Decided

The web UI is split into ES-module components/views under webui/static/js (no bundler); Vue 3 global build and a pixel font (Press Start 2P, OFL) are vendored. The aesthetic is a hand-built Minecraft block look (square corners, hard bevel box-shadows, grass-block logo, grass/dirt/stone palette), not a CSS framework. The full HTTP API is documented with swag v2 (v2.0.0-rc5) OpenAPI 3.1 annotations, generated by `make openapi` into internal/openapi and served at /openapi.json and /openapi.yaml.

**Reasoning**: keeps the build system extremely fast and clean. No node_modules, no JS compilation step.

**Do not**: add a Node/npm/Vite build step or a CSS utility framework; hand-edit the generated spec (regenerate with make openapi).

---

## Web UI: Vue 3 without a build step, plus the backend it requires

**Date**: 2026-06-27
**Status**: Decided

The Web UI lives in webui/ and is served from the binary via Go embed.FS. It uses Vue 3 in its standalone build (vendored vue.global.prod.js, no npm, no Vite, no bundler, no Node anywhere in the build or image). Styling is hand-written CSS with a shared design-token palette (no utility framework), aiming for an elegant, sober look consistent across all views. Views: /login, /players, /account, /admin-ui, /reset, /verify, /oauth/callback.

The UI requires backend additions, all OFF/compatible (they never touch the Yggdrasil token flow):
1. Browser sessions: DB-backed (SQLite) opaque session tokens in an HttpOnly cookie (Secure when BaseURL is https, SameSite=Lax), revocable so logout and block work. CSRF protection via a double-submit token required on cookie-authenticated mutating requests (HTTP Basic requests are exempt, they carry no ambient credential).
2. The management auth middleware accepts EITHER a session cookie (with CSRF on mutations) OR HTTP Basic, populating the same user context, so the existing /api and /admin routes serve the UI without duplication.
3. User.Blocked field (store migration): blocked users cannot authenticate on any plane (web login, Yggdrasil authenticate, Basic) and their sessions/tokens are revoked.
4. Admin manages users via a user-CRUD panel (list, delete, block/unblock, grant/revoke admin, impersonate) under /admin. The web UI manages another user's own resources (players, skins, capes) by IMPERSONATING that user: a dedicated endpoint mints a session bound to the target user while recording impersonated_by (the real admin's id) for the banner and audit trail; impersonation reuses the existing /me routes verbatim. While impersonating, the UI shows a banner and a "return to admin" action; a stop-impersonation endpoint restores the admin's own session. Impersonation was chosen as the UI mechanism because it gives the admin full "manage everything" capability with minimal UI code. Note: the API additionally exposes admin-scoped resource routes (/admin/users/{id}/players, .../skin, .../cape), added later for direct management without a session swap, so both paths now exist.
5. OIDC browser authorization-code flow (with state + PKCE): /web/api/oidc/login starts it, /oauth/callback completes it and sets the session. The existing bearer-id-token-as-password OIDC connector stays for the API.

**Reasoning**: keeps the single-binary, no-cgo, no-Node deployment intact while giving a real Vue SPA; DB-backed sessions match the opaque-token philosophy and make block / logout correct; reusing the existing API avoids a duplicated endpoint surface.

**Do not**: introduce a Node/npm/Vite build step or a CSS utility framework; make the Web UI or its sessions affect the Yggdrasil token flow; skip CSRF on cookie-auth mutations; let a blocked user authenticate anywhere.

---

## OIDC connector shape: bearer-ID-token-as-password (pre-Web-UI), pure-Go libs allowed

**Date**: 2026-06-27
**Status**: Decided

The management Authenticator interface is Authenticate(ctx, email, password). Classic OIDC is a browser redirect flow, which does not exist yet (Web UI is the last thing). To deliver a usable OIDC connector now WITHOUT a browser, the OIDCAuthenticator implements the same interface by treating the supplied "password" as an OIDC ID token (bearer-as-password): it verifies the token against the configured IdP via OIDC discovery + JWKS (issuer, audience, expiry, signature), then maps the verified email claim to a local user. It is wired as part of a composite authenticator: local password first, then OIDC token, so password auth keeps working. OIDC is OFF unless configured (no IdP required to boot). JWT/JWKS verification uses the de-facto pure-Go standard libraries github.com/coreos/go-oidc/v3 and golang.org/x/oauth2 rather than a hand-rolled verifier, because rolling your own JWT signature verification is a security footgun. These are pure-Go, no cgo, consistent with the project rules.

**Reasoning**: fits the existing interface, needs no browser, keeps deploy friction zero (off by default), and uses trusted crypto libraries for a security-critical path. The full browser authorization-code flow belongs with the Web UI phase.

**Do not**: hand-roll JWT/JWKS signature verification; require an IdP to run the server; make OIDC touch the Yggdrasil token flow (it remains management-plane only).

---

## Management API authentication: HTTP Basic + IsAdmin gate

**Date**: 2026-06-27
**Status**: Decided

The management plane (account/player CRUD) authenticates requests with HTTP Basic auth (email:password) verified through the existing auth.Authenticator (bcrypt). The public management surface lives under one path prefix (e.g. /api) and the admin surface under a distinct prefix (e.g. /admin); admin routes additionally require the authenticated user to have IsAdmin=true. The path split lets an operator firewall the admin surface (bind to localhost / separate proxy) as decided in P2.

**Reasoning**: reuses the Authenticator we already built, needs no new token type for humans/scripts, and is the simplest secure default that honors the P2 path-split directive. A dedicated admin API key can be added later if wanted.

**Do not**: put admin operations under the public prefix; do not skip the IsAdmin check on admin routes; do not invent a second password/token scheme without owner approval.

---

## P3 - Token strategy and OpenID Connect: DECIDED

**Date**: 2026-06-27
**Status**: Decided

Two independent planes, settled separately:

1. **Minecraft plane (Yggdrasil)**: **opaque random DB tokens**, not JWT. The launcher treats the accessToken as an opaque string; Yggdrasil mandates invalidate/signout, which forces a DB hit anyway, so JWT's stateless validation buys nothing and only adds key-rotation and expiry pain (a common source of spurious "Invalid session" reports). `validate` is an indexed SELECT, `invalidate` a DELETE, `signout` a `DELETE WHERE user_id=`.
2. **Management plane (admin/public API + future web)**: authentication sits behind an `Authenticator` interface. MVP ships **local password auth** (username==email). **OpenID Connect is a management-plane concern only and never touches the Yggdrasil flow.**

Note: this is distinct from the **mandatory RSA signing of profile/texture properties**, which is required regardless and unrelated to session-token format.

**Reasoning**: owner agreed. Keeps the Minecraft path simple and correct; keeps OIDC where it actually applies (humans/scripts managing accounts); preserves the no-friction deploy story (no external IdP required to boot).

**Do not**: emit JWTs for Yggdrasil tokens. Do not wire OIDC into authserver/ sessionserver. Do not require an external IdP to run the server.

---

## P6 - MVP scope confirmation

**Date**: 2026-06-27
**Status**: Decided

The MVP must include: full CRUD for users AND players (1:N), authentication of BOTH planes working (management password auth + Yggdrasil opaque tokens), the full API pre-design (public and admin surfaces on distinct paths), and the Yggdrasil/ authlib-injector protocol surface.

**OIDC in the MVP (resolved)**: the MVP ships ONLY the `Authenticator` interface designed from the start, with the **local password implementation concrete** and the **concrete OIDC connector deferred** to a later iteration. The interface costs nothing and adds no deploy friction; a concrete OIDC connector would require an external IdP, which is exactly the deploy friction we reject. OIDC is the first item of the iteration after the MVP.

**Do not**: cut user or player CRUD, or either auth plane, from the MVP. Do not require an external IdP to run the MVP. Do not implement a concrete OIDC connector inside the MVP.

---

## Migration of Configuration to single YAML file loaded with --config

**Date**: 2026-06-29
**Status**: Decided

The entire application configuration has been migrated from approximately ~38 `MINECRAUTH_*` environment variables to a single YAML configuration file loaded via a required `--config` command-line flag. 

**Reasoning**:
- **Self-documenting**: Structured YAML is much cleaner and allows for comments, easier grouping, and clear schema definition.
- **Support for Fallbacks**: Fallback API servers can be configured cleanly as a list of nested objects directly inside YAML instead of complex, hard-to-parse JSON strings inside environment variables.
- **Secrets injection**: We retain the security benefit of environment variables by passing the file content through environment-variable expansion (`os.ExpandEnv`) BEFORE YAML decoding. Secrets like SMTP/OIDC passwords can be specified as `${VAR}` and injected from the environment, keeping them out of plain-text config files.
- **Fail-fast validation**: Strict parsing is enabled (`KnownFields` strict parsing), which means any unknown keys or typos in the configuration file will cause the server to fail fast and exit with a clear error at startup.
- **Logging configuration**: Logging has been brought into the configuration structure as well (`log_format` and `log_level`), completely removing the legacy `LOG_FORMAT` and `LOG_LEVEL` environment variables.

**Do not**:
- Restore any direct `MINECRAUTH_*` environment variables or legacy logging environment variables.
- Bypass strict YAML decoding or environment variable expansion on the configuration file.

---

## Game Password (Yggdrasil-only credential)

**Date**: 2026-06-29
**Status**: Decided

A user can set an independent "game password" distinct from their account (management-plane) password. When a game password is set, the launcher/Yggdrasil plane accepts *only* this credential; the account password is disabled for the game launcher but remains the only way to log into the web management panel.

**Reasoning**: Decouples in-game authentication from web-plane administrative access. If a player shares their launcher credentials or uses a less secure third-party launcher, their primary account administration panel remains protected.

**Do not**: Allow the primary account password to bypass the game password check on the Yggdrasil plane when a game password has been set.

---

## Two-Factor Authentication (TOTP)

**Date**: 2026-06-29
**Status**: Decided

TOTP-based 2FA is implemented to protect the management/web plane *only*. It features a two-step login process (where primary authentication returns a temporary token indicating TOTP is required), server-side secure QR code and secret generation, and recovery codes for account recovery.

**Reasoning**: Standard security for account administration. Since launchers cannot natively process a 2FA prompt during Yggdrasil auth, TOTP is strictly isolated to the browser login flow, preventing game clients from ever seeing or requiring 2FA codes.

**Do not**: Require TOTP verification on the Yggdrasil launcher plane, or bypass 2FA checks on the management/web plane once enabled.

---

## WAL-consistent Backup and Atomic Restore

**Date**: 2026-06-30
**Status**: Decided

The administrative backup feature produces a `.tar.gz` archive of the entire server state (SQLite database, textures, config, and signing key). Database backups are created via SQLite's `VACUUM INTO` command to ensure consistent snapshots even with WAL mode active. Restores are staged as `.restore-pending.tar.gz` and applied atomically at the next application startup before the database is opened.

**Reasoning**: Guarantees zero database corruption during backups under active writes, and eliminates partial-overwrite states during restores by applying changes atomically on a fresh boot cycle.

**Do not**: Attempt to hot-restore the SQLite database over an active connection pool, or run backups by directly copying the raw database file.

---

## Password Reset and Email Verification

**Date**: 2026-06-30
**Status**: Decided

Admins can mint single-use password reset tokens/links directly from the UI, which function instantly even without an SMTP server configured. Self-service password resets and email verification are gated behind an SMTP mailer config. All endpoints utilize strict anti-enumeration techniques (returning identical status responses regardless of whether the email exists).

**Reasoning**: Ensures administrators can always recover users or verify accounts locally, while protecting public endpoints from automated scanning and account-harvesting attacks.

**Do not**: Disclose whether an email address exists or is registered in reset/verification API responses.

---

## Observability (Health, Readiness, and Metrics)

**Date**: 2026-06-30
**Status**: Decided

The HTTP server exposes dedicated observability endpoints: `GET /healthz` for process liveness, `GET /readyz` for readiness (actively pinging the SQLite database with a 2-second timeout), and `GET /metrics` returning standard Prometheus format metrics (including HTTP request counters and latency histograms partitioned by route).

**Reasoning**: Essential for robust container orchestration and cloud deployments, allowing reverse proxies, load balancers, or Kubernetes to monitor health and collect precise telemetry.

**Do not**: Expose raw database connection details or allow the readiness probe to block indefinitely.
