# Architecture - minecrauth

This document describes the actual architecture, package layout, and data-flow invariants of the minecrauth server.

## Overview

minecrauth is a single-process authentication server. It exposes the Yggdrasil protocol so launchers and game servers can authenticate players, a JSON management API for user self-service and administration, and a browser-facing web UI. 

The software architecture strictly enforces a separation of concerns across three layers:

1. **Protocol Layer:** Translates raw HTTP wire formats into structured domain calls. This layer holds no business logic.
2. **Domain Layer:** Enforces business rules regarding users, players, authenticators, tokens, skin rules, registration, and signing.
3. **Persistence Layer:** Exposes a unified data store abstraction, ensuring database-specific details are completely isolated.

All components run in a single process. SQLite is embedded via a cgo-free driver, and the web UI is compiled directly into the binary assets.

## Core Architectural Invariants

To keep the codebase maintainable and decoupled, the following invariants must be preserved:
* **The domain layer never imports `net/http`:** Domain models, authenticators, and services must remain completely decoupled from transport protocols. Handlers in the protocol layer are responsible for mapping HTTP requests to domain calls and converting domain responses or errors back into HTTP.
* **The `Store` interface is the only persistence path:** No SQL queries, database drivers, or schema-specific structures may leak above the `internal/store` boundary. 
* **The `signing` package is the sole owner of the private key:** The RSA private key used to sign Yggdrasil texture profiles must never be read, exposed, or handled by any package other than `internal/signing`.
* **PRAGMAs are set on the DSN, not per-Exec:** the store opens SQLite through `database/sql`, which keeps a connection pool. `foreign_keys`, `busy_timeout` and `journal_mode=WAL` are passed in the DSN so they apply to every pooled connection (running a PRAGMA via a single `Exec` would configure only one connection and silently leave cascade deletes unenforced on the rest).

## Folder and Package Structure

The actual project structure on disk is organized as follows:

```
minecrauth/
  cmd/
    minecrauth/        # Main server entry point
  internal/
    accounts/          # User + player domains (1:N) and account policies
    auth/              # Yggdrasil tokens, authenticators (local, OIDC, composite), and web sessions
    backup/            # SQLite WAL-consistent backups and atomic restore staging
    config/            # Configuration structs, validation, and env variable expansion
    fallback/          # Delegation to upstream Yggdrasil/Mojang auth servers
    httpserver/        # HTTP routing, middleware, session handlers, and lifecycle
    logging/           # Structured log/slog setup and log formats
    mailer/            # Mailer interfaces, SMTP, and HTML styling templates
    metrics/           # Prometheus HTTP counters and latency histogram exports
    openapi/           # Generated OpenAPI 3.1 specification (swag v2)
    signing/           # RSA keypair management and cryptographic profile signing
    store/             # Unified database storage interfaces
      sqlite/          # Pure-Go modernc.org/sqlite implementation and migrations
    textures/          # Content-addressed skin/cape storage and dimension verification
    yggdrasil/         # Yggdrasil/authlib-injector protocol layer and DTOs
  webui/               # Embedded filesystem hosting the no-build Vue 3 frontend
```

### Detailed Package Roles

* **cmd/minecrauth/**  
  The main entry point. Loads configuration via the required `--config` flag, handles pending backup restorations before opening the database, initializes the database schema, loads the RSA signing key, bootstraps configured default admin accounts, and starts the HTTPServer with clean SIGINT/SIGTERM graceful shutdown.
* **internal/config/**  
  Loads a single YAML configuration file, expands environment variables (supporting `${SECRET}` syntax), validates parameters (requiring `base_url`), and parses fields strictly.
* **internal/httpserver/**  
  Configures the HTTP router, applies rate and body limiting middleware, and manages the lifecycle of all endpoints (Yggdrasil, public APIs, administrative APIs, and metrics). Supports session cookie validation and HTTP Basic auth.
* **internal/yggdrasil/**  
  Yggdrasil protocol handlers and DTOs. Translates incoming client join actions, handles game server validation pings, caches sessions, assembles signed texture profiles, and issues per-player certificates for 1.19+ signed chat.
* **internal/auth/**  
  Manages opaque, random Yggdrasil tokens. Provides specialized authenticators for normal passwords, OIDC tokens, game-specific passwords, and browser-facing composite auth with PKCE.
* **internal/accounts/**  
  Defines the 1:N relationship between users and players. Enforces invitation rules, manages TOTP (2FA) lifecycle states, manages reset tokens, and holds skin selection models.
* **internal/signing/**  
  Handles the RSA 4096-bit keypair lifecycle (persisted in PKCS#8 format) and executes SHA1withRSA signatures: profile properties and, via the raw `SignSHA1` primitive, the player public keys returned by the certificates endpoint.
* **internal/textures/**  
  Handles skin and cape file storage. Conducts content-addressing, validates image dimensions, and auto-detects classic or slim arm models. The `DecodeAndSanitize` primitive reads the PNG header first to reject oversized images before any full decode (decompression-bomb guard) and re-encodes accepted images to strip non-bitmap chunks; every upload path routes through it.
* **internal/fallback/**  
  Provides mixed-authentication capabilities, allowing requests for non-local accounts to be forwarded to upstream providers (such as Mojang) while honoring local whitelist permissions.
* **internal/mailer/**  
  Encapsulates email delivery via a `Mailer` interface, falling back to a logging `NoopMailer` when SMTP is unconfigured, or employing `SMTPMailer` with custom HTML templates.
* **internal/backup/**  
  Creates live, WAL-consistent database snapshots via SQLite's `VACUUM INTO` packed into a `.tar.gz` archive containing the DB, configuration, and keys. Restores are staged as `.restore-pending.tar.gz` and applied atomically on the next boot.
* **internal/metrics/**  
  Deploys Prometheus counters and histograms to measure request latencies and codes across all HTTP routes.
* **internal/logging/**  
  Integrates `log/slog` for structured text or JSON output governed by configuration log levels.
* **internal/store/**  
  Houses the core `Store` interface. The `store/sqlite/` implementation uses the cgo-free `modernc.org/sqlite` driver and executes incremental, versioned migrations. While the `Store` interface abstractly permits other persistence engines, SQLite is currently the sole supported database.
* **internal/openapi/**  
  Exposes the generated OpenAPI 3.1 schema. This schema is generated programmatically via `make openapi` and is never hand-edited.
* **webui/**  
  Contains the embedded Vue 3 Single Page Application (`embed.FS`). Utilizes vendored, raw JavaScript with ES modules and a custom, hand-crafted retro pixel CSS theme to eliminate Node/npm build dependencies entirely.

## Handshake Data Flow (Yggdrasil Join Protocol)

The sequence diagram below displays the critical path of a player logging in through a launcher and joining a vanilla Minecraft server running the authlib-injector agent:

```
Launcher                 minecrauth                 Minecraft server
   |  authenticate (user/pass) |                              |
   |-------------------------->|                              |
   |  accessToken + profile    |                              |
   |<--------------------------|                              |
   |  join (token, serverId)   |                              |
   |-------------------------->|  record pending session      |
   |                           |                              |
   |            (player connects to the game server)          |
   |---------------------------------------------------------->|
   |                           |  hasJoined?(name, serverId)  |
   |                           |<-----------------------------|
   |                           |  profile + signed textures   |
   |                           |----------------------------->|
   |                           |        player is in          |
```
