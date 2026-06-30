# Conventions - minecrauth

The "how we write code here" contract. Follow it without asking.

## Mandatory Patterns

- **Pure Go, no cgo.** The whole point of the project is a single static binary with
  no toolchain dependencies. SQLite must be `modernc.org/sqlite` (pure Go).
- **`log/slog` for all logging.** Handler and level are loaded from the configuration file (`log_format: text|json`, JSON by default for cluster aggregation, and `log_level: debug|info|warn|error`) and set via `slog.HandlerOptions.Level`. No third-party logger.
- **Return all errors and handle them at the outermost sensible layer.** Propagate
  upward with context (`fmt.Errorf("...: %w", err)`); handle/log at the highest layer
  that can make a real decision.
- **Persistence behind a `Store` interface.** No SQL above the store package. The
  domain never imports the SQLite driver.
- **Domain never imports `net/http`.** Handlers translate between HTTP and domain.
- **Config has minimal required fields and sane defaults.** A fresh deploy should run
  with almost nothing set. A handful of well-chosen options beats dozens of knobs.

## Forbidden Patterns

- **No cgo dependencies** (e.g. dqlite, mattn/go-sqlite3). Breaks the single-binary goal.
- **No Node/TypeScript build step**, including for the web UI. Serve standalone Vue 3 via `embed.FS` with ES-module JS.
- **No business logic in HTTP handlers.** They marshal/unmarshal and delegate.
- **No leaking the access token or signing private key into logs.**

## Naming

- Files: lowercase, no underscores except `_test.go`.
- Packages: short, lowercase, no plurals where avoidable (`store`, `auth`, `signing`).
- Exported identifiers documented with a one-line header comment saying what it does,
  and the WHY only when non-obvious.

## Comments & Documentation Language

- **All code comments and config-file comments in ENGLISH**, regardless of the
  language of the conversation. Aligns with the repo and the achetronic convention.
- No AI-tell artifacts: no decorative separators (`# ===`, `# --- section ---`), no
  changelog-style framing, no em-dashes/unicode arrows. Comments are timeless and
  describe what the code does and (when non-obvious) why.
- Header comments on functions/structs: brief, explaining what; add the why only when
  the code is unusual.

## Error Handling

- Wrap with `%w` to preserve the chain.
- Sentinel errors or typed errors where callers need to branch on them.
- Map domain errors to Yggdrasil error responses only at the handler boundary
  (Yggdrasil has a specific JSON error shape: `error`, `errorMessage`, `cause`).

## Configuration Reference Comments

- In config files, env var docs, and any values file, include a `# Ref: <link>`
  comment pointing to the official documentation or the GitHub source where the
  possible values are described.

## Testing

- Behaviour over implementation; table-driven tests; arrange/act/assert.
- Each test must fail when the bug it guards against is present (canary rule).
- The protocol layer needs tests against the real Yggdrasil request/response shapes;
  treat the authlib-injector spec as the source of truth.

## Configuration

- Typed config struct with defaults loaded from a single YAML configuration file passed via the required `--config` flag.
- The YAML file is processed with environment-variable expansion before parsing to inject secrets safely.
- Strict parsing is enforced via `KnownFields(true)`, so any unknown configuration keys are rejected at startup.
- Required fields (specifically `base_url`) are validated at startup with a clear fatal error message.
- Document every field in `config.example.yaml` and `docs/configuration.md` (see Ref-comment rule above).
