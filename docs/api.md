# HTTP API Reference

The complete, always-current API reference is the OpenAPI 3.1 spec, generated from the
code and served by the running server:

- `GET /openapi.json`
- `GET /openapi.yaml`

Regenerate it after changing any handler with `make openapi`. Don't hand-maintain a
second copy of the route list here; it only drifts.

Open the spec in any viewer (Swagger UI, Redoc, Scalar, `curl | jq`, your editor's
OpenAPI plugin) to browse every route, its parameters, request/response schemas and
status codes.

## What the spec doesn't spell out

A few cross-cutting rules apply across the whole surface and are easier to state once
here than to read off each operation.

### Path prefixes

Routes live under configurable prefixes (defaults shown):

- Yggdrasil / authlib-injector: `/authlib-injector`
- Public management API: `/api`
- Admin management API: `/admin`
- Browser (web UI) API: `/web/api`

The public and admin surfaces sit on separate prefixes on purpose, so you can firewall
the admin one (bind it to localhost or put it behind a separate proxy).

### Two auth planes

- **Yggdrasil plane**: launchers and game servers authenticate with opaque access tokens
  carried in the request body, exactly as the Yggdrasil/authlib-injector spec defines.
  If a user has set a game password, the launcher must use that instead of the account
  password.
- **Management plane** (`/api`, `/admin`): every endpoint except registration and the
  public recovery endpoints requires authentication via **either** HTTP Basic
  (`email:password`) **or** the `minecrauth_session` cookie. Admin routes additionally
  require an admin account. When authenticating with the cookie, mutating requests
  (`POST`/`PUT`/`PATCH`/`DELETE`) must carry the `X-CSRF-Token` header; HTTP Basic
  requests are exempt (they carry no ambient credential).

### Operational endpoints

- `GET /healthz`  liveness.
- `GET /readyz`   readiness (pings the database).
- `GET /metrics`  Prometheus metrics.

## Connecting clients

See [usage.md](usage.md) for how to point launchers and vanilla servers at
`<base_url>/authlib-injector`.
