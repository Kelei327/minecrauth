# Getting Started

This walks you through a first run: bootstrap an admin, log in, and connect a launcher
and a game server. For the full HTTP API, see the OpenAPI spec at `/openapi.json` and
`/openapi.yaml` (and [api.md](api.md)). For every configuration key, see
[configuration.md](configuration.md).

## 1. First run and the bootstrap admin

List the admins you want in `config.yaml`, along with the externally reachable URL:

```yaml
base_url: "http://localhost:25585"
default_admins:
  - "admin@example.com"
```

Start the server:

```bash
./minecrauth --config config.yaml
```

On first boot, any address in `default_admins` that doesn't exist yet is created as an
admin with a random password, printed once in the logs at WARN:

```text
WARN created default admin account; change the password immediately email=admin@example.com generated_password=A4g8_kXhP-Zq9_0lmNP_18Jklas92_8fkaX_hja81
```

Copy that password. You'll change it on first login.

## 2. Log in to the web UI

Open `base_url` in a browser (e.g. `http://localhost:25585`). You're redirected to
`/login`. Sign in with the admin email and the generated password, then change it from
`/account`.

From there:

- `/players` manages your characters: create, rename, delete, change UUID, upload skins
  and capes.
- `/account` changes your email or password, sets a game password, and manages 2FA.
- `/admin-ui` is the admin panel: user CRUD, block/unblock, grant/revoke admin,
  impersonate, invites, and backups.

To let players register themselves, leave `require_invite: false`; otherwise create an
invite from the Invites tab and share the link. Players sign up at `/login`.

## 3. Connect a launcher

Give players your authlib-injector endpoint: `<base_url>/authlib-injector`, e.g.
`https://auth.example.com/authlib-injector`.

In Fjord/Freesm, HMCL or Prism: add a Yggdrasil / authlib-injector account, paste that
URL, and log in with the minecrauth email and password. The launcher pulls every player
the account owns; pick the one to play.

If the user has set a game password (from `/account`), the launcher must use that
instead of the website password.

## 4. Connect a vanilla server

Grab `authlib-injector.jar`, put it next to your server jar, and start the server with
it as a Java agent, keeping `online-mode=true`:

```bash
java -javaagent:authlib-injector.jar=https://auth.example.com/authlib-injector -jar server.jar nogui
```

When a player joins, the server calls minecrauth's `hasJoined`, which verifies the
session token and returns the profile with signed textures. Offline-mode username
spoofing is rejected.

## Next steps

- [Configuration reference](configuration.md) for every option.
- [Deployment notes](deployment.md) for reverse proxies, TLS, client IPs, the state
  directory, backups, firewalling the admin API, mixed-auth and OIDC.
