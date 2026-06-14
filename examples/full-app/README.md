# RustAuth Full App Example

This example is the living integration app for the current workspace version of
RustAuth. It uses local path dependencies, so it tracks the repository API
instead of a published crate version.

The app also enables `rustauth-oauth-provider` with MCP protected-resource
metadata. OAuth clients use the standard `/oauth2/*` routes under the auth base
path (`/api/axum/auth` by default).

## Run with SQLite

```bash
cargo run -p rustauth-example-full-app
```

Open http://127.0.0.1:3000.

The default SQLite database is created at `examples/full-app/data/rustauth.sqlite`.
The `data/` directory is local development state and should not be committed.

The demo UI's profile preferences (`/api/example/preferences`) use Redis when it
is reachable (`REDIS_URL`, default `redis://127.0.0.1:6379`). When Redis is not
running, preferences fall back to the startup configuration and an in-process
store for the current server instance, so the default SQLite flow works without a
Redis sidecar.

## Run with Docker services

From the repository root:

```bash
./scripts/ensure-test-services.sh postgres mysql redis valkey
```

Postgres:

```bash
RUSTAUTH_EXAMPLE_DB=postgres \
DATABASE_URL=postgres://user:password@127.0.0.1:5432/rustauth \
cargo run -p rustauth-example-full-app
```

MySQL:

```bash
RUSTAUTH_EXAMPLE_DB=mysql \
DATABASE_URL=mysql://user:password@127.0.0.1:3306/rustauth \
cargo run -p rustauth-example-full-app
```

Redis rate limiting:

```bash
RUSTAUTH_EXAMPLE_RATE_LIMIT=redis \
REDIS_URL=redis://127.0.0.1:6379 \
cargo run -p rustauth-example-full-app
```

Valkey rate limiting:

```bash
RUSTAUTH_EXAMPLE_RATE_LIMIT=valkey \
VALKEY_URL=valkey://127.0.0.1:6380 \
cargo run -p rustauth-example-full-app
```

Hybrid rate limiting (in-memory limiter with a Redis or Valkey secondary
store) via `redis-rs`:

```bash
RUSTAUTH_EXAMPLE_RATE_LIMIT=hybrid-redis \
REDIS_URL=redis://127.0.0.1:6379 \
cargo run -p rustauth-example-full-app
```

```bash
RUSTAUTH_EXAMPLE_RATE_LIMIT=hybrid-valkey \
VALKEY_URL=valkey://127.0.0.1:6380 \
cargo run -p rustauth-example-full-app
```

`fred`-backed Redis or Valkey rate limiting (uses the `fred` client instead of
`redis-rs`):

```bash
RUSTAUTH_EXAMPLE_RATE_LIMIT=fred-redis \
REDIS_URL=redis://127.0.0.1:6379 \
cargo run -p rustauth-example-full-app
```

```bash
RUSTAUTH_EXAMPLE_RATE_LIMIT=fred-valkey \
VALKEY_URL=valkey://127.0.0.1:6380 \
cargo run -p rustauth-example-full-app
```

Database-backed rate limiting:

```bash
RUSTAUTH_EXAMPLE_DB=sqlite \
RUSTAUTH_EXAMPLE_RATE_LIMIT=database \
cargo run -p rustauth-example-full-app
```

## Configuration

| Variable | Default |
| --- | --- |
| `RUSTAUTH_EXAMPLE_HOST` | `127.0.0.1` |
| `RUSTAUTH_EXAMPLE_PORT` | `3000` |
| `RUSTAUTH_EXAMPLE_BASE_URL` | `http://127.0.0.1:3000/api/axum/auth` |
| `RUSTAUTH_SECRET` | development-only secret |
| `RUSTAUTH_EXAMPLE_DB` | `sqlite` |
| `DATABASE_URL` | backend-specific local URL for the startup backend |
| `RUSTAUTH_EXAMPLE_SQLITE_DATABASE_URL` | optional explicit SQLite URL for alternate backend selection |
| `RUSTAUTH_EXAMPLE_POSTGRES_DATABASE_URL` | optional explicit Postgres URL for alternate backend selection |
| `RUSTAUTH_EXAMPLE_MYSQL_DATABASE_URL` | optional explicit MySQL URL for alternate backend selection |
| `RUSTAUTH_EXAMPLE_RATE_LIMIT` | `memory` |
| `RUSTAUTH_EXAMPLE_RATE_LIMIT_ENABLED` | `true` |
| `RUSTAUTH_EXAMPLE_RATE_LIMIT_WINDOW` | `60` (seconds) |
| `RUSTAUTH_EXAMPLE_RATE_LIMIT_MAX` | `120` (requests per window) |
| `REDIS_URL` | `redis://127.0.0.1:6379` |
| `VALKEY_URL` | `valkey://127.0.0.1:6380` |
| `RUSTAUTH_EXAMPLE_DEV_CONTROLS` | enabled only for loopback hosts |

Supported `RUSTAUTH_EXAMPLE_DB` values are `memory`, `sqlite`,
`postgres-sqlx` (SQLx driver; `postgres` is accepted as an alias),
`postgres-deadpool` (`deadpool-postgres` pool over `tokio-postgres`,
sharing the same Postgres database and `RUSTAUTH_EXAMPLE_POSTGRES_DATABASE_URL`),
and `mysql-sqlx` (`mysql` is accepted as an alias). Supported
`RUSTAUTH_EXAMPLE_RATE_LIMIT` values are `memory`,
`database`, `redis`, `valkey`, `hybrid-redis`, `hybrid-valkey`, `fred-redis`,
and `fred-valkey`. The `redis`/`valkey`/`hybrid-*` backends use the `redis-rs`
client and the `fred-*` backends use the `fred` client; `hybrid-*` pairs an
in-memory limiter with the secondary store. The `*-redis` variants read
`REDIS_URL` and the `*-valkey` variants read `VALKEY_URL`, while `database`
requires a SQL `RUSTAUTH_EXAMPLE_DB` (`sqlite`, `postgres-sqlx`,
`postgres-deadpool`, or `mysql-sqlx`).

Rate limiting is tuned with `RUSTAUTH_EXAMPLE_RATE_LIMIT_ENABLED` (default
`true`), `RUSTAUTH_EXAMPLE_RATE_LIMIT_WINDOW` (window in seconds, default `60`),
and `RUSTAUTH_EXAMPLE_RATE_LIMIT_MAX` (max requests per window, default `120`).
These apply to every backend, including the per-request override headers on the
dynamic auth profiles.

MongoDB and MSSQL are intentionally not wired into this example yet because the
workspace does not currently expose RustAuth adapters for them.

## Security: hardened by default

This example ships a privileged "control plane" used by the demo UI: the
database viewer (`/api/example/tables`, `/api/example/table`), the schema reset
endpoint (`/api/example/database/drop`), the profile preferences endpoints, and
per-request rate-limit override headers on the dynamic auth profiles. Those are
useful locally but dangerous if the app is exposed beyond your machine.

To make the example safe to copy, the control plane is **disabled by default
unless the server binds to a loopback address** (`127.0.0.1`, `::1`, or
`localhost`). When it is disabled:

- the database viewer, schema reset, and preferences endpoints return `403`, and
- the `x-rustauth-example-rate-*` headers are ignored, so callers cannot tune or
  disable the rate limiter for their own requests.

The dynamic auth profiles never run database migrations on the request path.
The configured backend is migrated once at startup, and re-initialization is
only available through the gated schema-reset action. Dynamic profile routes
cache their `RustAuth` instances (including database adapters) by profile key,
the database viewer reuses cached SQL adapters the same way, and both caches
invalidate when a schema reset runs. When any database URL is configured
explicitly (`DATABASE_URL` or `RUSTAUTH_EXAMPLE_*_DATABASE_URL`), alternate
backend selection reuses only configured URLs and fails closed for backends
without one; unset env vars still allow the local demo defaults.

Override the automatic behavior with `RUSTAUTH_EXAMPLE_DEV_CONTROLS`:

```bash
# Force-enable the control plane (only do this on a trusted network):
RUSTAUTH_EXAMPLE_HOST=0.0.0.0 RUSTAUTH_EXAMPLE_DEV_CONTROLS=true \
  cargo run -p rustauth-example-full-app

# Force-disable it even on localhost:
RUSTAUTH_EXAMPLE_DEV_CONTROLS=false cargo run -p rustauth-example-full-app
```

If you build a real application from this example, keep the control plane
disabled in any deployment that is reachable outside your development machine.