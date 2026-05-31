# OpenAuth Full App Example

This example is the living integration app for the current workspace version of
OpenAuth. It uses local path dependencies, so it tracks the repository API
instead of a published crate version.

## Run with SQLite

```bash
cargo run -p openauth-example-full-app
```

Open http://127.0.0.1:3000.

The default SQLite database is created at `examples/full-app/data/openauth.sqlite`.
The `data/` directory is local development state and should not be committed.

## Run with Docker services

From the repository root:

```bash
./scripts/ensure-test-services.sh postgres mysql redis valkey
```

Postgres:

```bash
OPENAUTH_EXAMPLE_DB=postgres \
DATABASE_URL=postgres://user:password@127.0.0.1:5432/openauth \
cargo run -p openauth-example-full-app
```

MySQL:

```bash
OPENAUTH_EXAMPLE_DB=mysql \
DATABASE_URL=mysql://user:password@127.0.0.1:3306/openauth \
cargo run -p openauth-example-full-app
```

Redis rate limiting:

```bash
OPENAUTH_EXAMPLE_RATE_LIMIT=redis \
REDIS_URL=redis://127.0.0.1:6379 \
cargo run -p openauth-example-full-app
```

Valkey rate limiting:

```bash
OPENAUTH_EXAMPLE_RATE_LIMIT=valkey \
VALKEY_URL=valkey://127.0.0.1:6380 \
cargo run -p openauth-example-full-app
```

Hybrid rate limiting (in-memory limiter with a Redis or Valkey secondary
store) via `redis-rs`:

```bash
OPENAUTH_EXAMPLE_RATE_LIMIT=hybrid-redis \
REDIS_URL=redis://127.0.0.1:6379 \
cargo run -p openauth-example-full-app
```

```bash
OPENAUTH_EXAMPLE_RATE_LIMIT=hybrid-valkey \
VALKEY_URL=valkey://127.0.0.1:6380 \
cargo run -p openauth-example-full-app
```

`fred`-backed Redis or Valkey rate limiting (uses the `fred` client instead of
`redis-rs`):

```bash
OPENAUTH_EXAMPLE_RATE_LIMIT=fred-redis \
REDIS_URL=redis://127.0.0.1:6379 \
cargo run -p openauth-example-full-app
```

```bash
OPENAUTH_EXAMPLE_RATE_LIMIT=fred-valkey \
VALKEY_URL=valkey://127.0.0.1:6380 \
cargo run -p openauth-example-full-app
```

Database-backed rate limiting:

```bash
OPENAUTH_EXAMPLE_DB=sqlite \
OPENAUTH_EXAMPLE_RATE_LIMIT=database \
cargo run -p openauth-example-full-app
```

## Configuration

| Variable | Default |
| --- | --- |
| `OPENAUTH_EXAMPLE_HOST` | `127.0.0.1` |
| `OPENAUTH_EXAMPLE_PORT` | `3000` |
| `OPENAUTH_EXAMPLE_BASE_URL` | `http://127.0.0.1:3000/api/axum/auth` |
| `OPENAUTH_SECRET` | development-only secret |
| `OPENAUTH_EXAMPLE_DB` | `sqlite` |
| `DATABASE_URL` | backend-specific local URL |
| `OPENAUTH_EXAMPLE_RATE_LIMIT` | `memory` |
| `OPENAUTH_EXAMPLE_RATE_LIMIT_ENABLED` | `true` |
| `OPENAUTH_EXAMPLE_RATE_LIMIT_WINDOW` | `60` (seconds) |
| `OPENAUTH_EXAMPLE_RATE_LIMIT_MAX` | `120` (requests per window) |
| `REDIS_URL` | `redis://127.0.0.1:6379` |
| `VALKEY_URL` | `valkey://127.0.0.1:6380` |
| `OPENAUTH_EXAMPLE_DEV_CONTROLS` | enabled only for loopback hosts |

Supported `OPENAUTH_EXAMPLE_DB` values are `memory`, `sqlite`, `postgres`, and
`mysql`. Supported `OPENAUTH_EXAMPLE_RATE_LIMIT` values are `memory`,
`database`, `redis`, `valkey`, `hybrid-redis`, `hybrid-valkey`, `fred-redis`,
and `fred-valkey`. The `redis`/`valkey`/`hybrid-*` backends use the `redis-rs`
client and the `fred-*` backends use the `fred` client; `hybrid-*` pairs an
in-memory limiter with the secondary store. The `*-redis` variants read
`REDIS_URL` and the `*-valkey` variants read `VALKEY_URL`, while `database`
requires a SQL `OPENAUTH_EXAMPLE_DB` (`sqlite`, `postgres`, or `mysql`).

Rate limiting is tuned with `OPENAUTH_EXAMPLE_RATE_LIMIT_ENABLED` (default
`true`), `OPENAUTH_EXAMPLE_RATE_LIMIT_WINDOW` (window in seconds, default `60`),
and `OPENAUTH_EXAMPLE_RATE_LIMIT_MAX` (max requests per window, default `120`).
These apply to every backend, including the per-request override headers on the
dynamic auth profiles.

MongoDB and MSSQL are intentionally not wired into this example yet because the
workspace does not currently expose OpenAuth adapters for them.

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
- the `x-openauth-example-rate-*` headers are ignored, so callers cannot tune or
  disable the rate limiter for their own requests.

The dynamic auth profiles never run database migrations on the request path.
The configured backend is migrated once at startup, and re-initialization is
only available through the gated schema-reset action.

Override the automatic behavior with `OPENAUTH_EXAMPLE_DEV_CONTROLS`:

```bash
# Force-enable the control plane (only do this on a trusted network):
OPENAUTH_EXAMPLE_HOST=0.0.0.0 OPENAUTH_EXAMPLE_DEV_CONTROLS=true \
  cargo run -p openauth-example-full-app

# Force-disable it even on localhost:
OPENAUTH_EXAMPLE_DEV_CONTROLS=false cargo run -p openauth-example-full-app
```

If you build a real application from this example, keep the control plane
disabled in any deployment that is reachable outside your development machine.
