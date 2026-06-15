# CLI migrate playground

Config-only playground for manually exercising `rustauth db`. There is no Rust
server here — only `rustauth.toml`, a SQLite file on disk, and optional SQL
files under `migrations/rustauth/`.

## Why `rustauth.toml` instead of `RustAuthBuilder`?

These are **two separate configuration surfaces**:

| | `rustauth.toml` | `RustAuthBuilder` / app code |
|--|-----------------|------------------------------|
| **Used by** | `rustauth-cli` (`db status`, `db generate`, `db migrate`, `doctor`, `init`) | Your running application |
| **Contains** | Adapter, provider, plugin **ids**, env var names | Full runtime wiring: secrets, callbacks, OAuth clients, plugin options |
| **Required for CLI migrations?** | Yes | No (but your app still needs the builder to serve traffic) |

The CLI reads `rustauth.toml`, instantiates **default** plugin stubs for each
enabled id, and derives the target database schema from that list. It does not
compile or execute your application.

In a full app (see [`backend-reference`](../backend-reference/)), you keep
`[plugins].enabled` in `rustauth.toml` in sync with the plugin ids you register
in Rust (`ENABLED_PLUGIN_IDS` in `src/auth/plugins.rs`). This playground skips
the app entirely — `rustauth.toml` alone is enough to test migrations.

Create a starter config with:

```bash
rustauth init --framework axum --seed-secrets
```

## Why SQLite + `sqlx`?

- Single file (`data/rustauth.db`) — easy to delete and inspect with `sqlite3`.
- `rustauth db generate` writes readable `.sql` under `migrations/rustauth/`
  (Postgres does too, but SQLite avoids Docker).
- The same CLI workflow works if you switch `provider` and `DATABASE_URL` to
  Postgres.

## Prerequisites

Build the CLI with all schema features from the repo root:

```bash
cargo build -p rustauth-cli --features full
```

Or prefix every command with `cargo run -p rustauth-cli --features full --`.

## Setup

```bash
cd examples/cli-migrate-playground
cp .env.example .env
```

## Manual test commands

Run these from `examples/cli-migrate-playground` (the CLI loads `./rustauth.toml`).

### 1. Target schema (no database required)

```bash
cargo run -p rustauth-cli --manifest-path ../../Cargo.toml --features full -- \
  schema print --format sql --dialect sqlite
```

### 2. Pending diff before migrating

```bash
cargo run -p rustauth-cli --manifest-path ../../Cargo.toml --features full -- \
  db status
```

You should see pending core tables plus plugins enabled in the first block of
`rustauth.toml`.

### 3. Write SQL files (optional, good for inspection)

```bash
cargo run -p rustauth-cli --manifest-path ../../Cargo.toml --features full -- \
  db generate --yes
```

Inspect `migrations/rustauth/*.sql`.

### 4. First migration pass

```bash
cargo run -p rustauth-cli --manifest-path ../../Cargo.toml --features full -- \
  db migrate --yes
```

Inspect the database:

```bash
sqlite3 data/rustauth.db ".tables"
sqlite3 data/rustauth.db ".schema api_keys"
```

### 5. Second pass — uncomment plugins

In `rustauth.toml`, uncomment one or all entries in the commented block
(`oauth-provider`, `passkey`, `scim`, `sso`, `stripe`).

```bash
cargo run -p rustauth-cli --manifest-path ../../Cargo.toml --features full -- \
  db status

cargo run -p rustauth-cli --manifest-path ../../Cargo.toml --features full -- \
  db migrate --yes
```

Confirm only new tables appear (e.g. `passkeys` after enabling `passkey`).

If the `rustauth` binary is on your PATH:

```bash
rustauth db status
rustauth db generate --yes
rustauth db migrate --yes
```

## Plugins and tables

| Plugin | New tables |
|--------|------------|
| *(core)* | `users`, `sessions`, `accounts`, `verifications`, `rate_limits` |
| `api-key` | `api_keys` |
| `device-authorization` | `device_codes` |
| `jwt` | `jwks` |
| `two-factor` | `two_factors` |
| `organization` | `organizations`, `members`, `invitations`, … |
| `siwe` | `wallet_addresses` |
| `oauth-provider` *(commented)* | `oauth_clients`, `oauth_refresh_tokens`, `oauth_access_tokens`, `oauth_consents` |
| `passkey` *(commented)* | `passkeys` |
| `scim` *(commented)* | `scim_providers`, `scim_user_profiles`, `scim_group_profiles` |
| `sso` *(commented)* | `sso_providers` |
| `stripe` *(commented)* | `stripe_webhook_events`, `subscriptions` |

Other official plugins (`admin`, `username`, `magic-link`, …) add **columns** or
have no fixed CLI schema; this example focuses on plugins that create tables.

## Reset and try again

```bash
./scripts/reset.sh
cp .env.example .env
cargo run -p rustauth-cli --manifest-path ../../Cargo.toml --features full -- db migrate --yes
```

Or manually:

```bash
rm -rf data migrations
mkdir -p data
```

## Rollback

There is **no** `rustauth db rollback`. RustAuth migrations are forward-only and
additive (create tables, add columns/indexes).

What exists instead:

- **`db migrate --dry-run`** — show the plan without applying.
- **Atomic transaction** (SQLite/Postgres) — if a plan fails mid-apply, that
  attempt is rolled back (the schema is not left half-applied for that run).
- **Manual reset** — delete `data/` and `migrations/` (this example) or drop
  the Postgres schema.

There is no Flyway/Liquibase-style version history table and no generated `DOWN`
SQL.

## Who runs migrations?

| Component | Role |
|-----------|------|
| **`rustauth-cli`** | Plans the diff, optionally writes `.sql`, applies via `db migrate` |
| **`rustauth-sqlx`** | Engine for `adapter = "sqlx"` (sqlite, postgres, mysql) |
| **`rustauth-tokio-postgres`** | Engine for `adapter = "tokio-postgres"` |
| **`rustauth-deadpool-postgres`** | Engine for `adapter = "deadpool-postgres"` (wraps tokio-postgres) |

All three SQL adapters support the same CLI workflow. They are **not** a replacement
for sqlx-cli, Diesel, or Prisma — RustAuth compares the live schema to the target
derived from `rustauth.toml` + plugins and applies the delta.

Applications should **not** call `run_migrations()` at startup; run the CLI in
local setup or CI instead. See [docs/database-migrations.md](../../docs/database-migrations.md)
and the automated [CLI migration test matrix](../../crates/rustauth-cli/tests/README.md).

## Optional: Postgres

In `rustauth.toml`:

```toml
adapter = "deadpool-postgres"  # or "tokio-postgres" or "sqlx"
provider = "postgres"
```

In `.env`:

```env
DATABASE_URL=postgres://user:password@127.0.0.1:5432/rustauth
```

Build/install the CLI with the matching adapter feature. `db generate` still
writes `.sql` using the Postgres dialect.
