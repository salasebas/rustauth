# Database migrations

RustAuth schema changes are applied with the **CLI**, not at application startup.

## `rustauth.toml` vs application code

| | Better Auth (upstream) | RustAuth |
| --- | --- | --- |
| CLI config source | Executable TypeScript auth config (`get-config.ts` imports your server module) | Static `rustauth.toml` + `.env` |
| Runtime config | Same TS auth module | `RustAuth::builder()` / `RustAuthOptions` in Rust |
| Plugin discovery for migrations | From live TS config | From `[plugins].enabled` in TOML (default plugin stubs) |

You need **`rustauth.toml`** for `rustauth db status`, `db generate`, and
`db migrate`. It is not a Rust language standard — it is CLI tooling config,
similar to how Cargo uses `Cargo.toml`. Runtime behavior still lives in Rust;
keep the plugin list and database adapter aligned between both places.

### Avoiding config drift

Maintain your runtime plugin id list in Rust (for example `ENABLED_PLUGIN_IDS`
in `RustAuth::builder().plugins(...)`) and mirror the same ids in
`[plugins].enabled` in `rustauth.toml`. After changing plugins, run
`rustauth doctor` and rebuild the CLI with matching `--features` when you enable
enterprise plugins (`passkey`, `sso`, `stripe`, etc.).

The [`backend-reference`](../examples/backend-reference/) example enforces this
with `tests/plugin_toml_parity.rs` and `tests/cli_schema_parity.rs`. Copy that
pattern into your app if you use both surfaces.

The **additional-fields** plugin is configured in Rust only for column shapes;
the CLI reads the plugin id but cannot infer custom columns. Align those
columns with your own SQL migrations — see [App-configured plugins](#app-configured-plugins-additional-fields)
below.

Create a starter file with `rustauth init --framework axum` or `rustauth init --framework actix-web`. See
[`examples/cli-migrate-playground`](../examples/cli-migrate-playground/) for a
config-only manual test harness.

## Workflow

1. Configure `rustauth.toml` with your database adapter, provider, and enabled plugins.
2. Set `DATABASE_URL` (or the env var named in `[database].url_env`).
3. Plan or apply migrations:

```bash
rustauth db status
rustauth db generate --yes          # optional: write SQL files
rustauth db migrate --yes           # apply pending schema changes
```

`rustauth db migrate` runs adapter migrations for the effective core + plugin
schema, then executes any plugin SQL migrations registered by enabled plugins.

Use `rustauth db status --check` in CI to fail when pending schema changes exist.

## Supported adapters

| `database.adapter` | Providers |
| --- | --- |
| `sqlx` | `sqlite`, `postgres`, `mysql` |
| `tokio-postgres` | `postgres` |
| `deadpool-postgres` | `postgres` |
| `diesel` | `postgres`, `mysql` |

> `database.adapter` is required — there is no implicit default. Diesel migration support uses
> RustAuth's SQL migration planner through the `rustauth-diesel` adapter. It does not use Diesel's
> migration CLI as a second source of schema truth.

Prisma, Drizzle, Kysely, memory, and MongoDB adapters are not driven by
`rustauth db migrate`. Use `rustauth db generate` and apply SQL with your ORM,
or switch to a supported SQL adapter for CLI migrations.

## Behavior guarantees

### Additive-only

Migrations create missing tables, add missing columns/indexes, and repair missing
indexes on existing columns. They **do not** drop tables or columns when you
remove a plugin id from `rustauth.toml`.

### Incremental plugins

Typical flow:

1. `rustauth db migrate --yes` with core plugins only.
2. Add a plugin id to `[plugins].enabled` (or `rustauth plugins add … --yes`).
3. `rustauth db status` — only new tables/columns/indexes appear.
4. `rustauth db migrate --yes` again.

### App-configured plugins (additional-fields)

The **additional-fields** plugin is configured in Rust (`additional_fields(...)`).
The CLI only reads the plugin **id** from `rustauth.toml` — it does **not**
infer which custom columns you defined. `rustauth db migrate` will **not** add
those columns.

Add them with your own SQL migration (matching types and `.db_name(...)` from
your Rust config). Runtime validation and API behavior still come from the
builder. See the Additional Fields plugin docs (`docs-site/content/docs/plugins/additional-fields.mdx`
or `/docs/plugins/additional-fields` on the docs site).

### Idempotence

When the live database already matches the target schema, `db migrate` prints
`No migrations needed.` and exits successfully.

### Atomic apply (SQLite / Postgres)

Each migration plan runs in a single transaction where the adapter supports it.
If apply fails mid-plan, that attempt is rolled back.

### No rollback command

There is no `rustauth db rollback` or generated `DOWN` SQL. Reset dev databases
manually (delete the SQLite file, drop a Postgres schema, etc.).

## Error and guard behavior

| Situation | `db status` | `db migrate` |
| --- | --- | --- |
| Pending tables/columns/indexes | Lists the plan; `--check` exits `1` | Applies when safe |
| Column type mismatch vs target | Prints `WARNING: ColumnTypeMismatch …` | **Blocked** (`migration has non-executable warnings`) |
| Foreign key mismatch | Prints `WARNING: ForeignKeyMismatch …` | **Blocked** |
| Missing `rustauth.toml` | Error | Error |
| Missing `DATABASE_URL` | Error | Error |
| Plugin enabled in TOML but CLI built without its feature | Error (`feature \`passkey\` is required`, etc.) | Error |
| Duplicate SQL artifact for same plan hash (`db generate`) | — | Error unless `--force` |
| SQLite: add UNIQUE column to existing table with rows | May plan column adds | **Fails at apply** (`Cannot add a UNIQUE column`) |
| Unsupported adapter (Prisma, memory, …) | Guidance | Guidance (exit `0`, no apply) |

Fix schema mismatches manually before re-running `db migrate`. Use
`db migrate --dry-run` to inspect a safe plan; unsafe plans fail before dry-run
completes.

## Application wiring

- Build `RustAuth` with your adapter; do **not** call a runtime `run_migrations` helper on `RustAuth`.
- Run `rustauth db migrate` in local setup, CI, or release jobs before starting the server.
- CI applies the documented workflow for [`backend-reference`](../examples/backend-reference/) via [`scripts/ensure-example-migrations.sh`](../scripts/ensure-example-migrations.sh).
- Adapter integration tests may call `DbAdapter::run_migrations` and
  `DbAdapter::run_plugin_migrations` directly.

## Testing

Automated coverage lives in `crates/rustauth-cli/tests/`:

```bash
cargo nextest run -p rustauth-cli --all-features --test migration_flows
```

See [`crates/rustauth-cli/tests/README.md`](../crates/rustauth-cli/tests/README.md)
for the full migration test matrix (incremental plugins, unsafe plans, adapter
variants, Docker-only Postgres cases).

Manual walkthrough: [`examples/cli-migrate-playground`](../examples/cli-migrate-playground/README.md).

## Deployment posture

Use `RUST_ENV=production` in production so RustAuth fails closed on insecure
defaults. Development and test environments may set `RUST_ENV=development` or
`RUST_ENV=test`, or rely on `DeploymentMode::Auto` with an explicit development
process environment.

See also: [`rustauth-cli` README](../crates/rustauth-cli/README.md).
