# Upstream parity — openauth-cli

Better Auth **1.6.9** behavioral reference for contributors and parity audits.
OpenAuth is inspired by Better Auth; it is not a line-by-line port.

**Audit scope:** server-side CLI only — secrets, server config resolution, database
schema generation, and direct SQL migration. Client tooling, npm lifecycle, and
TypeScript-only scaffolding are excluded from comparison.

| Field | Value |
| --- | --- |
| **Parity pin** | [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md) |
| **Upstream package** | `auth@1.6.9` (npm; binaries `better-auth`, `auth`) |
| **Upstream path** | `reference/upstream-src/1.6.9/repository/packages/cli/` |
| **Rust crate** | `crates/openauth-cli/` |
| **Parity level** | **High** (Kysely/sqlx migration workflow) · **Partial** (overall) |
| **Scope** | Server DB schema, migration apply, signing secrets, server config/env for CLI commands |
| **Audit status** | **Complete** (server-only inventory — see [Server file inventory](#server-file-inventory)) |

## Summary

OpenAuth CLI matches Better Auth’s server migration path: load auth config, diff
the target schema (core + plugins), emit SQL, and apply when using the built-in
SQL adapter (`sqlx` ↔ upstream Kysely). Config is static `openauth.toml` instead
of executable server config modules. Schema emitters target versioned `.sql`
files only (no Prisma/Drizzle generators). Rust adds `doctor`, `db status`,
`schema print`, and standalone `plugins` commands for operational safety.

## Feature parity

| Area | Status | Notes |
| --- | --- | --- |
| `secret` | ✅ | Generate + `--check` / `--check-env` / production strength rules |
| `generate` | ⚠️ | SQL via `openauth-sqlx`; matches Kysely SQL path; no Prisma/Drizzle emitters |
| `migrate` | ✅ | sqlx apply, confirm/`--yes`; adds `--dry-run` and unsafe-plan guard |
| `init` (server config) | ⚠️ | Seeds `openauth.toml` + env; no generated server auth module |
| Init social providers / auth toggles | ❌ | Upstream prompts for OAuth env + email/password/stateless; Rust init has none |
| Config resolution | ⚠️ | `openauth.toml` + `.env`; upstream loads server config via `get-config.ts` |
| Plugin schema in generate/migrate | ✅ | Enabled plugins extend target schema before plan/apply |
| `info` (server diagnostics) | ⚠️ | Redacted live server config; Rust reports static TOML + Cargo/Rust toolchain |
| Telemetry (`cli_generate`, `cli_migrate`) | ✅ | Outcomes via `openauth-telemetry` |
| Programmatic schema API | ❌ | Upstream exports `auth/api` (`src/api.ts`); no Rust equivalent in this crate |
| `generate --adapter` / `--dialect` | ❌ | Upstream mock adapter path in `generate.ts`; Rust requires `openauth.toml` |
| `doctor` | 🎯 | Production readiness checks |
| `schema print` | 🎯 | SQL/JSON schema dump without DB connection |
| `db status` | 🎯 | Pending migration summary + `--check` exit code |
| `plugins list/add/remove` | 🎯 | Config editing + schema impact hint |
| `completions` | 🎯 | Shell completion via clap |

## Test coverage

Server-side upstream tests only. Excludes: `check-package-managers.test.ts`,
`install-dependencies.test.ts`, `framework.test.ts`, and three `init.test.ts`
cases (`auth client configuration`, `package managers`, `installing dependencies`).

| Surface | OpenAuth (Rust) | Upstream (server) | Notes |
| --- | --- | --- | --- |
| **Total** | **63** | **219** | Rust: `cargo test -p openauth-cli -- --list` |
| `generate` / schema / SQL | 22 | 65 | Rust: `db.rs`, `schema_snapshots.rs`, `regression_gaps.rs`; upstream: `generate.test.ts` (53), `generate-all-db.test.ts` (12); **~2–6** kysely-direct vs rest Prisma/Drizzle (G2) |
| Config / env resolution | 9 | 40 | Rust: `config.rs`, `env.rs`, `regression_gaps.rs`; upstream: `get-config.test.ts` (21), `init/utility/env.test.ts` (19) |
| Server init scaffolding | 6 | 105 | Rust: `commands.rs`, `quick_start.rs`, `regression_gaps.rs`; upstream: `init.test.ts` (14), `auth-config.test.ts` (4), `database.test.ts` (11), `plugin.test.ts` (66), `imports.test.ts` (10) |
| `migrate` / db apply | 16 | 2 | Rust: `db.rs`, `regression_gaps.rs`; upstream: `migrate.test.ts`; Postgres/MySQL Rust tests `#[ignore]` |
| `secret` | 6 | 0 | Rust: `secret.rs`, `regression_gaps.rs`; upstream has no dedicated secret tests |
| `info` / doctor / redaction | 4 | 7 | Rust: `doctor.rs`, `regression_gaps.rs`; upstream: `info.test.ts` |
| Completions / plugins CLI | 2 | 0 | Rust: `regression_gaps.rs`, `commands.rs` |
| Binaries / cargo wrappers | 6 | 0 | Rust: `commands.rs` alias tests only |

```bash
cargo nextest run -p openauth-cli
# Postgres/MySQL migrate (ignored by default):
cargo nextest run -p openauth-cli --run-ignored all
```

## Intentional differences

| Topic | Better Auth 1.6.9 | OpenAuth | Why |
| --- | --- | --- | --- |
| Server config | Executable server config module + `get-config.ts` | Static `openauth.toml` | Rust projects; explicit parse errors |
| SQL adapter | Kysely built-in (`generators/kysely.ts`) | `database.adapter = "sqlx"` | Native Rust/sqlx stack |
| Schema output | Kysely `.sql`, or Prisma/Drizzle ORM files | Versioned `.sql` under `migrations_dir` | Transparent, reviewable migrations |
| Secret format | 32-byte hex (`secret.ts`) | URL-safe base64 (default 32 bytes) | Idiomatic Rust crypto |
| Secret command | Generate only | Generate + validate flags | Fail-closed production diagnostics |
| Unsupported adapters | Guidance + exit 0 (Prisma/Drizzle on migrate) | Same for Prisma/Drizzle/Kysely/memory/MongoDB | Mixed-team operational parity |
| `migrate` | Apply only | `--dry-run`; blocks unsafe plans | Safer server deployments |
| `generate` | Single file write / ORM append | Plan-hash dedup, `--force`, `--output-dir` | Idempotent migration artifacts |
| Binaries | `better-auth`, `auth` | `openauth` + compatibility aliases + `cargo-*` shims | Rust ecosystem |

## Open gaps and risks

| ID | Gap / risk | Severity | Notes |
| --- | --- | --- | --- |
| G1 | Init does not emit server auth module | Med | Upstream `init/generate-auth.ts` + `utility/imports.ts`; Rust seeds TOML/env only |
| G2 | No Prisma/Drizzle schema emitters | Med | ~51 upstream `generate.test.ts` cases; use SQL output + ORM tool |
| G3 | No `auth/api` programmatic exports | Low | Upstream `src/api.ts` re-exports generators |
| G4 | No `generate --adapter` / `--dialect` without config | Low | Upstream mock adapter in `generate.ts` |
| G5 | Postgres/MySQL migrate untested in CI | Med | `db.rs` docker tests are `#[ignore]` |
| G6 | Init/plugin utility test depth | Med | 105 upstream server init tests vs 6 Rust init integration tests |
| G7 | Concurrent `migrate` not serialized | Med | Multi-instance race; use external migration lock |
| G8 | Live telemetry publish untested | Low | Events fire; network path not asserted |
| G9 | No init social-provider env scaffolding | Low | Upstream `social-providers.config.ts` + init prompts |
| G10 | No init auth-method toggles | Low | Upstream email/password disable, stateless mode, MongoDB/Prisma setup flows |

## Hardening notes

- **`migrate`** rejects plans with non-executable schema warnings before apply or dry-run (`ensure_safe_to_apply` in `db_support.rs`).
- **Secrets:** production mode rejects defaults, short secrets, and example-like values; errors exit non-zero.
- **Config:** missing `openauth.toml` is non-fatal for read-only commands; parse failures fail closed.
- **Env loading:** process environment wins over `.env` / `.env.local` (`env.rs`).
- **Redaction:** `doctor` / `info --json` redact database URLs and secrets (`diagnostics.rs`).
- **Unsupported adapters:** guidance printed; known non-sqlx adapters exit **0** on migrate (upstream parity), not silent apply.

## Server file inventory

Every file under `packages/cli/` is classified. **Audited** = behavior mapped to Rust;
**Excluded** = client/npm/TS-only (out of scope).

| Upstream path | Class | Rust / notes |
| --- | --- | --- |
| `src/commands/secret.ts` | Audited | `secret.rs`, `commands/secret.rs` |
| `src/commands/generate.ts` | Audited | `commands/db.rs`, `db.rs` |
| `src/commands/migrate.ts` | Audited | `commands/db.rs`, `db.rs`, `db_support.rs` |
| `src/commands/info.ts` | Audited | `commands/info.rs`, `diagnostics.rs`, `workspace.rs` |
| `src/commands/init/index.ts` | Audited (server paths) | `commands/init.rs` (partial); client block ~L1332+ excluded |
| `src/commands/init/generate-auth.ts` | Audited | `commands/init.rs` (partial) |
| `src/commands/init/configs/databases.config.ts` | Audited | `config.rs`, `commands/init.rs` |
| `src/commands/init/configs/temp-plugins.config.ts` | Audited | `plugins.rs`, `config.rs` |
| `src/commands/init/configs/social-providers.config.ts` | Audited | — (G9) |
| `src/commands/init/utility/{auth-config,database,env,plugin,imports,format,prompt}.ts` | Audited | `config.rs`, `env.rs`, `plugins.rs`, `schema.rs`, `prompt.rs` |
| `src/generators/{index,kysely,types}.ts` | Audited | `schema.rs`, `db.rs`, `openauth-sqlx` |
| `src/generators/{prisma,drizzle}.ts` | Audited | — intentional (G2) |
| `src/api.ts` | Audited | — (G3) |
| `src/index.ts` | Audited | `app.rs`, `src/bin/*` |
| `src/utils/get-config.ts` | Audited | `config.rs`, `env.rs` |
| `src/utils/config-paths.ts` | Audited | `paths.rs` (`possibleAuthConfigPaths` → fixed `openauth.toml`) |
| `src/utils/get-package-info.ts` | Audited | `workspace.rs` |
| `src/utils/helper.ts` | Audited | `secret.rs` (`generateSecretHash` ↔ generate); `spawnCommand` excluded (login) |
| `src/utils/add-cloudflare-modules.ts` | Excluded | TS config loader hook in `get-config.ts` |
| `src/utils/add-svelte-kit-env-modules.ts` | Excluded | TS config loader hook |
| `src/commands/{ai,mcp,login,upgrade}.ts` | Excluded | npm/product |
| `src/commands/init/generate-auth-client.ts` | Excluded | client |
| `src/commands/init/utility/auth-client-config.ts` | Excluded | client |
| `src/commands/init/configs/frameworks.config.ts` | Excluded | TS framework matrix |
| `src/commands/init/utility/framework.ts` | Excluded | TS framework detection |
| `src/utils/{check-package-managers,install-dependencies,fetch-latest-version}.ts` | Excluded | npm lifecycle |

**Rust crate (all files mapped):** `app.rs`, `lib.rs`, `config.rs`, `db.rs`,
`diagnostics.rs`, `env.rs`, `output.rs`, `paths.rs`, `plugins.rs`, `prompt.rs`,
`schema.rs`, `secret.rs`, `telemetry.rs`, `workspace.rs`, `commands/*`,
`src/bin/*` (8 alias entrypoints), `tests/*` (8 integration files + 3 unit tests in `env.rs`).

## Upstream lookup

1. Read the pin in [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md).
2. Run `./scripts/fetch-upstream-better-auth.sh` if `reference/upstream-src/1.6.9/repository/` is missing.
3. Open `packages/cli/` — use [Server file inventory](#server-file-inventory) for scope.
4. Map upstream → Rust:

| Upstream (server) | Rust |
| --- | --- |
| `src/index.ts` | `src/bin/openauth.rs`, `src/app.rs` |
| `src/api.ts` | — (G3) |
| `src/commands/secret.ts` | `src/commands/secret.rs`, `src/secret.rs` |
| `src/commands/generate.ts` | `src/commands/db.rs`, `src/db.rs` |
| `src/commands/migrate.ts` | `src/commands/db.rs`, `src/db.rs`, `src/commands/db_support.rs` |
| `src/commands/info.ts` | `src/commands/info.rs`, `src/diagnostics.rs`, `src/workspace.rs` |
| `src/commands/init/generate-auth.ts` | `src/commands/init.rs` (partial) |
| `src/commands/init/configs/{databases,temp-plugins,social-providers}.config.ts` | `src/config.rs`, `src/plugins.rs` (social: G9) |
| `src/commands/init/utility/{auth-config,database,env,plugin,imports,format,prompt}.ts` | `src/config.rs`, `src/env.rs`, `src/plugins.rs`, `src/schema.rs`, `src/prompt.rs` |
| `src/generators/kysely.ts` | `src/db.rs`, `src/schema.rs`, `openauth-sqlx` |
| `src/generators/{prisma,drizzle}.ts` | — (G2) |
| `src/utils/get-config.ts`, `config-paths.ts` | `src/config.rs`, `src/paths.rs`, `src/env.rs` |
| `src/utils/get-package-info.ts`, `helper.ts` | `src/workspace.rs`, `src/secret.rs` |
| `test/generate*.test.ts` | `tests/db.rs`, `tests/schema_snapshots.rs` |
| `test/get-config.test.ts` | `tests/config.rs`, `tests/regression_gaps.rs` |
| `test/migrate.test.ts` | `tests/db.rs`, `tests/regression_gaps.rs` |
| `test/info.test.ts` | `tests/doctor.rs`, `tests/regression_gaps.rs` |
| `test/init.test.ts` (server cases), `init/utility/*.test.ts` | `tests/commands.rs`, `tests/quick_start.rs`, `tests/regression_gaps.rs` |
| — | `src/telemetry.rs`, `src/commands/{doctor,schema,plugins,completions}.rs`, `src/output.rs`, `src/bin/*` |

5. Add or extend Rust integration tests before behavior changes; match CLI exit codes, stdout/stderr, and filesystem/DB side effects.

## Related docs

- [Crate README](./README.md) — usage and quick start
- [Parity index](../../docs/parity/README.md)
