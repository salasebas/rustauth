# openauth-cli

Command-line tools for OpenAuth-RS.

## What It Is

`openauth-cli` provides local developer tooling for OpenAuth projects. The
published package exposes the `openauth` binary and cargo-style aliases.

## What It Provides

- Secret generation.
- Project diagnostics.
- Workspace and package information.
- Schema and migration planning output.
- Project initialization helpers.
- Plugin inspection and changes for official OpenAuth plugins.
- Shell completion generation.

## Quick Start

These commands work in any directory and do not need an `openauth.toml`:

```sh
openauth secret --bytes 32              # generate a signing secret
openauth plugins list                   # list official plugins
openauth schema print --dialect sqlite  # print the base OpenAuth schema
openauth doctor                         # diagnose the environment
```

Without a config, `doctor` reports what is missing (including the absent
`openauth.toml`) and `schema print` emits the default schema, so the CLI is
useful before any project setup.

To create a project and unlock the config-bound workflow, run `openauth init`
first. It writes `openauth.toml`; the following commands read it:

```sh
openauth init                # write openauth.toml and .env.example
openauth doctor --production # config-aware production readiness checks
openauth db generate         # generate a migration from the configured schema
openauth db migrate          # apply pending migrations
```

The CLI is intentionally transparent: it inspects the current Rust workspace
and prints or writes OpenAuth configuration/migration output without hiding the
Rust code that owns your application behavior.

## Environment variables

Before running config-backed commands, the CLI loads `.env` and `.env.local`
without overriding variables already set in the process environment. When
`--config` points at a file outside the project root layout, files next to that
config are loaded first, then files in `--cwd` (weaker to stronger:
`config/.env`, `config/.env.local`, `<cwd>/.env`, `<cwd>/.env.local`).

## Status

Experimental beta. Commands, flags, generated output, and workspace detection
may change before stable release.

## Upstream parity (Better Auth 1.6.9)

Parity pin: [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md).
Upstream package: `packages/cli` (npm `auth@1.6.9`). Rust toolchain for `openauth.toml`,
SQL migrations via `openauth-sqlx`, and CLI telemetry via `openauth-telemetry`.

| Area | Parity | Notes |
| --- | --- | --- |
| `secret`, `init`, `db generate`, `db migrate`, `info`, `plugins` | High | Operational equivalence for Rust/sqlx workflows |
| Config | Different | Static `openauth.toml` vs upstream `auth.ts` + jiti/c12 |
| Schema output | Different | SQL files vs Prisma/Drizzle/Kysely generators |
| `doctor`, `schema print`, `db status`, `completions` | Extra Rust | No upstream homonyms |
| `ai`, `mcp`, `upgrade`, `login`, `logout` | N/A | TypeScript / npm product commands |
| Package tests | Different shape | ~284 upstream Vitest vs 52 Rust integration tests |

Verify: `cargo nextest run -p openauth-cli`.

### Upstream lookup

1. Pin: [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md).
2. CLI package: `reference/upstream-src/<version>/repository/packages/cli/`.
3. Map upstream `src/commands/` to `crates/openauth-cli/src/`.
4. Verify: `cargo nextest run -p openauth-cli`.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
