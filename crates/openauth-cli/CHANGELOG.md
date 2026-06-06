# Changelog

All notable changes to `openauth-cli` are documented in this file.

## Unreleased

### Added

- CLI telemetry documentation in `README.md`: participating commands
  (`generate` / `migrate` and `db` aliases), event names (`cli_generate`,
  `cli_migrate`), environment variables, payload/redaction summary, and opt-out
  guidance for local shells and CI.
- Docs regression test ensuring the CLI README documents telemetry env vars and
  event names; extended debug-mode tests assert documented redaction of secrets,
  base URLs, and database connection strings.
- `info --json` / `--copy` (clipboard helpers) and global `-c` for `--cwd`.
- `db generate` confirmation with `-y` and telemetry outcome `aborted`.
- `init --seed-secrets` to write a generated secret into a new `.env` file.
- Regression tests for `migrate --dry-run`, `generate --force`, `doctor --strict`,
  `plugins remove`, `schema print --json`, shell completions, and init `.env`
  bootstrap.
- `secret --dev` to validate secrets with relaxed development rules.
- Friendly migration guidance and exit code `0` for known non-sqlx adapters
  (Prisma, Drizzle, Kysely, memory, MongoDB) on `db generate` / `db migrate`.

### Changed

- Loads `.env` from the directory of a custom `--config` path, not only the cwd.
- `db generate`, `db migrate`, `init`, and `plugins` commands now require
  `--yes` when stdin is not a TTY instead of auto-confirming.
- `init` now creates or updates `.env` alongside `.env.example` (without
  overwriting an existing `.env`).
- `db migrate` rejects unsafe plans before apply or dry-run; telemetry uses
  `overwritten` when `generate --force` runs.
- Updated the generated Axum integration snippet from `init` to serve with
  `into_make_service_with_connect_info::<SocketAddr>()` so OpenAuth rate
  limiting sees real client IPs, with a note to configure trusted forwarding
  headers explicitly behind a proxy.

### Removed

- Unused `openauth` crate dependency from the CLI package.

## [0.0.6] - 2026-05-24

### Added

- Added focused command modules for completions, database tasks, doctor,
  project info, initialization, plugins, schema output, and secret generation.
- Added environment, path, prompt, and output helpers for command execution.
- Added schema snapshot and command coverage for the expanded CLI surface.

### Changed

- Split the CLI application implementation into smaller command handlers.

## [0.0.5] - 2026-05-19

### Added

- Published the beta CLI release line.

