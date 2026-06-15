# Changelog

## [Unreleased]

Planned for the next crates.io release (likely **0.3.0** because of CLI breaking changes).

### Added

- `rustauth init --framework actix-web` snippet and workspace detection for Actix Web projects.

### Changed

- **Breaking:** `rustauth init` requires `--framework axum` or `--framework actix-web`.
- **Breaking:** `database.adapter` is required in `rustauth.toml` and for `rustauth init` (via
  `--adapter` or workspace detection). The previous implicit default (`sqlx`) was removed.

## [0.2.0] - 2026-06-14

Initial public working release.

### Added

- `rustauth` CLI: `init`, `info`, `secret`, `db status|generate|migrate`, and plugin/schema helpers.
- `rustauth.toml` workflow aligned with Better Auth v1.6.9 CLI parity.
- Feature-gated enterprise plugin and adapter support (`sqlx`, `tokio-postgres`, `plugins`, `full`).
- Opt-in telemetry for `db generate` and `db migrate`.

[0.2.0]: https://github.com/salasebas/rustauth/releases/tag/v0.2.0
