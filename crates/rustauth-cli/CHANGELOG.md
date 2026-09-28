# Changelog

## [Unreleased]

## [0.3.2](https://github.com/salasebas/rustauth/compare/v0.3.1...v0.3.2) - 2026-07-26

### Changed

- update Cargo.lock dependencies

## [0.3.0] - 2026-06-15

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

[0.3.0]: https://github.com/salasebas/rustauth/releases/tag/v0.3.0
[0.2.0]: https://github.com/salasebas/rustauth/releases/tag/v0.2.0
