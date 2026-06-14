# Changelog

## [0.2.0] - 2026-06-14

Initial public working release.

### Added

- `rustauth` CLI: `init`, `info`, `secret`, `db status|generate|migrate`, and plugin/schema helpers.
- `rustauth.toml` workflow aligned with Better Auth v1.6.9 CLI parity.
- Feature-gated enterprise plugin and adapter support (`sqlx`, `tokio-postgres`, `plugins`, `full`).
- Opt-in telemetry for `db generate` and `db migrate`.

[0.2.0]: https://github.com/salasebas/rustauth/releases/tag/v0.2.0
