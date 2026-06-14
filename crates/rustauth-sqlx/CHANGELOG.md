# Changelog

## [0.2.0] - 2026-06-14

Initial public working release.

### Added

- SQLx-backed adapters for SQLite, Postgres, and MySQL.
- Bundled `SqlxStores` and `apply_to_options` for recommended app wiring.
- SQL-backed standalone rate-limit store and dialect-specific migration planning.
- Feature flags per dialect (`sqlite`, `postgres`, `mysql`); `default = []`.

[0.2.0]: https://github.com/salasebas/rustauth/releases/tag/v0.2.0
