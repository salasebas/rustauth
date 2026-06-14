# Changelog

## [0.2.0] - 2026-06-14

Initial public working release.

### Added

- Redis/Valkey rate-limit and secondary storage via `redis-rs`.
- TLS support behind optional `rustls` and `native-tls` features.
- Atomic `GETDEL` for secondary-storage `take` operations.

[0.2.0]: https://github.com/salasebas/rustauth/releases/tag/v0.2.0
