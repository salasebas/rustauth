# Changelog

## [0.3.2](https://github.com/salasebas/rustauth/compare/v0.3.1...v0.3.2) - 2026-07-26

### Fixed

- *(ci)* restore failing checks ([#208](https://github.com/salasebas/rustauth/pull/208))

## [0.3.1](https://github.com/salasebas/rustauth/compare/v0.3.0...v0.3.1) - 2026-07-02

### Fixed

- *(core)* validate social oauth callback aliases ([#197](https://github.com/salasebas/rustauth/pull/197))

## [0.2.0] - 2026-06-14

Initial public working release.

### Added

- Core auth server types (`RustAuth`, `RustAuthOptions`, `RustAuthError`, `AuthContext`).
- Sessions, cookies (default prefix `rustauth`), rate limiting, and email/password (opt-in).
- `AuthPlugin` contracts, hooks, and `create_auth_endpoint` route helpers.
- Database adapter traits, schema planning, SQL migrations, and secondary storage.
- Better Auth–shaped HTTP JSON (camelCase bodies); OAuth protocol fields stay RFC snake_case.
- Outbound delivery via `dispatch_outbound` for email/SMS/OTP senders.
- `test-utils` feature for integration test helpers.

[0.2.0]: https://github.com/salasebas/rustauth/releases/tag/v0.2.0
