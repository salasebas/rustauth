# Changelog

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
