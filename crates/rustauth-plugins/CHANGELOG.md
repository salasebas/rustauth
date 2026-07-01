# Changelog

## [Unreleased]

## [0.3.1](https://github.com/salasebas/rustauth/compare/v0.3.0...v0.3.1) - 2026-07-01

### Changed

- [codex] Add verified Generic OIDC profile extraction ([#186](https://github.com/salasebas/rustauth/pull/186))

### Fixed

- break plugins/fred dev-dep cycle and repair post-0.3.0 CI
- *(plugins)* restrict email OTP verification endpoints
- *(plugins)* reject unverified generic oauth id tokens ([#179](https://github.com/salasebas/rustauth/pull/179))
- fix generic oauth fail-closed http client ([#180](https://github.com/salasebas/rustauth/pull/180))
- fix phone otp storage ([#182](https://github.com/salasebas/rustauth/pull/182))
- reject protected admin user updates ([#185](https://github.com/salasebas/rustauth/pull/185))

### Changed

- Email OTP verification create/get endpoints are now marked server-only, so public route
  dispatch returns `404` while server-side handlers can still create and recover OTP values.

## [0.2.0] - 2026-06-14

Initial public working release.

### Added

- Official server-side plugins: access control, additional fields, admin, anonymous users,
  API keys, bearer sessions, CAPTCHA, custom sessions, device authorization, email OTP,
  generic OAuth, Have I Been Pwned, JWT, last login method, magic link, multi-session,
  OAuth proxy, one-tap, one-time tokens, OpenAPI, organizations, phone number, SIWE,
  two-factor, and username.
- `prelude` module with plugin factories and options.
- `schema_plugins` for plugin-augmented database schema planning.

[0.2.0]: https://github.com/salasebas/rustauth/releases/tag/v0.2.0
