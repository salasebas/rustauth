# Changelog

## [0.3.1](https://github.com/salasebas/rustauth/compare/v0.3.0...v0.3.1) - 2026-07-01

### Changed

- Harden SSO provider trust ([#183](https://github.com/salasebas/rustauth/pull/183))

### Fixed

- fail closed when OIDC HTTP client build fails ([#176](https://github.com/salasebas/rustauth/pull/176))
- *(sso)* cap SAML SLO message inflation ([#184](https://github.com/salasebas/rustauth/pull/184))

## [0.2.0] - 2026-06-14

Initial public working release.

### Added

- Enterprise SSO plugin combining OIDC and SAML routes, provider CRUD, and domain verification.
- Audit events for SSO trust-boundary changes.
- Feature-gated `oidc` and `saml` route composition.

[0.2.0]: https://github.com/salasebas/rustauth/releases/tag/v0.2.0
