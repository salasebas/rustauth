# Changelog

All notable changes to `openauth-sso` are documented in this file.

## Unreleased

### Fixed

- Fixed the OIDC SSO callback so it always validates the ID token (issuer,
  audience, expiration, subject, `nonce`, and `azp`) before trusting any
  profile source. Providers with a `userInfoEndpoint` previously skipped ID
  token validation entirely, allowing login and implicit account linking from a
  UserInfo fetch even when the token response omitted the ID token or returned
  an expired/malformed/replayed one. A valid ID token is now required, and when
  UserInfo is the profile source its `sub` is reconciled with the ID token
  subject (OIDC Core 5.3.2).

## [0.0.6] - 2026-05-24

### Added

- Added integration with the split `openauth-oidc` and `openauth-saml` crates.
- Added OIDC registration, discovery, callback, provider update, and sign-in
  coverage.
- Added SAML metadata/ACS state and security coverage.
- Added provider fixtures and additional endpoint error coverage.

### Changed

- Closed OIDC and SAML behavior gaps against the upstream reference.
- Updated provider registration, sign-in, callback, store, secret, OpenAPI, and
  schema handling.

## [0.0.5] - 2026-05-19

### Added

- Published the beta SSO release line.

