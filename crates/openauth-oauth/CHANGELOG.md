# Changelog

All notable changes to `openauth-oauth` are documented in this file.

## Unreleased

### Added

- Added `validate_authorization_url_invariants` for manual provider URL builders
  that need the same non-empty `state` and parseable `redirect_uri` checks as
  `create_authorization_url`.

### Fixed

- Token exchange requires `code_verifier` when the authorization request used PKCE.
- Local ID token verification rejects non-integer `exp` / `iat` / `nbf` claims.
- Fixed the default OAuth HTTP client to block GET/POST requests whose URLs
  use literal private, loopback, or link-local IP addresses (SSRF hardening).
- Fixed HTTP Basic client authentication to form-encode `client_id` and
  `client_secret` per RFC 6749 §2.3.1 before Base64 encoding (reserved and
  non-ASCII credentials no longer break token exchange).
- Fixed authorization URL and authorization-code/refresh token request builders
  so `additional_params` cannot override `state`, PKCE (`code_challenge`,
  `code_verifier`, `code_challenge_method`), or other standard OAuth fields.

## [0.0.6] - 2026-05-24

### Added

- Added OAuth claims, JWKS, introspection, HTTP, request, and token validation
  helpers.
- Added authorization URL and refresh/access-token support helpers.
- Added expanded OAuth helper coverage.

### Changed

- Updated authorization-code validation and token verification behavior.
- Made JOSE support feature-gated through the crate feature surface.

## [0.0.5] - 2026-05-19

### Added

- Published the beta OAuth helper release line.

