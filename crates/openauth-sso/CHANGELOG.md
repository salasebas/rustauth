# Changelog

All notable changes to `openauth-sso` are documented in this file.

## Unreleased

### Added

- Added audit event `DomainVerificationRevoked` when an update clears a
  previously verified provider domain, with stable `reason` codes such as
  `oidc_trust_boundary_changed` and `saml_trust_boundary_changed`.

### Fixed

- SAML LogoutResponse handling now deserializes and validates the pending
  LogoutRequest record before consuming it, rejecting responses whose
  `InResponseTo` state belongs to another provider and redirecting to the
  stored logout callback instead of an unbound inbound `RelayState`.
- Organization assignment during OIDC/SAML callbacks now provisions members
  through the real organization plugin semantics when installed, including
  membership hooks, role validation, and membership limits.
- Fixed `update-provider` to revoke domain verification when merged OIDC or SAML
  config changes alter the effective IdP trust boundary, not only when top-level
  `issuer` or `domain` change. Auxiliary OIDC endpoints and SAML callback URLs
  may still be updated without revoking verification.
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

