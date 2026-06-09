# Changelog

All notable changes to `openauth-saml` are documented in this file.

## [Unreleased]


### Added

- SAML crypto e2e tests in `openauth-sso` using vendorized PEM fixtures and
  `opensaml`-backed signed/encrypted login responses and SLO messages.
- Production-shaped IdP fixture tests (Okta/Azure/Google SAML) in
  `openauth-sso` (`provider_fixtures.rs`, `fixtures/saml/idp/*-shaped.json`).
- Inbound SLO parse via `opensaml::logout` with legacy fallback for unsigned
  messages and detached redirect signatures verified separately.
- Upstream `saml.test.ts` parity matrix in
  `docs/superpowers/specs/openauth-sso/gap-analysis.md`.

### Changed

- `saml-signed` now enables real XMLDSig/XML-Enc via `opensaml/crypto-bergshamra`
  (no longer a placeholder).
- `decrypt_encrypted_assertion_response` now decrypts encrypted assertions with
  `opensaml` when `saml-signed` is enabled instead of returning a placeholder
  failure.
- LogoutRequest/LogoutResponse preserve caller-provided IDs under `saml-signed`.
- Redirect SLO signature verification decodes DEFLATE/base64 before octet
  construction (fixes detached redirect binding verify).
- ACS attribute extraction falls back to XML parsing when `opensaml` flow extract
  omits `AttributeStatement` values.

### Fixed

- SP clock skew passed to `opensaml` as symmetric `(-skew, +skew)` drift window.
- GET `/sso/saml2/sp/slo/:providerId` no longer requires `Content-Type` (fixes
  IdP-initiated redirect SLO).
- Unsigned logout requests with `wantLogoutRequestSigned` return
  `SAML_LOGOUT_REQUEST_SIGNATURE_REQUIRED` instead of crypto parse errors.

## [0.0.6] - 2026-05-24

### Added

- Added the first standalone `openauth-saml` crate release.
- Added SAML service-provider options, AuthnRequest handling, assertion
  helpers, and security tests split from SSO.
- Added the `saml-signed` feature flag (placeholder at release time; implemented
  in `[Unreleased]`).

