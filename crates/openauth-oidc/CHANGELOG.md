# Changelog

All notable changes to `openauth-oidc` are documented in this file.

## Unreleased

### Added

- Exported `REQUIRED_DISCOVERY_FIELDS` and upstream-matching discovery helpers:
  `validate_discovery_url`, `fetch_discovery_document`, `validate_discovery_document`,
  `normalize_discovery_urls`, and `select_token_endpoint_authentication`.
- Added discovery parity tests for custom discovery endpoints, scopes metadata,
  untrusted-origin rejection, and runtime discovery short-circuit/failure paths.

## [0.0.6] - 2026-05-24

### Added

- Added the first standalone `openauth-oidc` crate release.
- Added OIDC discovery, flow, options, and utility modules split from SSO.
- Added focused OIDC flow coverage.

