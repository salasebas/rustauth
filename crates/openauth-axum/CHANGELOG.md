# Changelog

All notable changes to `openauth-axum` are documented in this file.

## Unreleased


### Added

- Added parity coverage for body-consuming Tower middleware ordered before auth
  routes, locking the stable JSON error returned for drained request bodies.

### Fixed

- Fixed request base URL inference so request-derived `Host` values are not
  trusted origins, and disabled that inference by default.

## [0.0.6] - 2026-05-24

### Added

- Added explicit adapter options, request conversion, response handling, router,
  and error modules.
- Added HTTP contract, error contract, security, routing, and storage smoke
  coverage.

### Changed

- Hardened Axum routing contracts and made adapter behavior easier to review
  through smaller modules.

## [0.0.5] - 2026-05-19

### Added

- Published the beta Axum integration release line.

