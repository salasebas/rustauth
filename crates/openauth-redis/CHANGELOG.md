# Changelog

All notable changes to `openauth-redis` are documented in this file.

## [Unreleased]

### Fixed

- Made TLS connections work for documented `rediss://` and `valkeys://` URLs by
  adding opt-in `rustls` and `native-tls` crate features that enable the
  corresponding redis-rs TLS backend. Without a TLS feature these URLs now fail
  with a clear `InvalidClientConfig` error, and the README documents the
  opt-in.

## [0.0.6] - 2026-05-24

### Changed

- Updated Redis integration behavior and documentation around rate limiting.

### Fixed

- Hardened Redis rate-limit coverage.

## [0.0.5] - 2026-05-19

### Added

- Published the beta Redis integration release line.

