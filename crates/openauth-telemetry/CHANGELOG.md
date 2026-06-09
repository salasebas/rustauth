# Changelog

All notable changes to `openauth-telemetry` are documented in this file.

## [Unreleased]

### Changed

- **Breaking:** `get_telemetry_auth_config`, `TelemetryTestHooks`, `DetectionInfo`,
  and `RuntimeInfo` are `#[doc(hidden)]` (still available for integration tests).
- Umbrella `openauth` feature `telemetry` now re-exports through `openauth::telemetry`
  instead of flattening symbols at the crate root.

## [0.1.1] - 2026-06-09

### Fixed

- `TelemetryPublisher::publish` waits for the async `init` bootstrap event before
  emitting later events, preserving documented CLI ordering in debug output and
  custom sinks.

### Changed

- README now documents that [`create_telemetry`](https://docs.rs/openauth-telemetry/latest/openauth_telemetry/fn.create_telemetry.html)
  immediately publishes an `init` event when telemetry is enabled and a sink
  exists, and that CLI `generate` / `migrate` runs emit `init` before their
  command-specific events.
- `get_telemetry_auth_config` now reports global hook presence, logger settings, `onAPIError`
  configuration (with URL redaction), custom password hash/verify callbacks, change-email
  confirmation hooks, verification `disableCleanup`, per-model schema alias presence, and
  structured `init_database_hooks` matrices from `OpenAuthOptions`.

### Added

- Depends on `openauth-core` `ModelSchemaOptions` and `InitDatabaseHooksOptions` for telemetry
  snapshot parity with Better Auth `modelName`/`fields` and `databaseHooks`.

## [0.0.6] - 2026-05-24

### Changed

- No code changes; version aligned with the workspace release.

## [0.0.5] - 2026-05-19

### Added

- Published the beta telemetry release line.

