# Changelog

All notable changes to `openauth-telemetry` are documented in this file.

## [Unreleased]

### Changed

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

