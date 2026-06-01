# Changelog

All notable changes to `openauth-cli` are documented in this file.

## Unreleased

### Changed

- Updated the generated Axum integration snippet from `init` to serve with
  `into_make_service_with_connect_info::<SocketAddr>()` so OpenAuth rate
  limiting sees real client IPs, with a note to configure trusted forwarding
  headers explicitly behind a proxy.

## [0.0.6] - 2026-05-24

### Added

- Added focused command modules for completions, database tasks, doctor,
  project info, initialization, plugins, schema output, and secret generation.
- Added environment, path, prompt, and output helpers for command execution.
- Added schema snapshot and command coverage for the expanded CLI surface.

### Changed

- Split the CLI application implementation into smaller command handlers.

## [0.0.5] - 2026-05-19

### Added

- Published the beta CLI release line.

