# Changelog

All notable changes to `openauth-i18n` are documented in this file.

## Unreleased

## [0.1.1] - 2026-06-09

### Changed

- **Breaking:** `I18nOptions::new()` takes no arguments; add locales with
  `.locale(code, entries)` or `I18nOptions::from_translations(map)` for
  existing `IndexMap` tables.
- `I18nOptions` is `#[non_exhaustive]`.

### Added

- `AsyncLocaleResolver` and `I18nOptions::get_locale_async` for Better Auth
  `getLocale` callbacks that return a `Promise`, wired through
  `openauth-core` `on_response_async` on async router paths.

## [0.0.6] - 2026-05-24

### Added

- Added typed locale, response, and i18n payload models.
- Added expanded locale response behavior and tests.

### Changed

- Updated plugin behavior and Accept-Language handling for richer responses.

## [0.0.5] - 2026-05-19

### Added

- Published the beta i18n release line.

