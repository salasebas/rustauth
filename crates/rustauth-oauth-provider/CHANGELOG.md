# Changelog

## [0.3.2](https://github.com/salasebas/rustauth/compare/v0.3.0...v0.3.2) - 2026-07-26

### Changed

- release v0.3.1 ([#175](https://github.com/salasebas/rustauth/pull/175))
- [codex] Preserve offline refresh-token semantics ([#205](https://github.com/salasebas/rustauth/pull/205))

### Fixed

- fix oauth client reference id update ([#181](https://github.com/salasebas/rustauth/pull/181))
- *(oauth)* enforce skip-consent boundary
- *(oauth)* prevent public client downgrade
- *(oauth)* bind introspection and revocation to clients

## [0.3.1](https://github.com/salasebas/rustauth/compare/v0.3.0...v0.3.1) - 2026-07-02

### Fixed

- fix oauth client reference id update ([#181](https://github.com/salasebas/rustauth/pull/181))
- *(oauth)* enforce skip-consent boundary
- *(oauth)* prevent public client downgrade
- *(oauth)* bind introspection and revocation to clients

## [0.2.0] - 2026-06-14

Initial public working release.

### Added

- OAuth 2.1 / OpenID Connect authorization server plugin.
- Authorization, consent, token, introspection, logout, userinfo, and metadata endpoints.
- Optional MCP protected-resource metadata via `OAuthProviderOptions::mcp`.
- `test-util` feature for integration-test helpers.

[0.2.0]: https://github.com/salasebas/rustauth/releases/tag/v0.2.0
