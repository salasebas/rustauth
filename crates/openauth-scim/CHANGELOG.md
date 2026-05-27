# Changelog

All notable changes to `openauth-scim` are documented in this file.

## Unreleased

### Added

- `docs/better-auth-design-differences.md` comparing OpenAuth SCIM to Better Auth 1.6.9.
- `tests/scim/routes/isolation.rs` for provider/org item-route and token-org boundary tests.
- Public `validation` module with email and SCIM identity validators.
- `filters::list_user_filter_uses_database_pushdown` for integrators.
- Crate and README documentation for provider id semantics (global unique,
  aligned with Better Auth) and list-filter evaluation paths.
- Route and bulk tests for invalid `userName`, `failOnErrors: 0`, and extended
  list filters.

### Changed

- Default `ScimOptions::token_storage` is now `Hashed` instead of `Plain`.
- SCIM provider token rotation uses `upsert` to preserve provider row ids.

### Fixed

- Reject provisioning when `userName` or resolved `emails` are not valid email
  addresses, including PATCH `userName` updates.
- Reject PUT and bulk PUT when `externalId` / `userName` would duplicate another
  user's provider account id.
- Reject PATCH and bulk PATCH when `externalId` would duplicate another user's
  provider account id.

### Added

- Integration tests for Groups auth, org-scoped Groups requirement, `If-Match: *`,
  bulk PATCH without concurrency headers, `admin,member` management roles,
  email-linked provisioning, metadata snapshots, and org-shared group visibility.
- `ScimBulkMode::Atomic` for all-or-nothing bulk requests on transactional DB
  adapters; `ScimBulkMode::Independent` remains the default (RFC sequential).
- `ScimDeprovisionMode::UnlinkAccount` to remove only the provider link on DELETE.
- Optional `ScimAuditEventResolver` for management, provisioning, and bulk events.

## [0.0.6] - 2026-05-24

### Added

- Added server-side SCIM provisioning with users, groups, bulk operations,
  metadata routes, management routes, organization scope handling, and auth
  context extraction.
- Added SCIM filters, patch operations, mappings, resources, schema, store,
  token, and error modules.
- Added adapter conformance, route, metadata, schema, store, token, filter,
  patch, and RFC parity coverage.

### Changed

- Hardened SCIM bulk, group membership, organization scope, and resource
  mutation behavior.

### Fixed

- Validated SCIM filters and documented protocol contracts.

## [0.0.5] - 2026-05-19

### Added

- Published the beta SCIM release line.

