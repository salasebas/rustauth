# OpenAuth SCIM Tasks

## Phase 0: Spec Foundation

- [x] Inspect upstream Better Auth SCIM package source.
- [x] Inspect upstream SCIM tests for metadata, management, users, and patch
  behavior.
- [x] Confirm SCIM runtime has no SAML dependency.
- [x] Confirm upstream SSO usage is test fixture/dev dependency only.
- [x] Inspect upstream README and changelog for package-level requirements.
- [x] Inspect upstream metadata schemas and late patch/user/management test
  cases for hidden parity details.
- [x] Inspect OpenAuth plugin, router, schema, organization, and adapter
  patterns.
- [x] Create `docs/superpowers/specs/openauth-scim/requirements.md`.
- [x] Create `docs/superpowers/specs/openauth-scim/design.md`.
- [x] Create `docs/superpowers/specs/openauth-scim/tasks.md`.

## Phase 1: Public Plugin And Schema

- [x] Add public plugin builder `openauth_scim::scim(ScimOptions) ->
  AuthPlugin`.
- [x] Add `UPSTREAM_PLUGIN_ID = "scim"` and preserve `VERSION`.
- [x] Add `ScimOptions`, provider ownership options, token storage options,
  default provider options, and hook types.
- [x] Add `scimProvider` schema contribution with physical table
  `scim_providers`.
- [x] Add conversion helpers between SCIM public camelCase JSON and OpenAuth
  adapter snake_case fields.
- [x] Add public model types for `ScimProvider`, SCIM names, emails, user
  requests, user resources, list responses, metadata resources, and errors.
- [x] Add sanitized provider response type that cannot serialize token
  material.
- [x] Add root crate feature/re-export wiring if the public `openauth` facade
  should expose `openauth::scim`.
- [x] Test plugin identity, version, endpoint registration, and schema
  contribution.
- [x] Test schema physical table/field names and confirm `scim_token` is hidden
  from returned records when using selected fields.

## Phase 2: Core Pure Modules

- [x] Implement SCIM error type and SCIM JSON response renderer.
- [x] Implement resource URL helper.
- [x] Implement name/email/account ID mapping helpers.
- [x] Implement OpenAuth user/account to SCIM User resource conversion.
- [x] Implement static ServiceProviderConfig, User schema, and ResourceType
  resources.
- [x] Implement SCIM filter parser for `userName eq "value"`.
- [x] Implement filter rejection for malformed filters, unsupported attributes,
  and unsupported operators with `invalidFilter`.
- [x] Implement PatchOp parser and patch builder for supported user/account
  fields.
- [x] Implement PATCH path normalization for leading slash, no slash, dot
  notation, nested object values, and omitted path object payloads.
- [x] Implement PATCH operation normalization: default omitted op to
  `replace`, lowercase operation names, accept `remove` as no-op, reject unknown
  operations during validation.
- [x] Unit-test mappings, resources, metadata constants, filter parsing, patch
  operations, and SCIM error serialization.
- [x] Unit-test SCIM User schema attributes exactly cover upstream-supported
  `id`, `userName`, `displayName`, `active`, `name`, and `emails`.

## Phase 3: Token Handling

- [x] Implement random base token generation using OpenAuth crypto utilities.
- [x] Implement base64url returned bearer token encoding.
- [x] Implement bearer token decoding that accepts padded and unpadded
  base64url input.
- [x] Implement colon-delimited parsing that preserves colons inside
  organization IDs.
- [x] Reject `providerId` values containing `:`.
- [x] Implement plain token storage and verification.
- [x] Implement SHA-256/base64url hashed token storage and verification.
- [x] Implement OpenAuth symmetric encrypted token storage and verification.
- [x] Implement custom hash and custom encrypt/decrypt modes.
- [x] Use constant-time comparison where practical.
- [x] Implement default provider token verification before database lookup and
  keep it plain-token only.
- [x] Unit-test token format, malformed token rejection, invalid base64,
  padded default-provider token, organization IDs with colons, and all token
  storage modes.

## Phase 4: Store And Organization Access

- [x] Implement `ScimProviderStore` over `&dyn DbAdapter`.
- [x] Implement provider create/find/list/delete conversions.
- [x] Implement provider replacement lookup that prevents replacing another
  org's provider by omitting `organizationId`.
- [x] Implement user/account lookup by provider and account ID.
- [x] Implement provisioned-user list queries by provider and optional org.
- [x] Implement create-user/create-account/create-member transaction helpers.
- [x] Implement update-user/update-account transaction helpers.
- [x] Implement provider access policy helpers for ownership and org roles.
- [x] Implement role parsing for comma-separated stored roles.
- [x] Implement required-role resolution from options and organization creator
  role default.
- [x] Implement access denial when an org provider creator has been removed
  from the organization.
- [x] Ensure role parsing handles persisted comma-separated roles and the
  representation produced by organization role arrays.
- [x] Test store conversions and access policy with `MemoryAdapter`.
- [x] Test GHSA-2g28-66mv-wghh parity: regular members cannot generate or list
  org-scoped SCIM providers by default.

## Phase 5: Metadata Routes

- [x] Register `GET /scim/v2/ServiceProviderConfig`.
- [x] Register `GET /scim/v2/Schemas`.
- [x] Register `GET /scim/v2/Schemas/:schemaId`.
- [x] Register `GET /scim/v2/ResourceTypes`.
- [x] Register `GET /scim/v2/ResourceTypes/:resourceTypeId`.
- [x] Attach allowed media types and OpenAPI metadata where supported.
- [x] Avoid requiring `Content-Type` on metadata GET routes.
- [x] Test public access, expected response shapes, base URL locations,
  ServiceProviderConfig auth scheme fields, schema attributes, resource type
  metadata, and 404 errors for unsupported schema/resource type IDs.

## Phase 6: Management Routes

- [x] Register `POST /scim/generate-token`.
- [x] Register `GET /scim/list-provider-connections`.
- [x] Register `GET /scim/get-provider-connection`.
- [x] Register `POST /scim/delete-provider-connection`.
- [x] Require authenticated OpenAuth session for all management routes.
- [x] Implement token generation, replacement, and storage transformation.
- [x] Implement management before/after hooks.
- [x] Ensure before-hook failures abort persistence.
- [x] Ensure after-hook payload includes persisted provider and returned bearer
  token.
- [x] Implement provider list/get/delete with token material redaction.
- [x] Implement ownership and org role authorization for management routes.
- [x] Implement null `organizationId` in provider responses for personal
  providers.
- [x] Test session requirement, invalid provider IDs, all storage modes, hook
  behavior, token replacement, provider listing, provider get, provider delete,
  token invalidation, owner checks, org membership checks, and role checks.
- [x] Test all built-in and custom token storage modes through management routes.
- [x] Test before/after token hook behavior.
- [x] Test unknown provider get/delete returns not found.
- [x] Test removed org member cannot get/list an org provider they created.
- [x] Test custom `required_role`, multiple roles, admin success, and regular
  member denial.
- [x] Test customized organization creator role.

## Phase 7: SCIM Bearer Authentication

- [x] Implement route-local SCIM bearer middleware/extractor.
- [x] Support `Authorization: Bearer <token>` case-insensitively.
- [x] Support normal HTTP header casing for both `authorization` and
  `Authorization`.
- [x] Check default providers before database providers.
- [x] Verify database provider token according to configured storage mode.
- [x] Inject authenticated provider context into SCIM User handlers.
- [x] Return SCIM 401 JSON for missing, malformed, unknown, or invalid tokens.
- [x] Test anonymous access denial and invalid token denial for all SCIM User
  routes.
- [x] Test missing token detail is `SCIM token is required` and invalid token
  detail is `Invalid SCIM token`.

## Phase 8: SCIM User Routes

- [x] Register `POST /scim/v2/Users`.
- [x] Register `GET /scim/v2/Users`.
- [x] Register `GET /scim/v2/Users/:userId`.
- [x] Register `PUT /scim/v2/Users/:userId`.
- [x] Register `PATCH /scim/v2/Users/:userId`.
- [x] Register `DELETE /scim/v2/Users/:userId`.
- [x] Validate SCIM user request body and email values.
- [x] Accept non-email `userName` values and lowercase them.
- [x] Reject invalid `emails[].value` values.
- [x] Implement create/link behavior for new and existing users.
- [x] Implement org membership creation for org-scoped provider tokens.
- [x] Implement list behavior by provider and optional organization.
- [x] Implement get behavior with provider/org access restriction.
- [x] Implement PUT replacement for supported fields.
- [x] Implement PATCH add/replace behavior, case-insensitive operations,
  omitted-path object updates, dot notation, nested values, duplicate add skip,
  ignored remove, invalid operation validation, and invalid/no-op update
  errors.
- [x] Implement DELETE with 204 response and no body.
- [x] Keep DELETE as hard user deletion for v1.
- [x] Test upstream-equivalent create, list, filter, get, update, patch, delete,
  provider isolation, organization isolation, duplicate account conflict,
  missing user errors, invalid body errors, location header, and 204 responses.
- [x] Test invalid `emails[].value` errors and create `Location` header.
- [x] Test list response defaults to `startIndex: 1`, validates pagination
  inputs, applies `startIndex`/`count`, and reports `itemsPerPage` and
  `totalResults` consistently.
- [x] Test primary email selection, first-email fallback, `userName` fallback,
  formatted name precedence, given/family name composition, and whitespace-only
  formatted name fallback.
- [x] Test existing user by email links a new provider account without creating
  a duplicate user.
- [x] Test SCIM-linked accounts do not store OAuth access/refresh token
  material.

## Phase 9: Adapter Coverage

- [x] Add memory adapter integration coverage for all SCIM route behavior.
- [x] Add SQLx SQLite tests for SCIM schema and database-backed provisioning.
- [x] Add SQLx Postgres tests for SCIM schema and database-backed provisioning.
- [x] Add SQLx MySQL tests for SCIM schema and database-backed provisioning.
- [x] Add deadpool-postgres tests for SCIM schema and database-backed
  provisioning.
- [x] Add tokio-postgres tests for SCIM schema and database-backed
  provisioning.
- [x] Ensure database tests cover:
  - [x] transactions
  - [x] `in` filters
  - [x] uniqueness
  - [x] timestamps
  - [x] provider deletion invalidation
  - [x] org member filtering
- [x] Ensure adapter tests cover schema creation for `scim_providers` and
  physical snake_case columns.
- [x] Ensure tests cover default provider behavior without a
  `scimProvider` database row.

## Phase 10: Public API And Docs Hardening

- [x] Add crate README usage example for `scim(ScimOptions::default())`.
- [x] Add a test parity matrix in `crates/openauth-scim/tests/support` or
  module docs mapping Rust test files to upstream SCIM test files.
- [x] Add rustdoc examples for options and token storage modes.
- [x] Ensure `cargo fmt` leaves generated code clean.
- [x] Run `pnpm` only for JavaScript/TypeScript workflows if needed; do not use
  `npm`.
- [x] Run focused SCIM tests.
- [x] Run relevant workspace checks:
  - [x] `cargo test -p openauth-scim`
  - [x] `cargo clippy -p openauth-scim --lib`
  - [x] `cargo clippy -p openauth-scim --all-targets`
  - [x] `cargo check -p openauth --features scim`
  - [x] adapter crate tests touched by SCIM coverage
  - [x] `cargo clippy --all-targets --all-features --locked -- -D warnings`

## Explicit Boundaries For First Implementation

- [x] Do not port upstream `src/client.ts`.
- [x] Do not add SAML parsing or SSO provider lookup.
- [x] Do not add Better Auth-style custom field-name mapping for SCIM schema.
- [x] SCIM Groups, Bulk, Sort, ETags, projection, and list pagination are now
  implemented in the Rust crate.
- [x] Do not implement password change or provider-scoped `/Me`.
- [x] Keep PATCH remove semantics narrow; do not implement every SCIM
  path/filter variant.
- [x] Do not implement browser-only or TypeScript-only behavior in the Rust
  server crate.
