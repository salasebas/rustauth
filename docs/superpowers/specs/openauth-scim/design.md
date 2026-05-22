# OpenAuth SCIM Design

The SCIM crate is an OpenAuth plugin crate. It owns typed SCIM options,
provider schema, adapter-backed provider storage, bearer-token authentication,
SCIM metadata, SCIM User resource mapping, patch/filter parsing, and route
handlers.

## Current Baseline

- `crates/openauth-scim` currently exposes only `VERSION`.
- `crates/openauth-core` already provides plugin registration, async endpoint
  routing, OpenAPI metadata, body parsing, schema contribution, database
  adapter contracts, memory adapter, user/session/account models, and
  cryptographic helpers.
- Organization support already lives in `openauth-plugins` with logical
  `organization` and `member` models.
- SCIM should be implemented without any SSO or SAML dependency.
- Upstream's SCIM changelog only shows dependency/version maintenance through
  1.6.9, so the 1.6.9 source and tests are the authoritative local reference.

## Public Surface

- `scim(options: ScimOptions) -> AuthPlugin` builds the plugin.
- `UPSTREAM_PLUGIN_ID` is `scim`.
- `VERSION` remains the crate package version.
- Public exports include:
  - `ScimOptions`
  - `ScimProvider`
  - `ProviderOwnershipOptions`
  - `ScimTokenStorage`
  - SCIM User request/resource DTOs
- SCIM metadata DTOs where useful for tests and downstream consumers
- `ScimProviderConnection` or equivalent sanitized response type that excludes
  token material and normalizes absent `organizationId` to `null`.
- `ScimTokenGenerationContext` and `ScimTokenGeneratedContext` hook payload
  types.

## Module Layout

- `lib.rs`: public exports and plugin builder.
- `options.rs`: options, builders, hook types, token storage mode.
- `schema.rs`: `scimProvider` schema contribution and SCIM schema constants.
- `models.rs`: provider records and SCIM request/response types.
- `store.rs`: adapter-backed provider, user, account, and member operations.
- `token.rs`: token generation, base64url format, storage transformation,
  and verification.
- `auth.rs`: `Authorization` header extraction, token decode, provider lookup,
  and authenticated SCIM context.
- `org.rs`: organization membership lookup, role parsing, and access policy.
- `errors.rs`: SCIM error type and response renderer.
- `mappings.rs`: account ID, full name, primary email, resource URL helpers.
- `resources.rs`: OpenAuth user/account to SCIM User resource conversion.
- `filters.rs`: SCIM filter parser and database filter mapping.
- `patch.rs`: PatchOp validation and user/account patch builder.
- `routes/mod.rs`: endpoint registration.
- `routes/management.rs`: token and provider-connection management routes.
- `routes/users.rs`: SCIM User resource routes.
- `routes/metadata.rs`: ServiceProviderConfig, Schemas, and ResourceTypes.

Keep files focused. If a module starts mixing parsing, storage, and route
response assembly, split it before implementation continues.

## Schema Design

SCIM contributes logical model `scimProvider` with physical table
`scim_providers`.

Fields:

- `id` -> `id`, string, required.
- `providerId` -> `provider_id`, string, required, unique.
- `scimToken` -> `scim_token`, string, required, unique, hidden from public
  responses.
- `organizationId` -> `organization_id`, string, optional, indexed.
- `userId` -> `user_id`, string, optional, indexed, references `users.id`
  with cascade delete when provider ownership is enabled.

OpenAuth's core schema already uses snake_case logical fields for user,
account, session, and organization records. SCIM provider public JSON remains
camelCase, but adapter queries should use a clear conversion boundary instead
of scattering aliases through route code.

Unlike upstream, OpenAuth should keep one logical schema contract and let
adapters translate to physical snake_case/plural storage. Do not add Better
Auth-style field-name mapping options in this first implementation.

## Token Design

The returned token is an opaque bearer credential, but internally follows the
upstream-compatible format:

- Personal provider: `base64url(baseToken:providerId)`.
- Org provider: `base64url(baseToken:providerId:organizationId)`.

`providerId` cannot contain `:`. `organizationId` may contain `:`; parsing
joins all decoded token parts after the second segment.

The decoder should be tolerant of padded and unpadded base64url input because
upstream's default-provider test uses a padded base64 string. Generated tokens
should use the workspace's normal URL-safe representation.

Only `baseToken` is persisted after storage transformation:

- Plain: stored as-is.
- Hashed: SHA-256 digest encoded as base64url without padding.
- Encrypted: OpenAuth symmetric encryption using context secret config.
- Custom hash: async callback returns stored value.
- Custom encryption: async callbacks encrypt and decrypt stored value.

Token verification should compare using constant-time equality where practical
for plain/hash results. All malformed or failed verification paths return the
same SCIM 401 shape to avoid leaking which part failed.

Default SCIM providers are special: they are static plain-token entries and are
verified before database lookup. Do not hash or decrypt them through the
database token storage mode.

## Authentication Design

Management endpoints use the normal OpenAuth session cookie/session middleware
behavior.

SCIM User endpoints use SCIM bearer authentication:

- Read `Authorization`.
- Strip `Bearer` case-insensitively.
- Base64url decode the credential.
- Resolve provider by `providerId` and optional `organizationId`.
- Check `default_scim` before database lookup.
- Verify stored token according to configured storage mode.
- Pass `AuthenticatedScimProvider` into handlers through an endpoint
  middleware/extractor boundary.

The SCIM auth boundary should be route-local. Do not introduce hidden global
state.

The extractor should preserve enough context for handlers:

- Returned/base SCIM token string used for auth.
- Provider ID.
- Optional organization ID.
- Optional owner user ID.
- Whether the provider came from `default_scim` or the database.

## Route Design

All routes are plugin async endpoints.

Management routes:

- `/scim/generate-token`
- `/scim/list-provider-connections`
- `/scim/get-provider-connection`
- `/scim/delete-provider-connection`

SCIM User routes:

- `POST /scim/v2/Users`
- `GET /scim/v2/Users`
- `GET /scim/v2/Users/:userId`
- `PUT /scim/v2/Users/:userId`
- `PATCH /scim/v2/Users/:userId`
- `DELETE /scim/v2/Users/:userId`

Metadata routes:

- `/scim/v2/ServiceProviderConfig`
- `/scim/v2/Schemas`
- `/scim/v2/Schemas/:schemaId`
- `/scim/v2/ResourceTypes`
- `/scim/v2/ResourceTypes/:resourceTypeId`

SCIM v2 write routes accept `application/json` and `application/scim+json`.
DELETE must not require a request body. Be careful with OpenAuth endpoint
`allowed_media_types`: applying it to GET/DELETE can force an unnecessary
`Content-Type` header.

Management routes intentionally use normal OpenAuth API errors for session
auth and role-management failures. SCIM User routes and SCIM metadata not-found
failures render SCIM error JSON.

## Storage Design

`ScimProviderStore` wraps `&dyn DbAdapter` and owns conversion between
`DbRecord` and typed records. It should expose small operations instead of
letting route handlers build all queries inline:

- create provider
- find provider by ID and optional org
- list providers
- delete provider by ID
- find user/account for provider
- list provisioned users for provider/org
- create or update user/account
- create org membership if missing

For user/account operations, prefer existing OpenAuth core user/account helpers
where they provide the right behavior. Use direct adapter operations only where
SCIM-specific account/provider filtering is needed.

The store should expose sanitized provider response assembly so route code
cannot accidentally serialize `scim_token`. The raw provider record should stay
internal to `store` and `auth`.

Transactions should write result values through a small local pattern like the
existing `DbUserStore::create_oauth_user` transaction helper, because
OpenAuth's transaction callback returns `()`.

## Organization Design

SCIM uses organization data only when requested:

- Personal providers work without organization plugin.
- Org-scoped token generation requires organization plugin integration.
- Provider management checks read `member` rows by `userId` and
  `organizationId`.
- Required roles are resolved from options or default to `admin` plus creator
  role, defaulting to `owner`.
- Role strings are parsed as comma-separated values and trimmed.
- Required-role checks are used for token generation, provider list filtering,
  provider get, provider delete, and provider replacement.
- Existing org providers remain protected even if a different user omits
  `organizationId` while trying to regenerate the same `providerId`.
- If an org provider creator is removed from the organization, that user loses
  management visibility and get/delete access.

The design intentionally does not depend on `openauth-sso`. SCIM provider IDs
can reference SSO providers by convention, but SCIM itself treats them as opaque
external IDs.

## User Resource Design

SCIM User resources are projections of OpenAuth `user` plus provider `account`:

- `id`: OpenAuth user id.
- `externalId`: account account id.
- `userName`: user email.
- `name.formatted`: user name.
- `displayName`: user name.
- `active`: true.
- `emails`: one primary email equal to user email.
- `meta.resourceType`: `User`.
- `meta.created` and `meta.lastModified`: user timestamps.
- `meta.location`: base URL plus `/scim/v2/Users/:id`.
- `schemas`: SCIM User schema URN.

SCIM create computes:

- account id = `externalId` or `userName`.
- email = primary email, else first email, else `userName`.
- name = formatted name, else given/family name, else email.

Request validation and normalization:

- `userName` is required but does not need to be an email address.
- `userName` is lowercased at the boundary.
- `emails[].value` is validated as email only when supplied.
- Whitespace-only `name.formatted` is ignored.
- If both `givenName` and `familyName` are missing, name falls back to email.
- SCIM accounts should not store OAuth token material.

List responses intentionally match upstream's simple shape: no pagination
inputs, `startIndex: 1`, `itemsPerPage` equal to returned count, and
`totalResults` equal to returned count.

Delete is a hard user delete in v1 because upstream calls its internal delete
user operation. A future deactivation mode can be added behind an option after
the initial parity implementation.

## Patch Design

Patch support should be isolated in `patch.rs` and should not know about HTTP
or adapters. It receives the current user and typed operations, then returns
separate user/account patch maps.

Supported behavior:

- `add` and `replace` only; `remove` is accepted by validation but ignored.
- Operation names are case-insensitive.
- Omitted `op` defaults to `replace`.
- Paths accept leading slash, no leading slash, and dot notation.
- Operations may omit `path` when `value` is an object containing supported
  fields.
- Object values recurse through nested fields, including `path: "name"` with
  `{ "givenName": "A" }`.
- `userName` values are lowercased.
- `name.givenName` and `name.familyName` recompute formatted name using the
  current or already-patched counterpart.
- `add` skips a user-field update when the value already exists.
- Unsupported fields and `remove` operations produce no patch. The route turns
  an empty patch into SCIM 400 `No valid fields to update`.

## Error Design

Use a typed `ScimError` with HTTP status and optional SCIM type. Convert it to
JSON response:

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "status": "400",
  "detail": "Invalid SCIM filter",
  "scimType": "invalidFilter"
}
```

Non-SCIM management session failures can continue using normal OpenAuth API
errors, but SCIM bearer/user resource failures should render SCIM errors.

Error detail conventions to preserve:

- Missing bearer token: `SCIM token is required`.
- Invalid bearer token: `Invalid SCIM token`.
- Missing user or inaccessible provider-scoped user: `User not found`.
- Duplicate SCIM account: `User already exists` with SCIM type `uniqueness`.
- Empty PATCH result: `No valid fields to update`.
- Invalid filter: `scimType: "invalidFilter"`.

## OpenAPI Design

Attach operation IDs and response schemas where OpenAuth's endpoint metadata
supports it. Keep operation IDs stable:

- `generateSCIMToken`
- `listSCIMProviderConnections`
- `getSCIMProviderConnection`
- `deleteSCIMProviderConnection`
- `createSCIMUser`
- `listSCIMUsers`
- `getSCIMUser`
- `updateSCIMUser`
- `patchSCIMUser`
- `deleteSCIMUser`
- `getSCIMServiceProviderConfig`
- `getSCIMSchemas`
- `getSCIMSchema`
- `getSCIMResourceTypes`
- `getSCIMResourceType`

Hide SCIM v2 endpoints from ordinary end-user auth metadata when possible,
while still keeping OpenAPI schemas available for SCIM docs.

OpenAPI schemas should cover:

- SCIM error body.
- SCIM User resource.
- SCIM ListResponse for Users/Schemas/ResourceTypes.
- ServiceProviderConfig support flags and auth scheme.
- Schema attributes including nested `subAttributes`.
- ResourceType metadata.

## Testing Design

Test organization:

- `tests/metadata.rs`
- `tests/management.rs`
- `tests/users.rs`
- `tests/patch.rs`
- `tests/support/mod.rs`

Pure unit coverage should live beside implementation modules when it is tighter
and faster. Route-level behavior belongs in integration tests.

Database coverage policy:

- Memory adapter route tests are required for each user-facing behavior.
- Adapter-specific tests are required for database-backed behavior that can
  differ by adapter: schema creation, uniqueness, transactions, `in` filters,
  timestamp persistence, delete invalidation, and provider/user/account/member
  joins by query.
- Add coverage for SQLx SQLite/Postgres/MySQL, deadpool-postgres, and
  tokio-postgres where their crates already host adapter integration tests.
- Add module-level comments or a small matrix documenting which upstream test
  group each Rust test file covers.
- Include specific negative tests for padded default-provider tokens, invalid
  base64 bearer token, `Authorization` header casing, unsupported filters,
  invalid PATCH operation names, and no-body 204 responses.

## Security Defaults

- No production panics.
- No token material in provider list/get responses.
- No different error detail for token-not-found vs token-mismatch.
- No SAML parsing or SSO provider lookup in SCIM.
- Validate provider IDs before token generation.
- Validate emails supplied through SCIM request bodies.
- Treat token auth, provider access checks, account linking, user deletion, and
  org membership writes as security-sensitive and test them directly.
- Treat role-based authorization as advisory-sensitive because upstream marks
  the regular-member org token generation case with
  GHSA-2g28-66mv-wghh.
