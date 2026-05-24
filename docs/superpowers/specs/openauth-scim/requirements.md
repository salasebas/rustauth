# OpenAuth SCIM Requirements

OpenAuth SCIM ports the server-side behavior from Better Auth
`packages/scim` 1.6.9 into the existing Rust workspace. Upstream is the
behavioral and product reference, not a structure to copy mechanically.

## Coverage Source

- `docs/superpowers/plans/2026-05-12-scim-upstream-parity.md`
- `upstream/better-auth/1.6.9/repository/packages/scim`
- Upstream source files inspected:
  - `src/index.ts`
  - `src/types.ts`
  - `src/routes.ts`
  - `src/middlewares.ts`
  - `src/scim-tokens.ts`
  - `src/scim-filters.ts`
  - `src/patch-operations.ts`
  - `src/mappings.ts`
  - `src/scim-resources.ts`
  - `src/user-schemas.ts`
  - `src/scim-error.ts`
  - `src/scim-metadata.ts`
  - `src/utils.ts`
- Upstream tests inspected:
  - `src/scim.test.ts`
  - `src/scim-users.test.ts`
  - `src/scim-patch.test.ts`
  - `src/scim.management.test.ts`
- Upstream package docs inspected:
  - `README.md`
  - `CHANGELOG.md`

## Dependency Findings

- Upstream runtime dependency is `zod` for request validation.
- Upstream peer/runtime behavior depends on Better Auth core APIs, the generic
  database adapter, session middleware, bearer token headers, random token
  generation, SHA-256 hashing, and symmetric encryption helpers.
- Upstream tests import `@better-auth/sso`, but SCIM runtime code does not call
  SSO or SAML internals. Provider IDs are opaque strings. OpenAuth SCIM must
  not depend on `openauth-sso` or SAML.
- Upstream `package.json` lists `@better-auth/sso` only under dev
  dependencies. The only SSO references in tests are fixture setup and provider
  IDs such as `the-saml-provider-1`; they are not SCIM runtime requirements.
- Upstream tests use the organization plugin for org-scoped provider access and
  provisioning. OpenAuth SCIM must integrate with the existing organization
  plugin schema when that plugin is installed.
- Upstream `src/client.ts` is client-side type inference and convenience API.
  Do not port it into the server crate.
- Prefer existing workspace dependencies before proposing new crates:
  `openauth-core`, `serde`, `serde_json`, `base64`, `sha2`, `http`,
  `thiserror`, `time`, and `tokio`.
- If email validation needs behavior beyond simple syntax checks, propose the
  dependency before adding it. The default plan is a small local validation
  helper or existing OpenAuth validation, not a new validation crate.

## Core Requirements

- Expose a server-only `openauth_scim::scim(ScimOptions) -> AuthPlugin`.
- Keep plugin ID `scim` and crate version export aligned with
  `env!("CARGO_PKG_VERSION")`.
- Register all SCIM management, SCIM User, and SCIM metadata endpoints through
  OpenAuth's plugin endpoint system.
- Keep JSON field names compatible where useful: `providerId`, `scimToken`,
  `organizationId`, `userId`, `userName`, `externalId`, `displayName`,
  `itemsPerPage`, `totalResults`, `startIndex`, and `Resources`.
- Keep physical database tables plural and fields snake_case while preserving
  logical model names compatible with OpenAuth adapter conventions.
- Use OpenAuth's existing snake_case logical fields for core user/account/member
  operations. SCIM public JSON may be camelCase, but adapter queries for core
  models should use fields such as `provider_id`, `account_id`, `user_id`, and
  `organization_id` where the existing helpers expect them.
- Model fallible operations with typed errors and `Result`.
- Do not use `unwrap()` or `expect()` in production code.
- Validate all external input at endpoint boundaries.
- Return SCIM-compliant error JSON for SCIM resource failures:
  `schemas`, string `status`, optional `detail`, and optional `scimType`.

## Public API Requirements

- Export typed options:
  - `ScimOptions`
  - `ProviderOwnershipOptions`
  - `ScimTokenStorage`
  - token generation hooks
  - default SCIM provider configuration
- Default token storage mode is plain storage unless configured otherwise.
- Support provider ownership through `provider_ownership.enabled`.
- Support `required_role`; when absent, allow `admin` and the organization
  creator role, defaulting to `owner`.
- Support `default_scim` providers for test/static setups before database
  provider lookup.
- Default SCIM providers store plain base tokens. They must not be passed
  through configured database token hashing/encryption modes.
- Support async hooks:
  - `before_scim_token_generated` after built-in authorization checks and
    before persistence.
  - `after_scim_token_generated` after provider persistence.
- Hook payloads must include the authenticated user, optional organization
  member record, returned SCIM bearer token, and created provider record where
  upstream supplies them.
- Do not expose a TypeScript-shaped plugin registry or upstream client plugin.

## Storage Requirements

- Contribute logical model `scimProvider` backed by physical table
  `scim_providers`.
- Fields:
  - `id`: required provider connection id.
  - `providerId`: required unique provider identifier.
  - `scimToken`: required unique stored token material.
  - `organizationId`: optional organization scope.
  - `userId`: optional owner id when provider ownership is enabled.
- SCIM provisioning reads and writes existing OpenAuth `user` and `account`
  models.
- Org-scoped provisioning reads and writes existing organization `member`
  records when the organization plugin schema is installed.
- User creation that also creates an account and optional membership must run
  transactionally where the adapter supports transactions.
- Updates that touch user and account records must run transactionally where the
  adapter supports transactions.
- Duplicate account for the same `providerId` plus computed `accountId` must
  return SCIM 409 uniqueness error.
- SCIM-linked accounts must not receive OAuth token material. Store access and
  refresh tokens as absent/empty according to OpenAuth account conventions, and
  do not expose account token fields in SCIM responses.
- Provider list/get responses normalize missing `organizationId` to JSON null
  and never include `scimToken` or `userId` unless a future explicit admin API
  requires it.

## Token Requirements

- Generate cryptographically random base tokens with upstream-equivalent
  strength.
- Return bearer tokens as base64url of `baseToken:providerId` for personal
  providers.
- Return bearer tokens as base64url of `baseToken:providerId:organizationId`
  for org-scoped providers.
- Token decoding must accept URL-safe base64 with or without padding. Upstream
  default-provider tests use a padded token string.
- Reject `providerId` values containing `:` because the token format is
  colon-delimited.
- Store only the base token after configured transformation, not the full
  returned bearer token.
- Plain mode stores and compares the base token directly.
- Hashed mode stores a base64url SHA-256 digest of the base token.
- Custom hash mode stores caller-provided hash output and verifies by
  recomputing it.
- Encrypted mode uses OpenAuth symmetric encryption with server secret material.
- Custom encryption mode uses caller-provided encrypt/decrypt functions.
- Missing, malformed, unknown, or failed token verification must return SCIM
  401 JSON.
- Missing bearer credentials must return detail `SCIM token is required`.
- Malformed, unknown, or mismatched credentials must return detail
  `Invalid SCIM token`.
- `Authorization: Bearer <token>` is required for SCIM User resource endpoints;
  the `Bearer` prefix is case-insensitive.
- Header lookup must tolerate normal HTTP header casing. Tests should cover
  both `authorization` and `Authorization`.
- Token parsing must preserve colons inside organization IDs by joining all
  decoded token parts after the second colon.

## Management Endpoint Requirements

### `POST /scim/generate-token`

- Require authenticated user session.
- Accept required `providerId` and optional `organizationId`.
- Reject org-scoped tokens when organization integration is unavailable.
- When org-scoped, require current user membership in the organization and one
  of the resolved required roles.
- If an existing provider connection matches, require access to it, delete it,
  and create a replacement token.
- Existing provider lookup must consider `providerId`; this prevents a user
  from replacing another org's provider by omitting `organizationId`.
- Set `userId` only when provider ownership is enabled.
- Return HTTP 201 with `{ "scimToken": "<token>" }`.
- Before-hook failures must abort persistence and return the hook's error.
- After-hook failures should propagate as request failures after persistence,
  matching upstream's observable callback behavior.

### `GET /scim/list-provider-connections`

- Require authenticated user session.
- Return only providers accessible to the current user.
- Include org providers only when the user has a required role in that org.
- Include owned personal providers.
- Include legacy personal providers without `userId`.
- If a user was removed from an organization after creating an org provider,
  list must no longer show that provider to that user.
- Never return stored token material.

### `GET /scim/get-provider-connection`

- Require authenticated user session.
- Accept required query `providerId`.
- Return 404 for unknown provider.
- Require org membership and role for org providers.
- Require owner for owned personal providers.
- If the creator of an org provider is removed from the org, read access must
  return 403 even if that user originally generated the token.
- Never return stored token material.

### `POST /scim/delete-provider-connection`

- Require authenticated user session.
- Accept required body `providerId`.
- Apply the same provider access checks as read/regenerate.
- Delete the provider connection and invalidate the token.
- Return `{ "success": true }`.
- Unknown provider IDs return a not-found management error.

## SCIM User Endpoint Requirements

- Support `application/json` and `application/scim+json`.
- Enforce media type only on SCIM requests that actually have a body. OpenAuth's
  endpoint media-type validation should not accidentally require `Content-Type`
  on GET or DELETE without body.
- `POST /scim/v2/Users` creates or links a user:
  - `userName` is required and normalized to lowercase.
  - `userName` does not have to be an email address; upstream accepts arbitrary
    strings.
  - `externalId` is optional and becomes account ID when present.
  - `emails` is optional; primary email wins, otherwise first email,
    otherwise `userName`.
  - `emails[].value` must be a syntactically valid email when supplied.
  - `name.formatted` wins for display name, otherwise
    `givenName familyName`, otherwise email.
  - Whitespace-only `name.formatted` is ignored.
  - Existing user by email gets a new provider account.
  - New email creates user and provider account.
  - Org-scoped tokens add missing `member` row with role `member`.
  - Return HTTP 201, SCIM User resource JSON, and `Location` header.
- `GET /scim/v2/Users` lists only users provisioned for the authenticated
  provider and, when token is org-scoped, only users in that organization.
- `GET /scim/v2/Users/:userId` returns one provisioned user or SCIM 404.
- `PUT /scim/v2/Users/:userId` replaces supported user/account fields and
  returns a SCIM User resource.
- `PUT` must update both user email/name and linked account ID when
  `externalId` changes.
- `PATCH /scim/v2/Users/:userId` supports `add` and `replace` operations for:
  - `/externalId`
  - `/userName`
  - `/emails` as a whole-attribute replacement
  - `/name/formatted`
  - `/name/givenName`
  - `/name/familyName`
  - dot-notation equivalents
  - nested object values with path prefix
  - operations without explicit `path` when `value` is an object containing
    supported fields
- `PATCH` operation names are case-insensitive and default to `replace` when
  omitted.
- `PATCH` rejects read-only core attributes with SCIM `mutability`; if no valid
  fields remain, return SCIM 400 with detail `No valid fields to update`.
- `PATCH` validates email replacement values, including email address format
  and at most one primary email.
- `PATCH` with `add` should skip a user field when the mapped value already
  equals the current value; if that leaves no valid update, return the same
  no-valid-fields error.
- Invalid operation names must fail request validation before applying changes.
- `DELETE /scim/v2/Users/:userId` deletes the OpenAuth user and returns 204.
- Deletion is a hard delete for the first implementation, matching upstream's
  current behavior. SCIM deactivation is not implemented yet.
- Successful `PATCH` and `DELETE` responses must have status 204 and no JSON
  body.

## SCIM Metadata Requirements

- Metadata endpoints are public and require neither session auth nor SCIM
  bearer auth.
- `GET /scim/v2/ServiceProviderConfig` returns support flags matching the
  current Rust surface: patch true, bulk true, filter true, password change
  false, sort true, etag true, OAuth bearer token auth scheme.
- The ServiceProviderConfig auth scheme must include name
  `OAuth Bearer Token`, type `oauthbearertoken`, RFC 6750 `specUri`, and
  `primary: true`.
- `GET /scim/v2/Schemas` returns a SCIM ListResponse with User, Group, and
  Enterprise User schemas.
- `GET /scim/v2/Schemas/:schemaId` returns a supported schema or SCIM 404.
- `GET /scim/v2/ResourceTypes` returns a SCIM ListResponse with User and Group
  resource types.
- `GET /scim/v2/ResourceTypes/:resourceTypeId` returns a supported resource
  type or SCIM 404.
- Resource URLs must be resolved against OpenAuth `base_url`.
- User schema attributes include core SCIM User fields, common multi-valued
  profile fields, and the Enterprise User extension.
- User ResourceType must expose id/name `User`, endpoint `/Users`, schema
  `urn:ietf:params:scim:schemas:core:2.0:User`, and location
  `/scim/v2/ResourceTypes/User` resolved against base URL.

## Filter Requirements

- Support upstream-compatible filter parsing for `userName eq "value"` and
  unquoted values.
- Map `userName` to OpenAuth user email.
- Perform case-insensitive matching when the SCIM schema attribute is not
  case-exact.
- Unsupported attributes or operators such as `ne`, `co`, `sw`, `ew`, or `pr`
  return SCIM 400 with
  `scimType: "invalidFilter"`.
- Malformed filter strings return detail `Invalid filter expression`.

## Organization Requirements

- SCIM must not require the organization plugin for personal providers.
- Org-scoped provider management requires organization plugin integration.
- Roles may be stored comma-separated; trim whitespace before matching.
- Role arrays created by the organization plugin must also be handled through
  the persisted representation used by OpenAuth adapters.
- Empty `required_role` means any organization member is allowed.
- Default required roles are `admin` and organization creator role, defaulting
  to `owner`.
- Personal providers with `userId` require owner access.
- Personal providers without `userId` remain accessible as legacy providers.
- Org-scoped User resource access is determined by the authenticated SCIM
  provider's `organizationId`, not by the session user.
- Role-based authorization covers GHSA-2g28-66mv-wghh upstream advisory
  behavior: regular members cannot generate or list org-scoped SCIM providers
  by default; admins and owners can.

## SCIM Compatibility Boundaries

- Groups, Bulk, filtering, sorting, ETags, projection, and `startIndex`/`count`
  pagination are supported by the current Rust crate.
- Password change and provider-scoped `/Me` are not supported.
- PATCH remove support is intentionally narrow and does not implement every
  SCIM path/filter variant.
- Deactivation or soft-delete is not implemented; DELETE remains hard delete.
- Do not implement a Rust client SDK in this phase.
- Do not implement SAML or SSO provider validation in SCIM.

## Testing Requirements

- Adapt upstream tests into focused Rust tests rather than cloning TypeScript
  test structure.
- Unit-test pure modules: token, filter, patch, mappings, resource conversion,
  schema metadata, and error rendering.
- Integration-test route behavior with `MemoryAdapter`.
- For every test that exercises database adapter behavior beyond pure memory
  fixtures, add coverage for each supported database adapter:
  - `openauth-core` `MemoryAdapter`
  - `openauth-sqlx` SQLite
  - `openauth-sqlx` Postgres
  - `openauth-sqlx` MySQL
  - `openauth-deadpool-postgres`
  - `openauth-tokio-postgres`
- Keep tests modular under `crates/openauth-scim/tests/`:
  `metadata.rs`, `management.rs`, `users.rs`, `patch.rs`, and `support/`.
- Add a parity matrix in test comments or module docs linking each major Rust
  scenario back to upstream files so omissions are easy to audit.
- Run focused crate tests first, then workspace checks relevant to changed
  crates.
