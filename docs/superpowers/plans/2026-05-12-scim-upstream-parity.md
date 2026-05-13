# SCIM Upstream Parity Implementation Plan

> **Guide note:** This checklist is a reusable implementation guide, not a requirement to clone upstream line by line. If the Rust/OpenAuth implementation adds behavior that covers the same server-side intent more correctly, securely, or idiomatically than upstream, mark the related upstream-parity item as completed and document the stronger behavior in the implementation notes.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build server-side SCIM parity from Better Auth `packages/scim` 1.6.9 as an idiomatic Rust/OpenAuth SCIM module.

**Architecture:** Treat upstream as behavioral reference, not as structure to copy. Implement SCIM as a server plugin/module with typed options, storage contracts, bearer-token authentication, SCIM metadata endpoints, SCIM User resource endpoints, and management endpoints for provider connections. Keep browser-only and TypeScript-only client inference out of the Rust server core.

**Tech Stack:** Rust, Serde, HTTP/router framework used by OpenAuth, OpenAuth storage/session/plugin contracts, SCIM RFC 7643/7644 response shapes, bearer token authentication, Base64 URL encoding, SHA-256 hashing, optional symmetric encryption, async tests.

---

## Upstream Scope

Reference package:

- `upstream/better-auth/1.6.9/repository/packages/scim/package.json`
- `upstream/better-auth/1.6.9/repository/packages/scim/src/index.ts`
- `upstream/better-auth/1.6.9/repository/packages/scim/src/types.ts`
- `upstream/better-auth/1.6.9/repository/packages/scim/src/middlewares.ts`
- `upstream/better-auth/1.6.9/repository/packages/scim/src/routes.ts`
- `upstream/better-auth/1.6.9/repository/packages/scim/src/mappings.ts`
- `upstream/better-auth/1.6.9/repository/packages/scim/src/patch-operations.ts`
- `upstream/better-auth/1.6.9/repository/packages/scim/src/scim-error.ts`
- `upstream/better-auth/1.6.9/repository/packages/scim/src/scim-filters.ts`
- `upstream/better-auth/1.6.9/repository/packages/scim/src/scim-metadata.ts`
- `upstream/better-auth/1.6.9/repository/packages/scim/src/scim-resources.ts`
- `upstream/better-auth/1.6.9/repository/packages/scim/src/scim-tokens.ts`
- `upstream/better-auth/1.6.9/repository/packages/scim/src/user-schemas.ts`
- `upstream/better-auth/1.6.9/repository/packages/scim/src/utils.ts`
- `upstream/better-auth/1.6.9/repository/packages/scim/src/version.ts`
- `upstream/better-auth/1.6.9/repository/packages/scim/src/scim.test.ts`
- `upstream/better-auth/1.6.9/repository/packages/scim/src/scim-users.test.ts`
- `upstream/better-auth/1.6.9/repository/packages/scim/src/scim-patch.test.ts`
- `upstream/better-auth/1.6.9/repository/packages/scim/src/scim.management.test.ts`

Excluded from server parity:

- `src/client.ts`: Better Auth client plugin inference only. Do not port into the Rust server module except as future thin HTTP SDK work.
- `tsdown.config.ts`, `vitest.config.ts`, `tsconfig.json`: TypeScript package tooling only.
- NPM publish/export metadata except where it documents server package identity/versioning.

## Dependency And Equivalent Inventory

- [ ] **Input validation:** upstream uses `zod` for request schemas. Rust equivalent should be typed request structs with Serde plus boundary validation. If extra validation is needed, evaluate `validator`, custom constructors, or local validation helpers.
- [ ] **Base64 URL:** upstream uses `@better-auth/utils/base64` for token encoding/decoding. Rust equivalent can use an existing OpenAuth helper or the `base64` crate with URL-safe no-padding config.
- [ ] **SHA-256 hashing:** upstream uses `@better-auth/utils/hash` `createHash("SHA-256")`. Rust equivalent can use an existing crypto helper or `sha2`.
- [ ] **Symmetric encryption:** upstream uses `better-auth/crypto` `symmetricEncrypt`/`symmetricDecrypt`. Rust equivalent should use OpenAuth-owned crypto interfaces or an AEAD crate already approved by the project.
- [ ] **Random token generation:** upstream uses `generateRandomString(24)`. Rust equivalent should use a cryptographically secure RNG, through existing OpenAuth token utilities if available.
- [ ] **HTTP endpoint framework:** upstream uses `createAuthEndpoint`, `sessionMiddleware`, and endpoint metadata. Rust equivalent should use the project router/plugin pattern and preserve observable HTTP behavior.
- [ ] **Endpoint middleware framework:** upstream uses `createAuthMiddleware` to inject SCIM auth context into protected SCIM resource endpoints. Rust equivalent needs a composable request extractor/middleware with typed context.
- [ ] **Endpoint hiding/metadata:** upstream applies `HIDE_METADATA` to SCIM v2 resource and metadata endpoints while still attaching OpenAPI metadata. Rust equivalent should intentionally decide whether these routes are hidden from general auth metadata while keeping SCIM docs available.
- [ ] **SCIM errors:** upstream extends `APIError` and uses `better-call` status codes. Rust equivalent should return typed errors rendered as SCIM-compliant JSON bodies.
- [ ] **Storage adapter:** upstream uses generic `adapter.findOne/findMany/create/delete/transaction` plus internal adapter user/account operations. Rust equivalent needs storage traits for `user`, `account`, `member`, and `scim_provider`.
- [ ] **Organization dependency:** management and org-scoped provisioning depend on Better Auth `organization` plugin concepts: `organization`, `member`, roles, creator role. Rust equivalent needs a clean optional integration boundary with OpenAuth organization support.
- [ ] **SSO/SAML provider dependency:** upstream tests use `@better-auth/sso`, but the SCIM package only stores `providerId` and does not call SSO internals. Rust equivalent should not hard-depend on SSO unless OpenAuth provider connection semantics require it.
- [ ] **Bearer plugin dependency in tests:** upstream tests use Better Auth `bearer()` client support. Server behavior is just `Authorization: Bearer <scimToken>`.
- [ ] **Cookie/session test dependency:** upstream tests use `createAuthClient`, `setCookieToHeader`, email/password sign-in, and a memory adapter to obtain session headers for management endpoints. Rust tests need equivalent session fixture helpers, not a client SDK port.
- [ ] **SQL integration test hook:** upstream has a private `_createSqlTestInstance` helper using Better Auth `getTestInstance` for sqlite/postgres coverage. Rust parity should include adapter-level integration tests if OpenAuth supports multiple storage adapters.
- [ ] **TypeScript plugin registry dependency:** upstream augments `@better-auth/core` plugin registry for type inference. Rust equivalent is only a public trait/module registration concern; do not create a TypeScript-shaped registry layer.
- [ ] **OpenAPI metadata:** upstream includes OpenAPI schemas and hidden endpoint metadata. Rust equivalent can expose OpenAPI if the target project supports it, but SCIM JSON behavior is the required parity surface.

## Suggested Rust Module Decomposition

Use project conventions when implementing. These paths are suggested ownership boundaries for `crates/openauth-scim`:

- [ ] `src/lib.rs`: public SCIM plugin/module exports and version surface.
- [ ] `src/options.rs`: `ScimOptions`, provider ownership config, required role config, token storage mode config, token generation hooks.
- [ ] `src/model.rs`: `ScimProvider`, `ScimName`, `ScimEmail`, SCIM request/response DTOs.
- [ ] `src/storage.rs`: storage trait extensions or adapter calls for SCIM provider, user, account, member, organization lookups.
- [ ] `src/token.rs`: SCIM token format, storage, verification, hashing/encryption modes.
- [ ] `src/auth.rs`: bearer-token extraction, Base64 URL decode, provider lookup, `default_scim` handling, request context injection.
- [ ] `src/errors.rs`: SCIM-compliant error type and renderer.
- [ ] `src/mappings.rs`: account id, full name, primary email, resource URL helpers.
- [ ] `src/schema.rs`: SCIM User schema, ResourceType, ServiceProviderConfig, OpenAPI-compatible schema metadata if supported.
- [ ] `src/resource.rs`: `create_user_resource` mapping from OpenAuth user/account to SCIM User resource.
- [ ] `src/filter.rs`: SCIM filter parser and storage filter mapping.
- [ ] `src/patch.rs`: SCIM PatchOp parsing and user/account patch builder.
- [ ] `src/routes/management.rs`: token and provider-connection management endpoints.
- [ ] `src/routes/users.rs`: `/scim/v2/Users` endpoints.
- [ ] `src/routes/metadata.rs`: `/scim/v2/ServiceProviderConfig`, `/Schemas`, and `/ResourceTypes` endpoints.
- [ ] `tests/management.rs`: provider management and authorization behavior.
- [ ] `tests/metadata.rs`: SCIM metadata behavior.
- [ ] `tests/users.rs`: create/list/get/update/delete user behavior.
- [ ] `tests/patch.rs`: PatchOp behavior.
- [ ] `tests/support/mod.rs`: in-memory test setup, auth/session helpers, SCIM bearer header helpers, organization/member fixtures.

## Endpoint Construction And Metadata Checklist

- [ ] **Endpoint abstraction:** implement every route through OpenAuth's normal endpoint/router abstraction, equivalent in responsibility to upstream `createAuthEndpoint`.
- [ ] **Request validation binding:** bind body/query/path validation at the endpoint boundary, equivalent to upstream `body`, `query`, and route params in `createAuthEndpoint`.
- [ ] **Management middleware:** apply session-auth middleware only to management endpoints: `generateSCIMToken`, `listSCIMProviderConnections`, `getSCIMProviderConnection`, and `deleteSCIMProviderConnection`.
- [ ] **SCIM bearer middleware:** apply SCIM bearer middleware only to User resource endpoints: create, update, list, get, patch, and delete users.
- [ ] **Public metadata endpoints:** do not require session auth or SCIM bearer auth for ServiceProviderConfig, Schemas, Schema by id, ResourceTypes, and ResourceType by id.
- [ ] **Hidden metadata behavior:** mirror or intentionally replace upstream `HIDE_METADATA` on SCIM v2 endpoints so these routes do not accidentally appear as normal end-user auth APIs.
- [ ] **Allowed media types:** attach or enforce `application/json` and `application/scim+json` on SCIM v2 endpoints.
- [ ] **Delete content type:** allow DELETE requests without a content type/body when the HTTP layer validates media types.
- [ ] **OpenAPI summaries/descriptions:** carry endpoint-level summaries and SCIM RFC references into OpenAPI/docs where the Rust project supports generated docs.
- [ ] **OpenAPI response schemas:** attach response schemas for SCIM User resource, SCIM ListResponse, ServiceProviderConfig, Schema, ResourceType, management responses, and SCIM error responses.
- [ ] **Management operation ids:** preserve stable operation ids for `listSCIMProviderConnections`, `getSCIMProviderConnection`, and `deleteSCIMProviderConnection`, or document any idiomatic Rust rename.
- [ ] **Status codes:** set explicit 201 for create token/user, 200 for read/update/list/management success, 204 for patch/delete user success, 400/401/403/404/409 for failures.
- [ ] **Location header:** set `Location` on successful SCIM user creation.
- [ ] **No-body responses:** ensure 204 patch/delete responses do not serialize JSON bodies.
- [ ] **Route registration names:** expose route handlers under stable names matching the public server API where practical: `generate_scim_token`, `list_scim_provider_connections`, `get_scim_provider_connection`, `delete_scim_provider_connection`, `create_scim_user`, `update_scim_user`, `list_scim_users`, `get_scim_user`, `patch_scim_user`, `delete_scim_user`, `get_scim_service_provider_config`, `get_scim_schemas`, `get_scim_schema`, `get_scim_resource_types`, `get_scim_resource_type`.

## Plugin Surface Checklist

- [ ] **SCIM plugin identity:** expose plugin/module id `scim`.
- [ ] **SCIM version:** expose package/module version equivalent to the crate version.
- [ ] **Server endpoints registration:** register all management, SCIM User, and metadata endpoints.
- [ ] **Public types export:** expose server configuration and SCIM model types equivalent to upstream `export * from "./types"`.
- [ ] **Options defaulting:** default `store_scim_token` to plain storage unless caller configures another mode.
- [ ] **Provider ownership option:** support optional `provider_ownership.enabled`.
- [ ] **Required role option:** support optional `required_role`; when missing, default to `["admin", organization.creator_role_or_owner]`.
- [ ] **Default SCIM providers option:** support configured providers that bypass database provider lookup for tests/static setups.
- [ ] **Before token generation hook:** allow an async hook after built-in role checks and before persistence.
- [ ] **After token generation hook:** allow an async hook after persistence with created provider connection.
- [ ] **Server-only export boundary:** do not include the upstream TypeScript `scimClient` concept in the server crate.

## Storage Schema Checklist

- [ ] **`scim_provider.id`:** opaque provider connection id.
- [ ] **`scim_provider.provider_id`:** required unique provider identifier.
- [ ] **`scim_provider.scim_token`:** required unique stored token material; value may be plain, hashed, encrypted, or custom transformed.
- [ ] **`scim_provider.organization_id`:** optional organization scope.
- [ ] **`scim_provider.user_id`:** optional owner id when provider ownership is enabled.
- [ ] **User dependency:** SCIM provisioning reads/creates/updates/deletes OpenAuth users.
- [ ] **Account dependency:** SCIM provisioning links users to provider accounts using `provider_id` plus computed `account_id`.
- [ ] **Member dependency:** org-scoped provisioning reads/creates organization membership rows.
- [ ] **Transactions:** create/update operations that touch user, account, and membership must be transactional where storage supports it.
- [ ] **Uniqueness behavior:** prevent duplicate account for same `provider_id` and computed `account_id`.

## Token Format And Storage Checklist

- [ ] **Generated base token:** generate cryptographically random base token of upstream-equivalent strength.
- [ ] **Returned bearer token format:** return Base64 URL encoding of `baseToken:providerId` for personal/non-org providers.
- [ ] **Org-scoped bearer token format:** return Base64 URL encoding of `baseToken:providerId:organizationId`.
- [ ] **Provider id validation:** reject provider ids containing `:` because the token format is colon-delimited.
- [ ] **Token storage input:** persist only the base token after storage transformation, not the full returned bearer string.
- [ ] **Plain storage mode:** store and compare the base token directly.
- [ ] **Hashed storage mode:** store Base64 URL encoded SHA-256 digest of the base token and verify by recomputing it.
- [ ] **Custom hash mode:** support caller-provided async hash function and compare hash output.
- [ ] **Encrypted storage mode:** encrypt token with server secret and verify by decrypting stored token.
- [ ] **Custom encryption mode:** support caller-provided async encrypt/decrypt functions.
- [ ] **Invalid token handling:** missing, malformed, unknown, or failed verification returns SCIM 401 JSON error.
- [ ] **Provider lookup by token parts:** lookup provider by `provider_id` and optional `organization_id`.
- [ ] **Default provider verification:** when `default_scim` matches provider/org, compare configured plain token directly.

## Authentication Middleware Checklist

- [ ] **Authorization header:** require `Authorization: Bearer <token>` case-insensitively for SCIM resource endpoints.
- [ ] **Bearer extraction:** remove the `Bearer` prefix and reject empty credentials.
- [ ] **Base64 URL decode:** decode bearer token and split into base token, provider id, and optional organization id.
- [ ] **Organization id parsing:** preserve colons inside organization id by joining remaining token parts after the second colon.
- [ ] **Provider context:** inject authenticated SCIM token and `ScimProvider` into request context.
- [ ] **Default SCIM providers:** support default providers before database lookup.
- [ ] **Database providers:** support database lookup and configured verification modes.
- [ ] **SCIM error rendering:** all auth failures return `schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"]`, string `status`, and useful `detail`.

## Management Endpoint Checklist

### `POST /scim/generate-token`

- [ ] **Implementation:** require an authenticated user session.
- [ ] **Implementation:** validate request body with required `providerId` and optional `organizationId`.
- [ ] **Implementation:** reject `providerId` containing `:`.
- [ ] **Implementation:** reject `organizationId` usage when organization integration is not available.
- [ ] **Implementation:** when organization-scoped, require current user membership in the organization.
- [ ] **Implementation:** when organization-scoped, require one of the resolved roles.
- [ ] **Implementation:** if an existing provider connection matches, require access and delete it before creating the replacement.
- [ ] **Implementation:** generate returned token in the upstream colon-delimited Base64 URL format.
- [ ] **Implementation:** run `before_scim_token_generated` after built-in checks and before persistence.
- [ ] **Implementation:** store transformed base token according to configured storage mode.
- [ ] **Implementation:** set `user_id` on provider connection only when provider ownership is enabled.
- [ ] **Implementation:** run `after_scim_token_generated` after persistence.
- [ ] **Implementation:** return HTTP 201 with `{ "scimToken": "<token>" }`.
- [ ] **Tests:** session is required.
- [ ] **Tests:** user outside the requested org is denied.
- [ ] **Tests:** invalid provider id containing `:` is denied.
- [ ] **Tests:** token generation works through server API and client-facing call path where applicable.
- [ ] **Tests:** plain, hashed, custom hash, encrypted, and custom encryption storage modes generate usable tokens.
- [ ] **Tests:** org-scoped token includes organization behavior.
- [ ] **Tests:** before hook receives user, member, and token and can fail generation.
- [ ] **Tests:** after hook receives user, member, token, and created provider.
- [ ] **Tests:** regenerate is denied when current user is not owner of personal provider with ownership enabled.
- [ ] **Tests:** regenerate is denied when provider belongs to another organization.

### `GET /scim/list-provider-connections`

- [ ] **Implementation:** require an authenticated user session.
- [ ] **Implementation:** load all providers and filter to those accessible to current user.
- [ ] **Implementation:** include org providers only when user has required role in that organization.
- [ ] **Implementation:** include personal providers owned by current user.
- [ ] **Implementation:** include legacy personal providers without `user_id`.
- [ ] **Implementation:** return normalized providers without token material: `id`, `providerId`, `organizationId`.
- [ ] **Tests:** empty list when user has no accessible providers.
- [ ] **Tests:** org-scoped providers are visible to org members with required role.
- [ ] **Tests:** owned non-org providers are visible to owner.
- [ ] **Tests:** list endpoint filters org providers by role.

### `GET /scim/get-provider-connection`

- [ ] **Implementation:** require an authenticated user session.
- [ ] **Implementation:** validate query with required `providerId`.
- [ ] **Implementation:** return 404 when provider does not exist.
- [ ] **Implementation:** require org membership and role for org-scoped providers.
- [ ] **Implementation:** require owner for owned personal providers.
- [ ] **Implementation:** return normalized provider without token material.
- [ ] **Tests:** org member with role can read provider details.
- [ ] **Tests:** owner can read own non-org provider.
- [ ] **Tests:** non-owner cannot read owned non-org provider.
- [ ] **Tests:** user from another org receives 403.
- [ ] **Tests:** removed org member receives 403 for org provider.
- [ ] **Tests:** unknown provider id returns 404.

### `POST /scim/delete-provider-connection`

- [ ] **Implementation:** require an authenticated user session.
- [ ] **Implementation:** validate body with required `providerId`.
- [ ] **Implementation:** perform the same provider access checks as get/regenerate.
- [ ] **Implementation:** delete provider connection by provider id.
- [ ] **Implementation:** return `{ "success": true }`.
- [ ] **Implementation:** deleted provider token is invalid for future SCIM resource access.
- [ ] **Tests:** org member with role can delete org-scoped provider and invalidate token.
- [ ] **Tests:** user from another org receives 403.
- [ ] **Tests:** unknown provider id returns 404.
- [ ] **Tests:** non-owner cannot delete owned non-org provider.

## Role And Ownership Policy Checklist

- [ ] **Role parser:** parse comma-separated role strings into trimmed roles.
- [ ] **Multiple roles:** support role arrays or stored comma-separated role values according to OpenAuth storage conventions.
- [ ] **Required role resolution:** use configured `required_role` when provided.
- [ ] **Default roles:** otherwise allow `admin` and organization creator role, defaulting creator role to `owner`.
- [ ] **Empty required roles:** if the required role list is empty, allow any organization member.
- [ ] **Org provider access:** require organization plugin/integration for org-scoped provider access.
- [ ] **Org membership access:** deny access when user is not a member of the provider organization.
- [ ] **Role access:** deny access when user lacks required role.
- [ ] **Personal ownership access:** when `user_id` is present and different from current user, deny access.
- [ ] **Legacy personal provider access:** allow personal providers without `user_id` for backward compatibility.
- [ ] **Tests:** regular member cannot generate org-scoped token by default.
- [ ] **Tests:** admin can generate org-scoped token by default.
- [ ] **Tests:** user with multiple roles including admin can generate/list/get.
- [ ] **Tests:** custom required role is respected.
- [ ] **Tests:** customized organization creator role is included in default roles.

## SCIM User Request Validation Checklist

- [ ] **User schema:** accept `userName` as required string and normalize to lowercase.
- [ ] **External id:** accept optional `externalId`.
- [ ] **Name object:** accept optional `name.formatted`, `name.givenName`, `name.familyName`.
- [ ] **Emails array:** accept optional email entries with `value` and optional `primary`.
- [ ] **Email validation:** reject invalid email values.
- [ ] **Allowed media types:** accept `application/json` and `application/scim+json` for SCIM resource endpoints.
- [ ] **Delete media type:** additionally allow empty media type for DELETE if the HTTP layer checks request content type.

## SCIM User Mapping Checklist

- [ ] **Account id mapping:** compute account id as `externalId` when present, otherwise `userName`.
- [ ] **Primary email mapping:** choose primary email value, else first email value, else `userName`.
- [ ] **Name mapping:** prefer trimmed `name.formatted` when non-empty.
- [ ] **Name parts mapping:** when formatted is absent, join `givenName` and `familyName` when possible.
- [ ] **Name fallback:** fall back to email when no usable name is provided.
- [ ] **User resource id:** use OpenAuth user id.
- [ ] **User resource externalId:** expose linked account id.
- [ ] **User resource meta:** include `resourceType: "User"`, `created`, `lastModified`, and absolute `location`.
- [ ] **User resource userName:** expose user email.
- [ ] **User resource name/displayName:** expose user name as formatted name and display name.
- [ ] **User resource active:** upstream always returns `true`.
- [ ] **User resource emails:** expose primary user email as single primary email entry.
- [ ] **User resource schemas:** include `urn:ietf:params:scim:schemas:core:2.0:User`.
- [ ] **Resource URL helper:** join base URL and SCIM path without duplicate slashes.

## SCIM User Endpoint Checklist

### `POST /scim/v2/Users`

- [ ] **Implementation:** require valid SCIM bearer token.
- [ ] **Implementation:** validate SCIM user create body.
- [ ] **Implementation:** reject duplicate account for same provider id and computed account id with SCIM 409 `scimType: "uniqueness"`.
- [ ] **Implementation:** if user with computed email exists, link a new provider account to that user.
- [ ] **Implementation:** if user does not exist, create user then provider account.
- [ ] **Implementation:** for org-scoped provider, create default `member` role membership when missing.
- [ ] **Implementation:** perform user/account/member writes transactionally.
- [ ] **Implementation:** return HTTP 201 with SCIM User resource.
- [ ] **Implementation:** set `Location` response header to resource location.
- [ ] **Tests:** creates a new user.
- [ ] **Tests:** links a new account to an existing user.
- [ ] **Tests:** creates a user with external id.
- [ ] **Tests:** creates a user with given/family name parts.
- [ ] **Tests:** creates a user with formatted name.
- [ ] **Tests:** creates a user with primary email.
- [ ] **Tests:** creates a user with first non-primary email when no primary is set.
- [ ] **Tests:** rejects duplicate computed username/account.
- [ ] **Tests:** anonymous request without bearer token is rejected.

### `PUT /scim/v2/Users/:userId`

- [ ] **Implementation:** require valid SCIM bearer token.
- [ ] **Implementation:** find user only when linked account belongs to same provider and org scope is satisfied.
- [ ] **Implementation:** return SCIM 404 when not found or not accessible under provider/org scope.
- [ ] **Implementation:** replace user email/name from request mapping.
- [ ] **Implementation:** update account id from `externalId` or `userName`.
- [ ] **Implementation:** set updated timestamps for user and account.
- [ ] **Implementation:** return updated SCIM User resource.
- [ ] **Tests:** updates an existing resource.
- [ ] **Tests:** anonymous request without bearer token is rejected.
- [ ] **Tests:** missing/inaccessible resource returns 404.

### `GET /scim/v2/Users`

- [ ] **Implementation:** require valid SCIM bearer token.
- [ ] **Implementation:** list accounts for authenticated provider id.
- [ ] **Implementation:** return empty SCIM ListResponse when provider has no accounts.
- [ ] **Implementation:** if provider is org-scoped, restrict users to members of that organization.
- [ ] **Implementation:** return empty SCIM ListResponse when no members match org scope.
- [ ] **Implementation:** support optional SCIM filter and apply it to user lookup.
- [ ] **Implementation:** return SCIM ListResponse with `schemas`, `totalResults`, `startIndex: 1`, `itemsPerPage`, and `Resources`.
- [ ] **Tests:** returns list of provisioned users.
- [ ] **Tests:** returns empty list when no users were provisioned or none belong to org.
- [ ] **Tests:** only exposes users linked to same provider.
- [ ] **Tests:** only exposes users linked to same provider and organization.
- [ ] **Tests:** filters users by supported filter.
- [ ] **Tests:** anonymous request without bearer token is rejected.

### `GET /scim/v2/Users/:userId`

- [ ] **Implementation:** require valid SCIM bearer token.
- [ ] **Implementation:** find user only when linked account belongs to same provider and org scope is satisfied.
- [ ] **Implementation:** return SCIM User resource.
- [ ] **Implementation:** return SCIM 404 for missing/inaccessible users.
- [ ] **Tests:** returns single user resource.
- [ ] **Tests:** blocks access to user linked to another provider.
- [ ] **Tests:** blocks access to user outside provider organization scope.
- [ ] **Tests:** missing users return 404.
- [ ] **Tests:** anonymous request without bearer token is rejected.

### `DELETE /scim/v2/Users/:userId`

- [ ] **Implementation:** require valid SCIM bearer token.
- [ ] **Implementation:** find user only when linked account belongs to same provider and org scope is satisfied.
- [ ] **Implementation:** return SCIM 404 for missing/inaccessible users.
- [ ] **Implementation:** delete user using OpenAuth internal user deletion behavior.
- [ ] **Implementation:** return HTTP 204 with no body.
- [ ] **Tests:** deletes an existing user.
- [ ] **Tests:** anonymous request without bearer token is rejected.
- [ ] **Tests:** missing user is not deleted and returns 404.

## SCIM Filter Checklist

- [ ] **Filter parser:** parse simple expressions of shape `<attribute> <op> <value>`.
- [ ] **Supported operator:** support `eq` only.
- [ ] **Unsupported operators:** reject `ne`, `co`, `sw`, `ew`, and `pr` with invalid filter behavior.
- [ ] **Supported user attribute:** support `userName` mapped to storage field `email`.
- [ ] **Unsupported attributes:** reject attributes not present in the supported User schema mapping.
- [ ] **Quoted values:** strip double quotes from values.
- [ ] **Case normalization:** lower-case values for case-insensitive SCIM attributes.
- [ ] **Error mapping:** invalid filter returns SCIM 400 with `scimType: "invalidFilter"`.
- [ ] **Tests:** valid `userName eq "value"` filter returns matching users.
- [ ] **Tests:** malformed filter returns invalid filter error.
- [ ] **Tests:** unsupported operator returns invalid filter error.
- [ ] **Tests:** unsupported attribute returns invalid filter error.

## SCIM Patch Checklist

- [ ] **Patch request schema:** require `schemas` to include `urn:ietf:params:scim:api:messages:2.0:PatchOp`.
- [ ] **Patch operations:** accept `op` as case-insensitive `replace`, `add`, or `remove`; default to `replace` when omitted if target framework supports this behavior.
- [ ] **Patch operation path:** accept optional `path`.
- [ ] **Patch operation value:** accept arbitrary JSON value.
- [ ] **Implemented operations:** apply only `add` and `replace`; ignore `remove` operations.
- [ ] **Nested object values:** recursively traverse nested values to produce field paths.
- [ ] **Dot notation:** normalize dot paths like `name.givenName` to `/name/givenName`.
- [ ] **Slash notation:** normalize slash paths like `/name/givenName`.
- [ ] **Supported patch path:** `/name/formatted` updates user `name`.
- [ ] **Supported patch path:** `/name/givenName` updates user `name` while preserving derived family name from current name.
- [ ] **Supported patch path:** `/name/familyName` updates user `name` while preserving derived given name from current name.
- [ ] **Supported patch path:** `/externalId` updates account `accountId`.
- [ ] **Supported patch path:** `/userName` updates user `email` lowercased.
- [ ] **Add idempotency:** skip `add` for user fields when the current value already equals the new value.
- [ ] **Unknown paths:** ignore non-existing/unsupported paths.
- [ ] **No-op handling:** when no valid user/account fields are produced, return SCIM 400 `No valid fields to update`.
- [ ] **Patch persistence:** update user and account fields and timestamps when patches exist.
- [ ] **Patch response:** return HTTP 204 with no body on success.
- [ ] **Tests:** partially updates user with `replace`.
- [ ] **Tests:** partially updates user with `add`.
- [ ] **Tests:** mixed operations can update user and account fields together.
- [ ] **Tests:** dot notation paths are supported.
- [ ] **Tests:** add operation skips value that already exists where applicable.
- [ ] **Tests:** unsupported operation/path combinations are ignored.
- [ ] **Tests:** missing/inaccessible user returns 404.
- [ ] **Tests:** invalid updates/no valid fields return 400.
- [ ] **Tests:** anonymous request without bearer token is rejected.

## Metadata Endpoint Checklist

### `GET /scim/v2/ServiceProviderConfig`

- [ ] **Implementation:** public metadata endpoint; no SCIM bearer token required upstream.
- [ ] **Implementation:** return `patch.supported: true`.
- [ ] **Implementation:** return `bulk.supported: false`.
- [ ] **Implementation:** return `filter.supported: true`.
- [ ] **Implementation:** return `changePassword.supported: false`.
- [ ] **Implementation:** return `sort.supported: false`.
- [ ] **Implementation:** return `etag.supported: false`.
- [ ] **Implementation:** return OAuth bearer token authentication scheme with RFC 6750 URI.
- [ ] **Implementation:** return ServiceProviderConfig schema URN and meta resource type.
- [ ] **Tests:** response matches supported feature flags and authentication scheme.

### `GET /scim/v2/Schemas`

- [ ] **Implementation:** public metadata endpoint; no SCIM bearer token required upstream.
- [ ] **Implementation:** return SCIM ListResponse wrapper.
- [ ] **Implementation:** include supported User resource schema.
- [ ] **Implementation:** rewrite schema meta location to absolute URL using base URL.
- [ ] **Tests:** returns list with User schema and absolute location.

### `GET /scim/v2/Schemas/:schemaId`

- [ ] **Implementation:** public metadata endpoint; no SCIM bearer token required upstream.
- [ ] **Implementation:** return User schema for `urn:ietf:params:scim:schemas:core:2.0:User`.
- [ ] **Implementation:** return SCIM 404 when schema id is unsupported.
- [ ] **Tests:** returns single User schema.
- [ ] **Tests:** unsupported schema returns 404 SCIM error.

### `GET /scim/v2/ResourceTypes`

- [ ] **Implementation:** public metadata endpoint; no SCIM bearer token required upstream.
- [ ] **Implementation:** return SCIM ListResponse wrapper.
- [ ] **Implementation:** include User resource type.
- [ ] **Implementation:** rewrite resource type meta location to absolute URL using base URL.
- [ ] **Tests:** returns list with User resource type and absolute location.

### `GET /scim/v2/ResourceTypes/:resourceTypeId`

- [ ] **Implementation:** public metadata endpoint; no SCIM bearer token required upstream.
- [ ] **Implementation:** return User resource type for `User`.
- [ ] **Implementation:** return SCIM 404 when resource type id is unsupported.
- [ ] **Tests:** returns single User resource type.
- [ ] **Tests:** unsupported resource type returns 404 SCIM error.

## SCIM User Schema Checklist

- [ ] **Schema id:** `urn:ietf:params:scim:schemas:core:2.0:User`.
- [ ] **Schema wrapper:** `schemas: ["urn:ietf:params:scim:schemas:core:2.0:Schema"]`.
- [ ] **Schema name:** `User`.
- [ ] **Schema description:** `User Account`.
- [ ] **Attribute id:** string, non-multivalued, readOnly, returned default, server uniqueness.
- [ ] **Attribute userName:** string, required, non-case-exact, readWrite, returned default, server uniqueness.
- [ ] **Attribute displayName:** string, readOnly, returned default, no uniqueness.
- [ ] **Attribute active:** boolean, readOnly, returned default.
- [ ] **Attribute name:** complex object with formatted, familyName, givenName subattributes.
- [ ] **Name subattributes:** strings, non-case-exact, readWrite, returned default, no uniqueness.
- [ ] **Attribute emails:** complex multivalued, readWrite, returned default.
- [ ] **Email value subattribute:** string, non-case-exact, readWrite, returned default, server uniqueness.
- [ ] **Email primary subattribute:** boolean, readWrite, returned default.
- [ ] **Schema meta:** resource type `Schema`, location `/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User`.
- [ ] **Tests:** metadata snapshots or structured assertions cover the User schema shape.

## SCIM Resource Type Checklist

- [ ] **ResourceType schemas:** `["urn:ietf:params:scim:schemas:core:2.0:ResourceType"]`.
- [ ] **ResourceType id/name:** `User`.
- [ ] **ResourceType endpoint:** `/Users`.
- [ ] **ResourceType description:** `User Account`.
- [ ] **ResourceType schema:** User schema URN.
- [ ] **ResourceType meta:** resource type `ResourceType`, location `/scim/v2/ResourceTypes/User`.
- [ ] **Tests:** metadata assertions cover the resource type shape.

## Error Response Checklist

- [ ] **SCIM error schema:** every SCIM error body includes `schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"]`.
- [ ] **String status:** render HTTP status as a string in JSON body.
- [ ] **Detail field:** include human-readable `detail` for SCIM resource errors.
- [ ] **SCIM type field:** include `scimType` for uniqueness and invalid filter cases.
- [ ] **401 errors:** missing/invalid bearer token returns 401 SCIM error.
- [ ] **400 errors:** invalid filter or no valid patch fields returns 400 SCIM error.
- [ ] **404 errors:** missing schema/resource type/user returns 404 SCIM error.
- [ ] **409 errors:** duplicate SCIM user/account returns 409 SCIM error with `scimType: "uniqueness"`.
- [ ] **Management API errors:** session/role/provider management errors may use core API error format upstream; decide whether Rust module keeps core format for management endpoints or normalizes to SCIM JSON.
- [ ] **Tests:** assert status code and body shape for security-sensitive failures.

## Test Parity Checklist

### Upstream `scim.management.test.ts`

- [ ] **Test setup:** in-memory database includes `user`, `session`, `verification`, `account`, `ssoProvider`, `scimProvider`, `organization`, `member`.
- [ ] **Test setup:** email/password sign-up and sign-in helpers create session headers.
- [ ] **Test setup:** SCIM token helper calls management endpoint with session headers.
- [ ] **Test setup:** organization helper creates organizations for org-scoped providers.
- [ ] **Management tests:** cover generate token scenarios.
- [ ] **Management tests:** cover list provider connection scenarios.
- [ ] **Management tests:** cover get provider connection scenarios.
- [ ] **Management tests:** cover delete provider connection scenarios.
- [ ] **Management tests:** cover role-based authorization scenarios.
- [ ] **Management tests:** cover provider ownership scenarios.
- [ ] **Management tests:** cover token storage modes.
- [ ] **Management tests:** cover token generation hooks.

### Upstream `scim.test.ts`

- [ ] **Metadata tests:** ServiceProviderConfig response.
- [ ] **Metadata tests:** Schemas list response.
- [ ] **Metadata tests:** single Schema response.
- [ ] **Metadata tests:** unsupported Schema 404.
- [ ] **Metadata tests:** ResourceTypes list response.
- [ ] **Metadata tests:** single ResourceType response.
- [ ] **Metadata tests:** unsupported ResourceType 404.
- [ ] **Create user tests:** new user, existing user account link, external id, name parts, formatted name, primary email, first email fallback, duplicate account, anonymous access.
- [ ] **Update user tests:** full update, anonymous access, missing resource.

### Upstream `scim-users.test.ts`

- [ ] **List users tests:** provisioned users list.
- [ ] **List users tests:** empty list when no users or no org members match.
- [ ] **List users tests:** provider isolation.
- [ ] **List users tests:** provider plus organization isolation.
- [ ] **List users tests:** supported filter behavior.
- [ ] **List users tests:** anonymous access.
- [ ] **Get user tests:** single resource, provider isolation, provider plus organization isolation, missing user, anonymous access.
- [ ] **Delete user tests:** delete existing user, anonymous access, missing user.
- [ ] **Default provider tests:** static/default SCIM provider works.
- [ ] **Default provider tests:** invalid default provider token is rejected.

### Upstream `scim-patch.test.ts`

- [ ] **Patch tests:** replace operation updates supported fields.
- [ ] **Patch tests:** add operation updates supported fields.
- [ ] **Patch tests:** mixed operations update user and account together.
- [ ] **Patch tests:** dot notation paths work.
- [ ] **Patch tests:** idempotent add skips already existing value where applicable.
- [ ] **Patch tests:** unsupported/non-existing operation paths are ignored.
- [ ] **Patch tests:** missing user returns 404.
- [ ] **Patch tests:** invalid/no-op patch returns 400.
- [ ] **Patch tests:** anonymous access is rejected.

## Implementation Order Checklist

- [ ] **Task 1:** Define SCIM data model, options, storage schema, and error renderer.
- [ ] **Task 2:** Implement token generation, storage modes, verification, and auth middleware.
- [ ] **Task 3:** Implement management endpoints and role/ownership policy.
- [ ] **Task 4:** Implement SCIM metadata schemas and metadata endpoints.
- [ ] **Task 5:** Implement user mapping helpers and SCIM User resource serialization.
- [ ] **Task 6:** Implement create/update/list/get/delete user endpoints.
- [ ] **Task 7:** Implement SCIM filter parser and user filter integration.
- [ ] **Task 8:** Implement PatchOp parser/builder and PATCH endpoint.
- [ ] **Task 9:** Port upstream tests by behavior group.
- [ ] **Task 10:** Add crate-level docs/examples for configuring SCIM providers, token storage, org scoping, and bearer usage.

## Rust/OpenAuth Improvements Beyond Upstream

These are not required for upstream parity. If implemented, document the behavior and mark the related parity checklist item complete when the stronger behavior covers the same product intent.

- [ ] **Constant-time token comparison:** compare plain, hashed, decrypted, and default-provider tokens with a constant-time equality helper instead of normal string equality.
- [ ] **Token redaction:** ensure bearer tokens, base tokens, stored token material, encrypted token blobs, and hashes are never written to logs or returned in management responses.
- [ ] **Token storage default decision:** consider whether OpenAuth should keep upstream's `plain` default for compatibility or require/encourage `hashed` for safer production defaults.
- [ ] **Provider uniqueness model:** decide whether `provider_id` should be globally unique like upstream or unique per organization for better multi-tenant ergonomics; document the chosen constraint.
- [ ] **Token rotation transaction:** make provider replacement/token rotation atomic so the old token is not deleted unless the new provider record is persisted.
- [ ] **Malformed Base64 handling:** treat decode errors as SCIM 401 without leaking parser details or causing panics.
- [ ] **Pagination support:** upstream returns all users with `startIndex: 1`; OpenAuth may add SCIM `startIndex`/`count` support if needed for production identity providers.
- [ ] **Deprovision strategy:** upstream deletes users on DELETE; OpenAuth may support configurable delete vs deactivate behavior if that better matches server security and audit requirements.
- [ ] **Structured SCIM filter parser:** upstream supports only simple `userName eq ...`; OpenAuth may implement an extensible parser while preserving current supported behavior.
- [ ] **Audit hooks/events:** emit structured events for SCIM token generation, provider deletion, user provisioning, update, patch, and deletion if OpenAuth has an audit/event system.
- [ ] **Adapter conformance tests:** run the same SCIM integration scenarios against every supported storage adapter, not only an in-memory adapter.
- [ ] **Schema snapshot stability:** keep SCIM metadata tests as structured assertions or stable snapshots so accidental RFC-facing schema drift is visible.

## Final Verification Checklist

- [ ] **Build:** SCIM crate builds with workspace features.
- [ ] **Unit tests:** token, mapping, filter, patch, and error unit tests pass.
- [ ] **Integration tests:** management, metadata, users, and patch integration tests pass.
- [ ] **Security review:** bearer token parsing, token storage modes, provider/org isolation, and role checks are reviewed.
- [ ] **API review:** public Rust API is explicit, typed, and does not expose TypeScript-shaped client abstractions.
- [ ] **Documentation review:** docs clarify that SCIM resource endpoints use bearer tokens while management endpoints use authenticated sessions.
- [ ] **Dependency review:** any new crypto, validation, or base64 dependencies are proposed and approved before being added.
