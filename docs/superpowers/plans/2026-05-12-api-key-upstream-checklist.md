# API Key Upstream Checklist Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Guia de uso:** Este documento es una guia reutilizable derivada del upstream de Better Auth. Si OpenAuth implementa un comportamiento equivalente, mas seguro, mas idiomatico en Rust, o mas completo que el upstream, el item correspondiente puede marcarse como completado aunque la estructura interna no sea identica.

**Goal:** Track the server-side behavior required to implement an idiomatic Rust API Key plugin based on Better Auth upstream `packages/api-key`.

**Architecture:** Model API keys as server-owned authentication credentials with typed configuration, explicit storage contracts, validation endpoints, quota/rate-limit accounting, and organization-aware ownership. Translate the upstream behavior into Rust contracts and endpoints without porting browser-only client code or TypeScript-specific plugin mechanics.

**Tech Stack:** Rust workspace crates, HTTP endpoint layer, typed errors, storage adapter abstraction, optional secondary storage, secure hashing, serde-compatible request/response models, async tests.

---

## Upstream Scope

Source package inspected: `upstream/better-auth/1.6.9/repository/packages/api-key`.

Server-relevant upstream files:

- `src/index.ts`: plugin defaults, key hashing, route registration, API-key session hook.
- `src/types.ts`: configuration and API key data model.
- `src/schema.ts`: `apikey` database schema.
- `src/adapter.ts`: database and secondary-storage adapter behavior.
- `src/rate-limit.ts`: rate-limit decision logic.
- `src/utils.ts`: dates, API error detection, IP extraction.
- `src/error-codes.ts`: error catalog.
- `src/org-authorization.ts`: organization membership and permission checks.
- `src/routes/*.ts`: create, verify, get, update, delete, list, expired cleanup.
- `src/api-key.test.ts` and `src/org-api-key.test.ts`: behavior reference.

Out of scope for Rust core:

- `src/client.ts` as a client SDK implementation.
- TypeScript package/build metadata: `package.json`, `tsconfig*`, `tsdown.config.ts`, `vitest.config.ts`.
- Browser-only client helper structure. Keep only the HTTP/server contract implied by endpoints.

## Package-Level Checklist

### Dependency and Capability Map

- [ ] Endpoint definitions use the OpenAuth equivalent of upstream `createAuthEndpoint`.
- [ ] Request/response schemas use typed validation equivalent to upstream `zod` schemas.
- [ ] Endpoint metadata can carry OpenAPI descriptions and response schemas where routes are public HTTP APIs.
- [ ] Session-required endpoints use a shared session middleware/extractor equivalent to upstream `sessionMiddleware`.
- [ ] Server/direct API calls use a shared session extractor equivalent to upstream `getSessionFromCtx`.
- [ ] API errors use a common typed error system equivalent to upstream `APIError`.
- [ ] Plugin configuration errors use a startup/configuration error distinct from request API errors.
- [ ] Key hashing uses a cryptographic SHA-256 implementation.
- [ ] Base64url encoding without padding is available for hashes.
- [ ] Key generation uses cryptographically secure random generation.
- [ ] Database schema composition supports plugin-owned schema extension equivalent to upstream `mergeSchema`.
- [ ] JSON parsing helpers are centralized and safe for malformed JSON.
- [ ] IP validation and normalization utilities are available for session mocking.
- [ ] Environment-aware test/development IP fallback is available.
- [ ] Async bounded concurrency helper exists for storage fan-out.
- [ ] Background task runner exists for deferred updates.
- [ ] Background task runner has a synchronous fallback when no handler is configured.
- [ ] Organization access-control integration can authorize resource/action pairs.
- [ ] Organization role permissions can include an `apiKey` resource with create/read/update/delete actions.
- [ ] Secondary storage contract supports `get`, `set` with optional TTL, and `delete`.
- [ ] Tests can control time with an injected/fake clock instead of sleeping.
- [ ] Tests can use in-memory database/storage fixtures.

### Modularization and File Boundaries

- [ ] API-key package is split into small modules rather than one large file.
- [ ] Public plugin entry point owns registration, defaults, route assembly, schema merge, and API-key session hook.
- [ ] Type/configuration module owns public options and `ApiKey` domain type.
- [ ] Schema module owns only database table/field definitions and storage transforms.
- [ ] Error module owns only stable error codes/messages.
- [ ] Adapter module owns database/secondary-storage read/write/list behavior.
- [ ] Rate-limit module owns pure rate-limit decision logic.
- [ ] Utilities module owns date, IP, and error type helper functions.
- [ ] Organization authorization module owns organization membership and permission checks.
- [ ] Route index module owns route factory, config resolution, default-config compatibility, and expired cleanup orchestration.
- [ ] Each endpoint route lives in its own module.
- [ ] Tests are grouped by behavior area, with larger scenarios outside production modules.
- [ ] Optional future client SDK lives outside Rust core or remains a thin generated wrapper over HTTP contracts.

### Plugin Shape and Configuration

- [ ] API Key plugin/feature registration exists on the server side.
- [ ] Package exposes an API-key module through the public Rust crate surface.
- [ ] `API_KEY_TABLE_NAME` equivalent is defined as `apikey`.
- [ ] Package versioning follows the workspace version policy.
- [ ] Configuration accepts a single configuration.
- [ ] Configuration accepts multiple named configurations.
- [ ] Multiple-configuration mode requires every configuration to have `config_id`.
- [ ] Multiple-configuration mode rejects duplicate `config_id` values.
- [ ] Missing `config_id` resolves to the default configuration.
- [ ] `default`, `None`, and legacy missing config IDs are treated as the same default config.
- [ ] Unknown `config_id` falls back to default only when upstream behavior does.
- [ ] Missing default configuration returns a typed API error.
- [ ] Default `api_key_headers` is `x-api-key`.
- [ ] Multiple API key headers can be configured and checked in order.
- [ ] Custom API key getter can extract a key from request context.
- [ ] Custom API key getter returning a non-string is rejected.
- [ ] Custom API key validator can approve or reject a key before storage lookup.
- [ ] Default key length is 64 characters excluding prefix.
- [ ] Custom key generator is supported server-side.
- [ ] Default prefix is supported.
- [ ] Prefix length limits are configurable.
- [ ] Name length limits are configurable.
- [ ] `require_name` configuration is supported.
- [ ] Metadata is disabled by default.
- [ ] Key hashing is enabled by default.
- [ ] Plaintext key storage is possible only through an explicit `disable_key_hashing` option.
- [ ] Default storage backend is database.
- [ ] Secondary storage backend is supported.
- [ ] Secondary storage with database fallback is supported.
- [ ] Custom API-key storage methods take precedence over global secondary storage.
- [ ] Deferred update behavior is configurable.
- [ ] API-key-backed sessions are disabled by default.
- [ ] API-key ownership reference defaults to `user`.
- [ ] Organization ownership reference is supported.

### Error Catalog

- [ ] Error code definitions are centralized and exported for server consumers.
- [ ] Error messages are stable enough for tests and downstream integrations.
- [ ] Invalid metadata type error exists.
- [ ] Refill amount without interval error exists.
- [ ] Refill interval without amount error exists.
- [ ] User banned error exists.
- [ ] Unauthorized or invalid session error exists.
- [ ] Key not found error exists.
- [ ] Key disabled error exists.
- [ ] Key expired error exists.
- [ ] Usage exceeded error exists.
- [ ] Key not recoverable error exists.
- [ ] Expiration too small error exists.
- [ ] Expiration too large error exists.
- [ ] Invalid remaining count error exists.
- [ ] Invalid prefix length error exists.
- [ ] Invalid name length error exists.
- [ ] Metadata disabled error exists.
- [ ] Rate limit exceeded error exists.
- [ ] No values to update error exists.
- [ ] Custom expiration disabled error exists.
- [ ] Invalid API key error exists.
- [ ] Invalid user/reference from API key errors exist.
- [ ] Invalid API key getter return type error exists.
- [ ] Server-only property error exists.
- [ ] Failed-to-update API key error exists.
- [ ] Name required error exists.
- [ ] Organization ID required error exists.
- [ ] User not member of organization error exists.
- [ ] Insufficient API key permissions error exists.
- [ ] No default API key configuration error exists.
- [ ] Organization plugin required error exists.
- [ ] Errors map to stable HTTP statuses used by the upstream behavior.

### Data Model and Schema

- [ ] Database table/module name remains stable even if Rust type names differ.
- [ ] Field names are mapped consistently between Rust domain types, persistence, and HTTP responses.
- [ ] `ApiKey` domain type exists.
- [ ] `id` is stored.
- [ ] `config_id` is stored and indexed.
- [ ] `name` is optional.
- [ ] `start` stores optional visible starting characters.
- [ ] `reference_id` stores the owner ID and is indexed.
- [ ] `prefix` is optional and stored separately from the secret.
- [ ] `key` stores the hashed key value and is indexed.
- [ ] `refill_interval` is optional.
- [ ] `refill_amount` is optional.
- [ ] `last_refill_at` is optional.
- [ ] `enabled` defaults to true.
- [ ] `rate_limit_enabled` defaults to true.
- [ ] `rate_limit_time_window` defaults from plugin config.
- [ ] `rate_limit_max` defaults from plugin config.
- [ ] `request_count` defaults to zero.
- [ ] `remaining` is optional and can explicitly be null.
- [ ] `last_request` is optional.
- [ ] `expires_at` is optional.
- [ ] `created_at` is required.
- [ ] `updated_at` is required.
- [ ] `permissions` are stored as structured server data or serialized JSON behind the storage boundary.
- [ ] `metadata` is optional and can round-trip as an object.
- [ ] Metadata storage transform avoids double-stringification for new records.
- [ ] Schema supports custom extension fields where the Rust project allows plugin schemas.

### Hashing, Key Generation, and Secret Handling

- [ ] Default key generator produces random alphabetic key material with configured length.
- [ ] Prefix is prepended to generated key when present.
- [ ] Default key hasher uses SHA-256.
- [ ] Hashed keys are base64url encoded without padding.
- [ ] Full plaintext API key is returned only at creation.
- [ ] Get/list/update/verify responses never expose the stored hash or full secret.
- [ ] `start` stores the first configured number of characters of the plaintext key.
- [ ] `start` can be disabled and then returns null.
- [ ] `start` length includes prefix characters.
- [ ] Disabled hashing stores/verifies the raw key only when explicitly configured.

### Storage Adapter

- [ ] Storage helper constants/functions are centralized to prevent key-format drift.
- [ ] Storage adapter hides database/secondary-storage differences from endpoints.
- [ ] Database lookup by hashed key is implemented.
- [ ] Database lookup by ID is implemented.
- [ ] Database list by `reference_id` is implemented.
- [ ] Database list supports `limit`.
- [ ] Database list supports `offset`.
- [ ] Database list supports sorting by requested field and direction.
- [ ] Database count is returned with list results.
- [ ] Secondary-storage key by hash uses `api-key:{hashed_key}`.
- [ ] Secondary-storage key by ID uses `api-key:by-id:{id}`.
- [ ] Secondary-storage reference list uses `api-key:by-ref:{reference_id}`.
- [ ] API keys serialize to secondary storage with date fields as ISO-compatible strings.
- [ ] API keys deserialize from secondary storage with date fields restored as dates.
- [ ] Invalid secondary-storage payloads deserialize to null instead of panicking.
- [ ] Secondary-storage TTL is calculated from `expires_at`.
- [ ] Expired or already-past TTL values are not written as positive TTLs.
- [ ] Secondary-storage create writes hash lookup and ID lookup.
- [ ] Secondary-storage create updates the reference list in non-fallback mode.
- [ ] Secondary-storage delete removes hash lookup and ID lookup.
- [ ] Secondary-storage delete removes key ID from the reference list in non-fallback mode.
- [ ] Secondary-storage list reads reference list and fetches key records.
- [ ] Secondary-storage list applies sorting in memory.
- [ ] Secondary-storage list applies pagination in memory.
- [ ] Secondary-storage list returns total count before pagination.
- [ ] Missing secondary storage in secondary-storage mode fails creates/updates/deletes with a clear server error.
- [ ] Missing secondary storage in secondary-storage read paths returns empty/null results consistently.
- [ ] Secondary-storage list fetches keys concurrently with bounded concurrency.
- [ ] Database fallback mode reads secondary storage before database.
- [ ] Database fallback mode populates secondary storage after DB lookup by hash.
- [ ] Database fallback mode populates secondary storage after DB lookup by ID.
- [ ] Database fallback mode populates secondary storage after DB list.
- [ ] Database fallback mode writes to both database and secondary storage on create.
- [ ] Database fallback mode updates both database and secondary storage on update.
- [ ] Database fallback mode deletes from both database and secondary storage on delete.
- [ ] Database fallback mode treats DB as source of truth for quota updates.
- [ ] Database fallback mode invalidates the reference list on create/delete instead of read-modify-write mutation.
- [ ] Database fallback mode rebuilds the reference list after DB-backed list.
- [ ] Fallback list population writes per-key entries concurrently with bounded concurrency.
- [ ] Custom storage `get`, `set`, and `delete` methods are used instead of global secondary storage.

### Legacy Metadata Migration

- [ ] Double-stringified metadata can be parsed without failing the request.
- [ ] Get by ID migrates legacy double-stringified metadata.
- [ ] List migrates legacy double-stringified metadata in batch.
- [ ] Update migrates legacy double-stringified metadata in the returned object and storage.
- [ ] Verify migrates legacy double-stringified metadata.
- [ ] Already-correct object metadata is returned unchanged.
- [ ] Null metadata is returned as null.
- [ ] Metadata migration failures are logged but do not fail the request.
- [ ] Batch metadata migration runs updates concurrently.
- [ ] Metadata migration only writes to database-backed storage modes.

### Rate Limit and Usage Accounting

- [ ] Rate-limit decision logic is testable as a pure function.
- [ ] Clock/time access is abstracted enough for deterministic tests.
- [ ] Global rate limiting can be disabled by configuration.
- [ ] Per-key rate limiting can be disabled.
- [ ] Null rate-limit window or max disables rate limiting for that key.
- [ ] First request sets `last_request` and `request_count` to 1.
- [ ] Requests after the time window reset `request_count` to 1.
- [ ] Requests inside the window increment `request_count`.
- [ ] Requests at or above `rate_limit_max` fail with rate-limit error.
- [ ] Rate-limit failures include `try_again_in`.
- [ ] Validation updates `last_request` on successful verification.
- [ ] Validation updates `request_count` on successful verification.
- [ ] `remaining` decreases on successful verification when not null.
- [ ] `remaining = 0` without refill deletes or invalidates the key and returns usage exceeded.
- [ ] `remaining = 0` with refill settings can recover after the refill interval.
- [ ] Refill resets remaining credits to `refill_amount` after interval.
- [ ] Refill does not occur before interval.
- [ ] Multiple refill cycles are handled correctly.
- [ ] Update operations do not implicitly modify `last_request`.
- [ ] Update operations do not implicitly decrement `remaining`.
- [ ] Explicit update of `remaining` is supported.
- [ ] Deferred updates can run quota/rate-limit writes in the background.
- [ ] Without a background task handler, deferred update mode still commits synchronously.

### Organization Authorization

- [ ] Organization support is feature-gated or optional so core API keys do not force organization dependencies.
- [ ] Organization authorization failures do not reveal keys across org/user boundaries.
- [ ] API-key permission actions are modeled as create/read/update/delete.
- [ ] Organization plugin/options are discovered from auth context.
- [ ] Missing organization plugin produces organization-plugin-required error.
- [ ] Organization-owned keys require `organization_id` on create.
- [ ] Organization-owned key operations verify membership.
- [ ] Organization owners are allowed all API-key actions.
- [ ] Organization roles can grant full API-key CRUD permissions.
- [ ] Organization roles can grant read-only API-key permission.
- [ ] Organization roles with no API-key permission are denied.
- [ ] Non-members are denied organization API-key access.
- [ ] User-owned and organization-owned keys remain separated by `references`.
- [ ] Organization-owned keys can be verified by key without user session ownership checks.
- [ ] Organization-owned keys cannot be used to mock a user session.
- [ ] Wrong `config_id` cannot access an organization key.

## Endpoint Checklist

### Endpoint Framework and OpenAPI Contract

- [ ] Every endpoint is registered through the shared endpoint builder equivalent to `createAuthEndpoint`.
- [ ] Endpoints define method and path in one place.
- [ ] Endpoints define typed body/query schemas before handler logic.
- [ ] Schemas include field-level descriptions where OpenAPI documentation is generated.
- [ ] Create endpoint has OpenAPI description and success response schema.
- [ ] Get endpoint has OpenAPI description and success response schema.
- [ ] Update endpoint has OpenAPI description and success response schema.
- [ ] Delete endpoint has OpenAPI description, request body schema, and success response schema.
- [ ] List endpoint has OpenAPI description and success response schema.
- [ ] Verify endpoint has a documented server contract even if upstream lacks explicit OpenAPI metadata.
- [ ] Delete-expired endpoint has a documented server contract even if upstream lacks explicit OpenAPI metadata.
- [ ] Public HTTP path/method mapping is stable: create POST, verify POST, get GET, update POST, delete POST, list GET, delete expired POST.
- [ ] Response schemas distinguish creation-only plaintext `key` from redacted key records.
- [ ] Error response shape is consistent across direct server calls and HTTP/client calls.
- [ ] OpenAPI metadata does not expose server-only fields as client-safe operations without marking restrictions.

### Create API Key: `POST /api-key/create`

- [ ] Endpoint exists.
- [ ] Request accepts optional `config_id`.
- [ ] Request accepts optional `name`.
- [ ] Request accepts optional nullable `expires_in` in seconds.
- [ ] Request accepts optional `prefix`.
- [ ] Request validates prefix format as alphanumeric plus `_` and `-`.
- [ ] Request accepts optional nullable `remaining`.
- [ ] Request accepts optional `metadata`.
- [ ] Request accepts optional `refill_amount`.
- [ ] Request accepts optional `refill_interval`.
- [ ] Request accepts optional `rate_limit_time_window`.
- [ ] Request accepts optional `rate_limit_max`.
- [ ] Request accepts optional `rate_limit_enabled`.
- [ ] Request accepts optional permissions.
- [ ] Request accepts server-side `user_id`.
- [ ] Request accepts `organization_id` for organization-owned keys.
- [ ] Client/request-context calls require an authenticated session.
- [ ] Client/request-context calls cannot provide server-only properties.
- [ ] Client HTTP calls cannot provide `user_id`.
- [ ] Server-side calls require either session user or `user_id` for user-owned keys.
- [ ] Server-side calls reject mismatch between session user and provided `user_id`.
- [ ] Organization-owned create requires `organization_id`.
- [ ] Organization-owned create checks `create` permission.
- [ ] Metadata is rejected when metadata support is disabled.
- [ ] Metadata must be an object when provided.
- [ ] `refill_amount` and `refill_interval` must be provided together.
- [ ] Custom expiration is rejected when disabled.
- [ ] `expires_in` below minimum is rejected.
- [ ] `expires_in` above maximum is rejected.
- [ ] Prefix shorter than configured minimum is rejected.
- [ ] Prefix longer than configured maximum is rejected.
- [ ] Name shorter than configured minimum is rejected.
- [ ] Name longer than configured maximum is rejected.
- [ ] Missing name is rejected when `require_name` is enabled.
- [ ] Expired key cleanup is triggered.
- [ ] Key is generated with configured generator.
- [ ] Key is hashed unless hashing is disabled.
- [ ] `start` is stored according to starting-character config.
- [ ] Default permissions are applied when explicit permissions are not provided.
- [ ] Dynamic default permissions can depend on reference ID and request context.
- [ ] Explicit permissions override default permissions.
- [ ] Created row stores resolved `config_id`.
- [ ] Created row stores `reference_id` based on owner type.
- [ ] Created row stores rate-limit defaults or server overrides.
- [ ] Created row stores `remaining` using upstream precedence.
- [ ] Created row stores refill settings.
- [ ] Created row stores expiration from request or default expiration.
- [ ] Database storage creates a database row.
- [ ] Secondary-storage mode generates an ID without database insert.
- [ ] Secondary-storage mode writes storage records.
- [ ] Fallback mode writes database row and secondary-storage records.
- [ ] Response includes the full plaintext key only on creation.
- [ ] Response returns metadata as object/null.
- [ ] Response returns permissions as object/null.

### Verify API Key: `POST /api-key/verify`

- [ ] Endpoint exists.
- [ ] Endpoint is registered with the shared endpoint builder even though upstream omits an explicit route path string in this file.
- [ ] Request accepts optional `config_id`.
- [ ] Request requires `key`.
- [ ] Request accepts optional required permissions.
- [ ] Verification resolves lookup configuration from request/default.
- [ ] Custom validator can return invalid response without storage lookup success.
- [ ] Key hashing respects `disable_key_hashing`.
- [ ] Missing key record returns `valid: false`.
- [ ] Disabled key returns `valid: false`.
- [ ] Expired key returns `valid: false` and deletes/invalidates the key.
- [ ] Permission mismatch returns `valid: false`.
- [ ] Missing permissions on a key fail when permissions are required.
- [ ] Exhausted key returns `valid: false`.
- [ ] Successful verification updates usage/rate-limit counters.
- [ ] Deferred update mode returns optimistic updated key state.
- [ ] Failure responses include upstream-compatible error code/message shape.
- [ ] Success response returns `valid: true`.
- [ ] Success response omits the stored secret/hash.
- [ ] Success response returns metadata as object/null.
- [ ] Success response returns permissions as object/null.
- [ ] Verification triggers expired cleanup in deferred/background mode.

### Validate API Key Internal Flow

- [ ] Internal validation function can be reused by endpoint and session hook.
- [ ] Internal validation loads from configured storage backend.
- [ ] Internal validation rejects missing records.
- [ ] Internal validation rejects disabled records.
- [ ] Internal validation removes expired records from the correct storage backends.
- [ ] Internal validation checks requested permissions.
- [ ] Internal validation deletes exhausted non-refillable keys from the correct storage backends.
- [ ] Internal validation calculates refill from `last_refill_at` or `created_at`.
- [ ] Internal validation decrements remaining quota after refill logic.
- [ ] Internal validation applies rate-limit decision.
- [ ] Internal validation writes updated state to database, secondary storage, or both.
- [ ] Internal validation reports failed updates as typed server errors.

### Get API Key: `GET /api-key/get`

- [ ] Endpoint exists.
- [ ] Query requires `id`.
- [ ] Query accepts optional `config_id`.
- [ ] Endpoint requires authenticated session.
- [ ] Lookup uses requested/default configuration.
- [ ] Missing key returns not found.
- [ ] Config mismatch returns not found.
- [ ] User-owned key can only be read by owner.
- [ ] Organization-owned key requires `read` permission.
- [ ] Expired cleanup is triggered.
- [ ] Legacy metadata migration is applied.
- [ ] Response omits stored secret/hash.
- [ ] Response returns metadata as object/null.
- [ ] Response returns permissions as object/null.

### Update API Key: `POST /api-key/update`

- [ ] Endpoint exists.
- [ ] Request requires `key_id`.
- [ ] Request accepts optional `config_id`.
- [ ] Request accepts server-side `user_id`.
- [ ] Request accepts optional `name`.
- [ ] Request accepts optional `enabled`.
- [ ] Request accepts optional `remaining`.
- [ ] Request accepts optional `refill_amount`.
- [ ] Request accepts optional `refill_interval`.
- [ ] Request accepts optional `metadata`.
- [ ] Request accepts optional nullable `expires_in`.
- [ ] Request accepts optional `rate_limit_enabled`.
- [ ] Request accepts optional `rate_limit_time_window`.
- [ ] Request accepts optional `rate_limit_max`.
- [ ] Request accepts optional nullable permissions.
- [ ] Endpoint requires session or server-side user identity.
- [ ] Session user and provided `user_id` mismatch is rejected.
- [ ] Client/request-context calls cannot provide server-only properties.
- [ ] Missing key returns not found.
- [ ] Config mismatch returns not found.
- [ ] User-owned key can only be updated by owner.
- [ ] Organization-owned key requires `update` permission.
- [ ] Name length is validated.
- [ ] Custom expiration disabled rejects expiration changes.
- [ ] Expiration minimum/maximum are validated.
- [ ] `expires_in = null` clears expiration.
- [ ] Metadata update is accepted only when metadata support is enabled.
- [ ] Metadata must be an object when provided.
- [ ] `refill_amount` and `refill_interval` must be provided together.
- [ ] Rate-limit fields can be updated server-side.
- [ ] Permissions can be updated server-side.
- [ ] Empty update body is rejected.
- [ ] Database mode updates database.
- [ ] Secondary-storage mode updates secondary storage.
- [ ] Fallback mode updates both database and secondary storage.
- [ ] Expired cleanup is triggered.
- [ ] Legacy metadata migration is applied.
- [ ] Response omits stored secret/hash.
- [ ] Response returns metadata as object/null.
- [ ] Response returns permissions as object/null.

### Delete API Key: `POST /api-key/delete`

- [ ] Endpoint exists.
- [ ] Request requires `key_id`.
- [ ] Request accepts optional `config_id`.
- [ ] Endpoint requires authenticated session.
- [ ] Banned users are rejected.
- [ ] Missing key returns not found.
- [ ] Config mismatch returns not found.
- [ ] User-owned key can only be deleted by owner.
- [ ] Organization-owned key requires `delete` permission.
- [ ] Database mode deletes database row.
- [ ] Secondary-storage mode deletes secondary-storage records.
- [ ] Fallback mode deletes from both database and secondary storage.
- [ ] Storage errors return typed server errors.
- [ ] Expired cleanup is triggered.
- [ ] Response returns `{ success: true }`.

### List API Keys: `GET /api-key/list`

- [ ] Endpoint exists.
- [ ] Endpoint requires authenticated session.
- [ ] Query accepts optional `config_id`.
- [ ] Query accepts optional `organization_id`.
- [ ] Query accepts optional non-negative integer `limit`.
- [ ] Query accepts optional non-negative integer `offset`.
- [ ] Query accepts optional `sort_by`.
- [ ] Query accepts optional `sort_direction` as `asc` or `desc`.
- [ ] Organization list requires `read` permission.
- [ ] Without `organization_id`, list returns user-owned keys.
- [ ] With `organization_id`, list returns organization-owned keys.
- [ ] With `config_id`, list reads only matching configuration.
- [ ] Without `config_id`, list queries each unique storage backend once.
- [ ] List deduplicates keys returned by multiple storage groups.
- [ ] List filters keys by ownership type.
- [ ] List filters keys by `reference_id`.
- [ ] List filters keys by config ID with default-config compatibility.
- [ ] List computes total before pagination.
- [ ] List applies offset after filtering.
- [ ] List applies limit after filtering.
- [ ] List supports sorting with pagination.
- [ ] Offset beyond total returns empty array.
- [ ] String query values for limit/offset are coerced.
- [ ] Expired cleanup is triggered.
- [ ] Response omits stored secret/hash for every key.
- [ ] Response returns metadata as object/null for every key.
- [ ] Response returns permissions as object/null for every key.
- [ ] Response includes `api_keys`, `total`, `limit`, and `offset`.
- [ ] List schedules or awaits batch legacy metadata migration.

### Delete All Expired API Keys: `POST /api-key/delete-all-expired-api-keys`

- [ ] Endpoint exists.
- [ ] Endpoint is registered with the shared endpoint builder even though upstream omits an explicit route path string in this file.
- [ ] Endpoint can bypass the cleanup throttle.
- [ ] Cleanup deletes keys where `expires_at` is before now and not null.
- [ ] Cleanup is throttled to avoid repeated execution within 10 seconds unless bypassed.
- [ ] Cleanup logs deletion failures.
- [ ] Success response returns `{ success: true, error: null }`.
- [ ] Failure response returns `{ success: false, error }`.

### API-Key Session Hook

- [ ] Request hook runs before endpoints when API-key sessions are enabled.
- [ ] Hook searches only configurations with `enable_session_for_api_keys`.
- [ ] Hook extracts key from custom getter, configured header, or first matching header in a list.
- [ ] Hook rejects non-string keys.
- [ ] Hook rejects keys shorter than configured default key length.
- [ ] Hook applies custom validator when configured.
- [ ] Hook hashes key unless hashing is disabled.
- [ ] Hook validates key through shared validation flow.
- [ ] Hook triggers expired cleanup and logs failures.
- [ ] Hook supports deferred cleanup when configured.
- [ ] Hook rejects organization-owned keys for session mocking.
- [ ] Hook loads user by API key `reference_id`.
- [ ] Hook rejects missing user.
- [ ] Hook creates session object using API key ID as session ID.
- [ ] Hook sets session token to the presented API key.
- [ ] Hook records user agent from request headers.
- [ ] Hook records IP address unless IP tracking is disabled.
- [ ] Hook uses API key expiration or normal session expiration.
- [ ] Hook stores session in request/auth context.
- [ ] Hook returns session directly for `/get-session`.

## Test Checklist

### Test Harness and Fixtures

- [ ] Test helper can create an auth instance with selected plugins.
- [ ] Test helper can create a client-like HTTP caller when HTTP contract tests are needed.
- [ ] Test helper can sign in a default test user and return headers/session identity.
- [ ] Test helper can sign in arbitrary users for ownership and organization tests.
- [ ] Tests can inspect database rows directly when migration/storage behavior requires it.
- [ ] Tests can provide global secondary storage.
- [ ] Tests can provide custom per-plugin storage.
- [ ] Tests can capture background task promises/jobs.
- [ ] Tests can fake timers and restore real timers after each test.
- [ ] Tests cover both direct server API calls and HTTP/client-style calls where behavior differs.

### Creation Tests

- [ ] Test client create without session fails.
- [ ] Test client create with session succeeds.
- [ ] Test server create without session/user ID fails.
- [ ] Test client cannot provide `user_id`.
- [ ] Test server create with `user_id` succeeds.
- [ ] Test rate-limit defaults on created key.
- [ ] Test required name behavior.
- [ ] Test configured rate-limit defaults.
- [ ] Test valid name.
- [ ] Test name below minimum fails.
- [ ] Test name above maximum fails.
- [ ] Test valid prefix.
- [ ] Test prefix below minimum fails.
- [ ] Test prefix above maximum fails.
- [ ] Test custom expiration succeeds.
- [ ] Test disabled key hashing creates/verifies raw-key records.
- [ ] Test custom expiration disabled fails.
- [ ] Test expiration below minimum fails.
- [ ] Test expiration above maximum fails.
- [ ] Test client cannot set refill/server-only values.
- [ ] Test refill interval without amount fails.
- [ ] Test refill amount without interval fails.
- [ ] Test refill interval and amount succeed.
- [ ] Test custom remaining succeeds.
- [ ] Test explicit `remaining = null` succeeds.
- [ ] Test `remaining = null` with refill settings remains null.
- [ ] Test `remaining = 0` with refill amount is accepted.
- [ ] Test undefined remaining with refill settings uses null upstream behavior.
- [ ] Test invalid metadata fails.
- [ ] Test valid metadata succeeds.
- [ ] Test returned metadata is object.
- [ ] Test metadata disabled rejects metadata.
- [ ] Test default `start` first six characters.
- [ ] Test disabled `start` stores null.
- [ ] Test custom `start` length.
- [ ] Test client cannot set custom rate-limit fields.
- [ ] Test server custom rate-limit fields are stored.

### Verification and Validation Tests

- [ ] Test verify without valid key fails.
- [ ] Test invalid key fails.
- [ ] Test repeated verification hits rate limit.
- [ ] Test verification succeeds after rate-limit window passes.
- [ ] Test verification decrements remaining.
- [ ] Test exhausted key fails.
- [ ] Test expired key fails and is removed/invalidated.
- [ ] Test verifying updates `last_request`.
- [ ] Test verifying decrements remaining while update does not.
- [ ] Test verification with matching permissions succeeds.
- [ ] Test verification with non-matching permissions fails.
- [ ] Test verification requiring permissions fails when key has none.
- [ ] Test verification returns metadata as object.
- [ ] Test verification returns permissions as object.

### Update Tests

- [ ] Test update without headers/user ID fails.
- [ ] Test update name with session succeeds.
- [ ] Test update name above maximum fails.
- [ ] Test update name below minimum fails.
- [ ] Test update with no values fails.
- [ ] Test update expiration succeeds.
- [ ] Test update expiration when disabled fails.
- [ ] Test update expiration below minimum fails.
- [ ] Test update expiration above maximum fails.
- [ ] Test update remaining succeeds.
- [ ] Test update refill interval without amount fails.
- [ ] Test update refill amount without interval fails.
- [ ] Test update refill amount and interval succeeds.
- [ ] Test update enabled flag succeeds.
- [ ] Test update invalid metadata fails.
- [ ] Test update valid metadata succeeds.
- [ ] Test update returns metadata as object.
- [ ] Test update does not modify `last_request`.
- [ ] Test update does not decrement `remaining`.
- [ ] Test update can explicitly change `remaining`.
- [ ] Test update permissions succeeds.

### Get/List/Delete Tests

- [ ] Test get by ID succeeds for owner.
- [ ] Test get missing ID fails.
- [ ] Test get returns metadata as object.
- [ ] Test list without session fails.
- [ ] Test list with session succeeds.
- [ ] Test list returns metadata as object.
- [ ] Test list returns total count.
- [ ] Test list limit.
- [ ] Test list offset.
- [ ] Test list limit and offset together.
- [ ] Test list sort by `created_at` ascending.
- [ ] Test list sort by `created_at` descending.
- [ ] Test list sort by name.
- [ ] Test list sorting with pagination.
- [ ] Test list offset beyond total returns empty array.
- [ ] Test list handles string query values for pagination.
- [ ] Test delete without session fails.
- [ ] Test delete with session succeeds.
- [ ] Test delete through HTTP/client contract succeeds.
- [ ] Test delete missing key fails.

### Permission and Refill Tests

- [ ] Test create with explicit permissions.
- [ ] Test get returns permissions as object.
- [ ] Test default permissions are applied.
- [ ] Test refill after interval restores credits.
- [ ] Test refill before interval does not restore credits.
- [ ] Test multiple refill cycles.

### Secondary Storage Tests

- [ ] Test create in secondary storage.
- [ ] Test get from secondary storage.
- [ ] Test list from secondary storage.
- [ ] Test secondary-storage list fetches keys concurrently.
- [ ] Test update in secondary storage.
- [ ] Test delete in secondary storage.
- [ ] Test verify from secondary storage.
- [ ] Test TTL is set for expiring keys.
- [ ] Test metadata round-trips in secondary storage.
- [ ] Test rate limiting works in secondary storage.
- [ ] Test remaining count works in secondary storage.
- [ ] Test expired secondary-storage keys fail verification.
- [ ] Test reference list is maintained in secondary storage.

### Secondary Storage With Database Fallback Tests

- [ ] Test reads check secondary storage first.
- [ ] Test quota updates persist to database in fallback mode.
- [ ] Test DB fallback auto-populates storage on get.
- [ ] Test DB fallback auto-populates storage on list.
- [ ] Test fallback list population is concurrent.
- [ ] Test fallback list does not mutate reference list per key.
- [ ] Test fallback create invalidates reference list.
- [ ] Test fallback delete invalidates reference list.
- [ ] Test concurrent fallback creates do not lose IDs.
- [ ] Test fallback create writes database and secondary storage.
- [ ] Test fallback update writes database and secondary storage.
- [ ] Test fallback delete removes database and secondary storage.

### Deferred Updates and Custom Storage Tests

- [ ] Test deferred updates use configured background task handler.
- [ ] Test deferred rate-limit validation remains correct after background writes.
- [ ] Test deferred remaining-count updates.
- [ ] Test deferred mode falls back to synchronous updates without handler.
- [ ] Test custom storage methods are used instead of global secondary storage.
- [ ] Test custom `get` is used.
- [ ] Test custom `delete` is used.

### Legacy Metadata Migration Tests

- [ ] Test get migrates double-stringified metadata.
- [ ] Test list migrates double-stringified metadata.
- [ ] Test update migrates double-stringified metadata.
- [ ] Test verify migrates double-stringified metadata.
- [ ] Test correctly formatted metadata needs no migration.
- [ ] Test null metadata is handled.

### Multiple Configuration Tests

- [ ] Test create with specific `config_id`.
- [ ] Test create without `config_id` uses default config.
- [ ] Test list filtered by `config_id`.
- [ ] Test verify applies correct config rate limits.
- [ ] Test get resolves correct config.
- [ ] Test update preserves `config_id`.
- [ ] Test delete from specific config.
- [ ] Test duplicate config IDs are rejected.
- [ ] Test missing config ID in array config is rejected.

### Organization API Key Tests

- [ ] Test organization owner has full CRUD access.
- [ ] Test non-member is denied create/read/update/delete/list.
- [ ] Test default member role without API-key permissions is denied.
- [ ] Test user-owned and org-owned keys are separated when listing.
- [ ] Test organization-owned API key verification succeeds.
- [ ] Test admin role with API-key CRUD can create/read/update/delete.
- [ ] Test read-only member can list/get but not create/update/delete.
- [ ] Test restricted role is denied all API-key operations.
- [ ] Test missing organization plugin returns server error.
- [ ] Test wrong config ID cannot access org key.
- [ ] Test organization-owned create requires organization ID.
- [ ] Test organization-owned list can filter by config ID.
- [ ] Test organization-owned keys cannot mock sessions.
- [ ] Test user-owned keys can mock sessions when enabled.
- [ ] Test mixed user/org keys can both verify under their own configs.
- [ ] Test get org-owned key by ID.
- [ ] Test delete org-owned key invalidates verification.
- [ ] Test update org-owned key.

## Implementation Order Recommendation

- [ ] Data model, error catalog, and configuration defaults.
- [ ] Database schema/storage behavior.
- [ ] Key generation, hashing, and response redaction.
- [ ] Create/get/list/update/delete endpoints for user-owned database keys.
- [ ] Verification, rate limit, remaining quota, refill, and expiration cleanup.
- [ ] Metadata and permissions.
- [ ] Secondary storage.
- [ ] Database fallback mode.
- [ ] Deferred updates.
- [ ] Multiple configurations.
- [ ] API-key session hook.
- [ ] Organization-owned keys and role permissions.
- [ ] Full behavior test suite grouped by the sections above.

## Optional Improvements Over Upstream

- [ ] Whitelist allowed `sort_by` fields instead of accepting arbitrary field strings.
- [ ] Use typed permissions storage rather than exposing a JSON-string storage detail outside the persistence layer.
- [ ] Use an injected clock for expiration, cleanup throttle, rate limits, and refill tests.
- [ ] Avoid hidden mutable global cleanup state; store cleanup throttle state in plugin/application state.
- [ ] Validate custom key generator output before storage, including minimum entropy/length and expected prefix behavior.
- [ ] Treat `disable_key_hashing` as an explicitly unsafe configuration with clear docs and test coverage.
- [ ] Use best-effort transactional semantics or compensation for database-plus-secondary-storage fallback writes.
- [ ] Add structured telemetry/log fields for deferred update failures, cleanup failures, and metadata migration failures.
- [ ] Keep organization support behind an optional feature/integration boundary.
- [ ] Ensure all key redaction is enforced by response types, not only by handler conventions.

## Self-Review

- [ ] Server-side upstream files were covered.
- [ ] Browser/client SDK implementation was excluded.
- [ ] TypeScript package/build-only files were excluded.
- [ ] Upstream imports/dependencies were reviewed for hidden behavior.
- [ ] Endpoint builder, schema validation, and OpenAPI contract expectations were represented.
- [ ] Modular file boundaries were represented.
- [ ] Each upstream route has a checklist section.
- [ ] Storage, metadata migration, multiple config, organization, deferred updates, and tests are represented.
- [ ] No current OpenAuth implementation status was marked; this is a reusable upstream-derived plan only.
