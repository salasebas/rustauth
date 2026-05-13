# Redis Storage Upstream Checklist Implementation Plan

> **Guide note:** This checklist is a planning guide, not a limit on implementation. If OpenAuth adds behavior that covers the same upstream requirement more correctly, more securely, or more idiomatically in Rust, mark the item complete and document the stronger behavior.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Track the server-side Better Auth `@better-auth/redis-storage` package surface so OpenAuth can port the Redis-backed secondary storage behavior intentionally.

**Architecture:** Redis storage is an optional secondary-storage adapter, not core browser/client behavior. It should expose a Rust-native adapter around a Redis client/pool while satisfying the OpenAuth secondary-storage contract used by sessions, verification flows, rate limiting, and server plugins.

**Tech Stack:** Rust, async Redis client, OpenAuth secondary-storage trait, typed errors, Redis integration tests.

---

## Upstream Scope

Source package reviewed:

- `upstream/better-auth/1.6.9/repository/packages/redis-storage/src/redis-storage.ts`
- `upstream/better-auth/1.6.9/repository/packages/redis-storage/src/index.ts`
- `upstream/better-auth/1.6.9/repository/packages/redis-storage/package.json`
- `upstream/better-auth/1.6.9/repository/packages/redis-storage/README.md`
- `upstream/better-auth/1.6.9/repository/packages/redis-storage/CHANGELOG.md`

Relevant upstream contract and usage points:

- `upstream/better-auth/1.6.9/repository/packages/core/src/db/type.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/db/internal-adapter.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/db/internal-adapter.test.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/db/secondary-storage.test.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/api/rate-limiter/index.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/api/rate-limiter/rate-limiter.test.ts`
- `upstream/better-auth/1.6.9/repository/packages/core/src/db/get-tables.ts`
- `upstream/better-auth/1.6.9/repository/packages/core/src/db/test/get-tables.test.ts`
- `upstream/better-auth/1.6.9/repository/packages/api-key/src/adapter.ts`
- `upstream/better-auth/1.6.9/repository/packages/api-key/src/routes/*`
- `upstream/better-auth/1.6.9/repository/packages/oauth-provider/src/oauth.ts`
- `upstream/better-auth/1.6.9/repository/packages/sso/src/types.ts`
- `upstream/better-auth/1.6.9/repository/packages/sso/src/domain-verification.test.ts`
- `upstream/better-auth/1.6.9/repository/packages/sso/src/routes/*`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/device-authorization/routes.ts`

Out of scope for this package checklist:

- Browser-only code.
- TypeScript packaging mechanics such as `tsdown`, `publint`, and `attw`, except as reference for public export shape.
- Implementing session, verification, rate-limit, API key, OAuth provider, SSO, or device-authorization logic inside the Redis adapter. Those features consume the secondary-storage contract; this package only provides the Redis implementation.
- Defining HTTP endpoints or OpenAPI metadata inside Redis storage. Upstream `redis-storage` has no routes and does not call `createAuthEndpoint`; route/OpenAPI behavior belongs to consumers such as API key, SSO, and device authorization.

## Upstream Package Inventory

- [ ] Package identity: `@better-auth/redis-storage`.
- [ ] Package purpose: Redis storage for Better Auth secondary storage.
- [ ] Public entrypoint exports `RedisStorageConfig`.
- [ ] Public entrypoint exports `redisStorage`.
- [ ] README states the package is for Redis-backed session caching and rate limiting.
- [ ] Changelog contains only dependency-version updates from `1.6.0-beta.0` through `1.6.9`; no package-specific behavior changes are listed.
- [ ] No upstream test file exists inside `packages/redis-storage`; required behavior must be inferred from the adapter implementation plus shared secondary-storage tests.
- [ ] Package-local source is intentionally small: `src/index.ts` re-exports and `src/redis-storage.ts` owns config plus implementation.

## Suggested Rust Modularization Checklist

Use this as a starting structure when the adapter is implemented. Adjust paths to the final crate/feature layout.

- [ ] Public crate or feature module is separate from core so Redis remains optional.
- [ ] `src/lib.rs` owns public re-exports only.
- [ ] `src/config.rs` owns `RedisStorageConfig`-equivalent types and defaults.
- [ ] `src/storage.rs` owns the Redis storage implementation and prefix helper.
- [ ] `src/error.rs` owns Redis adapter errors and conversions from the chosen Redis client error type.
- [ ] `tests/redis_storage.rs` covers package-level Redis adapter behavior.
- [ ] `tests/secondary_storage_compat.rs` covers OpenAuth secondary-storage compatibility if the crate can spin up a full auth test harness.
- [ ] Test helpers isolate Redis key prefixes per test.
- [ ] Documentation examples live close to the crate or feature module, not in core-only docs.

## Public API Checklist

- [ ] Provide a Redis storage constructor equivalent to upstream `redisStorage(config)`.
- [ ] Accept a Redis client or connection handle through config.
- [ ] Accept an optional `key_prefix` through config.
- [ ] Default `key_prefix` to `better-auth:`.
- [ ] Return an object/type that satisfies the OpenAuth secondary-storage contract.
- [ ] Expose package-specific utility methods equivalent to upstream `listKeys`.
- [ ] Expose package-specific utility methods equivalent to upstream `clear`.
- [ ] Keep the public API server-side only.
- [ ] Keep the API Rust-native; do not expose TypeScript-shaped names unless the Rust crate already uses them intentionally.

## Secondary Storage Contract Checklist

- [ ] `get(key)` exists.
- [ ] `get(key)` prefixes the key before querying Redis.
- [ ] `get(key)` uses Redis `GET`.
- [ ] `get(key)` returns the stored string value when the key exists.
- [ ] `get(key)` returns no value when the key does not exist.
- [ ] `set(key, value, ttl)` exists.
- [ ] `set(key, value, ttl)` prefixes the key before writing Redis.
- [ ] `set(key, value, ttl)` stores string values without modifying JSON content.
- [ ] `set(key, value, ttl)` uses Redis `SETEX` when `ttl` is present and greater than zero.
- [ ] `set(key, value, ttl)` treats `ttl` as seconds.
- [ ] TTL values derived from timestamps use floor semantics, matching upstream `Math.floor`.
- [ ] TTL values derived from timestamps are clamped to zero before deciding whether to write with expiration.
- [ ] `set(key, value, ttl)` uses Redis `SET` when `ttl` is absent.
- [ ] `set(key, value, ttl)` uses Redis `SET` when `ttl` is zero.
- [ ] `set(key, value, ttl)` uses Redis `SET` when `ttl` is negative, if the Rust API can represent negative values.
- [ ] `delete(key)` exists.
- [ ] `delete(key)` prefixes the key before deleting Redis data.
- [ ] `delete(key)` uses Redis `DEL`.
- [ ] Redis command failures are propagated as typed Rust errors.
- [ ] Production code does not panic on Redis command errors.
- [ ] Production code does not use `unwrap()` or `expect()`.

## Redis Key Prefix Checklist

- [ ] Prefixing is centralized in one helper.
- [ ] The default prefix is exactly `better-auth:`.
- [ ] Custom prefixes are supported.
- [ ] Empty custom prefixes are either supported intentionally or rejected with a typed validation error; choose this explicitly during implementation.
- [ ] Two storage instances with different prefixes do not read each other's keys.
- [ ] Prefix stripping for list operations removes only the configured prefix from the start of matching keys.
- [ ] Prefix stripping does not remove matching text from the middle of a key.
- [ ] Prefixes containing Redis glob metacharacters such as `*`, `?`, `[`, or `]` are either rejected or escaped before pattern-based listing/clearing; upstream does not guard this.

## Utility Methods Checklist

- [ ] `list_keys()` exists as an adapter-specific utility.
- [ ] `list_keys()` queries only keys matching `${key_prefix}*`.
- [ ] `list_keys()` strips `key_prefix` from returned keys.
- [ ] `list_keys()` returns an empty list when there are no matching keys.
- [ ] `list_keys()` does not include keys outside the configured prefix.
- [ ] `clear()` exists as an adapter-specific utility.
- [ ] `clear()` queries only keys matching `${key_prefix}*`.
- [ ] `clear()` deletes only keys under the configured prefix.
- [ ] `clear()` is a no-op when there are no matching keys.
- [ ] `clear()` does not delete keys outside the configured prefix.
- [ ] Document that upstream uses Redis `KEYS`, which is simple but can block on large production keyspaces.
- [ ] Decide during implementation whether OpenAuth preserves `KEYS` exactly or offers a safer `SCAN`-based implementation while keeping the same observable result.
- [ ] If preserving upstream `KEYS`, document that it is intended for development/admin use or small keyspaces.
- [ ] If using `SCAN`, preserve the same final observable behavior: all matching prefixed keys are returned or cleared.
- [ ] Guard `clear()` against empty match sets before issuing `DEL`; upstream spreads an empty array into `client.del(...keys)`, which is a behavior worth improving in Rust.

## Dependency-Driven Functionality

| Upstream functionality | Upstream dependency | Rust equivalent to evaluate before implementation |
| --- | --- | --- |
| Redis client instance | `ioredis` peer dependency `^5.0.0` | `redis` crate with async Tokio support, `fred`, or a pooled wrapper such as `deadpool-redis`/`bb8-redis` |
| Redis `GET` | `ioredis.get` | Redis async command API |
| Redis `SET` | `ioredis.set` | Redis async command API |
| Redis `SETEX` with seconds TTL | `ioredis.setex` | Redis async command API with seconds-based expiry |
| Redis `DEL` | `ioredis.del` | Redis async command API |
| Redis `KEYS` by prefix pattern | `ioredis.keys` | Redis async command API; consider `SCAN` if production-safety is preferred |
| Async interface | JavaScript promises | Rust `async fn` trait methods or boxed futures, depending on the existing OpenAuth trait style |
| Integration testing against Redis | `vitest` listed, no package-local tests | `testcontainers`/`testcontainers-modules` with Redis, or an explicit local Redis test profile |
| External connection configuration | User-created `ioredis` client | Accept a user-created Redis client/pool/manager; do not force host/port-only config if the chosen crate supports richer setup |
| TLS/authentication/cluster/sentinel support | Delegated to `ioredis` client setup outside this package | Delegate to the chosen Redis client/pool type where possible; avoid baking every Redis deployment mode into OpenAuth config |

Dependency notes:

- [ ] Propose any new runtime Redis dependency before adding it.
- [ ] Prefer an actively maintained async Redis crate compatible with Tokio.
- [ ] If pooling is needed, keep pooling behind OpenAuth-owned config/types so the public API remains stable.
- [ ] Keep Redis as an optional feature or separate crate so core authentication does not require Redis.
- [ ] Keep test-only Redis container dependencies as dev-dependencies.

## Server Integration Compatibility Checklist

These items are not implemented inside the Redis adapter, but Redis storage must behave correctly when these server features consume the secondary-storage contract.

- [ ] Session creation can store the session payload by session token.
- [ ] Session payload shape supports `{ session, user }`.
- [ ] Session creation can store `active-sessions-{user_id}` lists.
- [ ] Active-session list shape supports `{ token, expiresAt }[]`, where `expiresAt` is milliseconds since epoch.
- [ ] Active-session list TTL is set to the furthest active session expiration.
- [ ] Session-token TTL is set to the session expiration.
- [ ] Expired sessions are filtered from active-session lists.
- [ ] Duplicate session tokens in active-session lists are deduplicated by session-list behavior.
- [ ] `get-session` can read Redis-backed session payloads.
- [ ] `list-sessions` can read Redis-backed active-session lists.
- [ ] `list-sessions` skips missing session-token keys without discarding valid sessions.
- [ ] `list-sessions` skips corrupt/unparseable session payloads without discarding valid sessions.
- [ ] `list-sessions` returns an empty list when all referenced session payloads are missing or corrupt.
- [ ] `find-sessions` skips corrupt/unparseable session payloads without discarding valid sessions.
- [ ] `update-session` updates the session-token payload.
- [ ] `update-session` updates the active-session list TTL when session expiration changes.
- [ ] `revoke-session` deletes the session token key.
- [ ] `revoke-session` updates or deletes the `active-sessions-{user_id}` key.
- [ ] `revoke-sessions` and `revoke-other-sessions` remove the expected Redis-backed sessions.
- [ ] Secondary storage can coexist with `session.storeSessionInDatabase: true`.
- [ ] Revoked sessions are not accepted after Redis deletion, even when preserved in database.
- [ ] Verification storage can use keys shaped as `verification:{identifier}`.
- [ ] Verification storage supports processed identifiers when upstream-equivalent identifier storage hashes/encrypts identifiers.
- [ ] Verification lookup falls back from processed identifier to plain identifier when the configured identifier storage is not plain.
- [ ] Verification values are written with TTL derived from `expiresAt`.
- [ ] Verification updates rewrite the Redis value with a fresh TTL derived from the updated `expiresAt`.
- [ ] Verification deletion deletes `verification:{processed_identifier}`.
- [ ] Verification table/schema can be omitted when secondary storage is configured and verification storage is not forced into the database.
- [ ] Verification table/schema remains available when `verification.storeInDatabase` is enabled.
- [ ] Rate limiter can read a JSON rate-limit value from secondary storage.
- [ ] Rate limiter can write a JSON rate-limit value with TTL equal to the rate-limit window.
- [ ] Rate-limit keys can contain pipe-separated IP/path values such as `127.0.0.1|/sign-in/email`.
- [ ] Rate-limit storage ignores query params because the consumer keying does.
- [ ] API key plugin custom storage remains separate from global secondary storage.
- [ ] API key plugin can use global secondary storage as fallback when configured.
- [ ] API key storage can use keys shaped as `api-key:{hashed_key}`.
- [ ] API key storage can use keys shaped as `api-key:by-id:{id}`.
- [ ] API key storage can use keys shaped as `api-key:by-ref:{reference_id}`.
- [ ] API key storage can write expiring keys when an API key has `expiresAt`.
- [ ] API key fallback-to-database mode invalidates the reference list instead of read-modify-writing it.
- [ ] OAuth provider validates that `session.storeSessionInDatabase: true` is set when secondary storage is configured.
- [ ] SSO domain-verification flows can use secondary storage when not stored in database.
- [ ] SSO SAML InResponseTo validation can use secondary storage when configured.
- [ ] Device authorization flows can store temporary user-code/device-code state with TTL.

## Endpoint And OpenAPI Checklist

- [ ] Redis storage itself defines no endpoints.
- [ ] Redis storage itself does not use `createAuthEndpoint`.
- [ ] Redis storage itself defines no OpenAPI metadata.
- [ ] Consumers that use Redis-backed secondary storage and expose routes still define their endpoints through their own endpoint builders.
- [ ] API key routes remain responsible for `createAuthEndpoint` and OpenAPI metadata.
- [ ] SSO routes remain responsible for `createAuthEndpoint` and OpenAPI metadata.
- [ ] Device authorization routes remain responsible for `createAuthEndpoint` and OpenAPI metadata.
- [ ] Redis storage documentation should link conceptually to secondary storage, not claim ownership of route contracts.

## Test Checklist

Package-level Redis adapter tests:

- [ ] Constructor uses default prefix `better-auth:`.
- [ ] Constructor accepts a custom prefix.
- [ ] `get` reads a prefixed key.
- [ ] `get` returns none for a missing key.
- [ ] `set` without TTL stores a string value.
- [ ] `set` with `ttl > 0` stores a string value with Redis expiration.
- [ ] `set` with timestamp-derived TTL uses floor semantics.
- [ ] `set` with `ttl = 0` stores a string value without Redis expiration.
- [ ] `delete` removes only the prefixed key.
- [ ] `list_keys` returns unprefixed keys for the configured prefix.
- [ ] `list_keys` excludes keys from other prefixes.
- [ ] `clear` deletes only keys from the configured prefix.
- [ ] `clear` succeeds when no keys match.
- [ ] Redis command errors are surfaced through the adapter error type.

Secondary-storage compatibility tests:

- [ ] End-to-end session flow works when `get` returns JSON strings.
- [ ] End-to-end session flow works when the broader secondary-storage contract permits already-parsed values, if OpenAuth keeps that flexibility.
- [ ] Session revocation removes Redis-backed session data.
- [ ] Session revocation removes or updates the Redis-backed active-session list.
- [ ] Session revocation rejects preserved database sessions after Redis deletion.
- [ ] Session listing skips missing sessions.
- [ ] Session listing skips malformed JSON with valid sessions still returned.
- [ ] Session listing skips structurally invalid JSON with valid sessions still returned.
- [ ] Session listing deduplicates duplicate active-session tokens.
- [ ] Session update refreshes both session payload and active-session list.
- [ ] Rate limiting writes values with TTL.
- [ ] Rate limiting reads values back from Redis.
- [ ] Verification storage writes and reads Redis-backed verification entries.
- [ ] Verification storage deletes Redis-backed verification entries.
- [ ] Verification storage sets TTL based on `expiresAt`.
- [ ] Verification storage can fall back to database when `storeInDatabase` is enabled and Redis misses.
- [ ] Verification reads revive date fields if the broader secondary-storage contract accepts pre-parsed objects.
- [ ] Verification schema/table exclusion behavior is covered in core tests when secondary storage is configured.

Operational tests:

- [ ] Redis integration tests can run against an isolated Redis instance.
- [ ] Redis integration tests clean their prefix after each test.
- [ ] Tests do not require a developer's shared local Redis data.
- [ ] Tests document how to run Redis-backed integration coverage.

## Documentation Checklist

- [ ] Document the Redis storage crate/package purpose.
- [ ] Document the constructor/configuration type.
- [ ] Document the default key prefix.
- [ ] Document the TTL unit as seconds.
- [ ] Document that values are stored as strings.
- [ ] Document that JSON serialization is handled by upstream/core consumers, not by the Redis adapter.
- [ ] Document the optional utility methods `list_keys()` and `clear()`.
- [ ] Document operational cautions around `KEYS` or the chosen `SCAN` implementation.
- [ ] Provide a server-side usage example showing Redis storage wired as secondary storage.
- [ ] Do not include browser/client SDK examples.

## Completion Definition

- [ ] Redis storage is available as an optional server-side OpenAuth adapter.
- [ ] The adapter implements the OpenAuth secondary-storage contract.
- [ ] Prefixing, TTL, deletion, listing, and clearing match the upstream package's observable behavior.
- [ ] Redis-specific command errors are typed and propagated.
- [ ] Unit/integration tests cover Redis adapter behavior.
- [ ] Core compatibility tests cover sessions, verification storage, rate limiting, and relevant plugin consumers.
- [ ] Documentation explains dependencies, configuration, TTL behavior, and operational caveats.
