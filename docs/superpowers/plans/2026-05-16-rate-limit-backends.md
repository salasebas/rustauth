# Rate Limit Backends Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild OpenAuth rate limiting around atomic storage decisions, fast local Tokio-backed limiting, SQLx distributed limiting, Redis distributed limiting, and optional hybrid local+distributed protection.

**Architecture:** Keep route/rule resolution in `openauth-core`, but replace the current `get`/`set` storage contract with an atomic async consume API. Local memory uses `tokio-rate-limit`; SQLx and Redis live outside core so core does not depend on SQLx or Redis. Distributed backends are authoritative for multi-instance deployments, and hybrid mode adds a local prefilter before the distributed backend.

**Tech Stack:** Rust 2021, Tokio, `tokio-rate-limit 0.8`, existing SQLx adapters, Redis `0.32` in a new integration crate, Better Auth upstream parity for rule semantics.

**Plan file target:** `docs/superpowers/plans/2026-05-16-rate-limit-backends.md`. In Plan Mode this was not written to disk; first execution step must save this plan there.

---

## Summary

The current rate limiter works for one process, but `Database` and `SecondaryStorage` are not real backends yet; without `custom_storage`, they are rejected during context creation. This plan makes rate limiting production-grade by making every real backend atomic and async.

Upstream Better Auth defaults to memory, switches to secondary storage when `secondaryStorage` exists, supports database storage, and supports custom storage, but still uses `get`/`set`. OpenAuth should intentionally improve on that by using an atomic `check_and_increment`/`consume` operation.

References: [tokio-rate-limit docs](https://docs.rs/tokio-rate-limit/latest/tokio_rate_limit/), [tokio-rate-limit Cargo features](https://docs.rs/crate/tokio-rate-limit/latest/source/Cargo.toml), upstream Better Auth rate limiter at `upstream/better-auth/1.6.9/repository/packages/better-auth/src/api/rate-limiter/index.ts`, upstream Redis storage at `upstream/better-auth/1.6.9/repository/packages/redis-storage/src/redis-storage.ts`.

## Key Changes

- Add `tokio-rate-limit = "0.8"` to workspace dependencies with default features disabled, and use it only for local in-process async limiting.
- Replace the public `RateLimitStorage` `get`/`set` contract with an atomic async store contract:
  - Input: normalized key, `RateLimitRule`, current timestamp.
  - Output: `RateLimitDecision { permitted, retry_after, limit, remaining, reset_after }`.
  - Keep a compatibility adapter for old `custom_storage` only if needed, but mark it non-atomic and not recommended for distributed production.
- Change router rate limiting to consume before endpoint execution in `handler_async`.
  - `handler_async` becomes the production path for all distributed backends.
  - `handler` returns a clear error if rate limiting is enabled with an async-only backend; tests should keep sync memory behavior only if a synchronous fallback remains simple.
- Keep OpenAuth's route-aware rule resolution:
  - default `window/max`;
  - Better Auth special rules for sign-in/sign-up/change-password/change-email/password reset/email verification;
  - plugin rules;
  - custom rules;
  - dynamic request-aware rules;
  - IP normalization and `ip|path` keying.
- Add real backend resolution:
  - `Memory`: Tokio local backend.
  - `Database`: SQLx atomic backend, only when the app is initialized with a SQLx rate limit store.
  - `SecondaryStorage`: Redis atomic backend or another explicit atomic secondary store.
  - `Hybrid`: optional local Tokio prefilter followed by SQLx/Redis authoritative backend.

## Implementation Tasks

### Task 1: Save The Plan

**Files:**
- Create: `docs/superpowers/plans/2026-05-16-rate-limit-backends.md`

- [ ] Save this plan exactly to `docs/superpowers/plans/2026-05-16-rate-limit-backends.md`.
- [ ] Commit:
  ```bash
  git add docs/superpowers/plans/2026-05-16-rate-limit-backends.md
  git commit -m "docs: plan atomic rate limit backends"
  ```

### Task 2: Introduce Atomic Core Rate Limit Types

**Files:**
- Modify: `Cargo.toml`
- Modify: `crates/openauth-core/Cargo.toml`
- Modify: `crates/openauth-core/src/options/rate_limit.rs`
- Modify: `crates/openauth-core/src/rate_limit.rs`
- Test: `crates/openauth-core/tests/rate_limit/rate_limiter.rs`

- [ ] Add workspace dependency:
  ```toml
  tokio-rate-limit = { version = "0.8", default-features = false }
  ```
- [ ] Add `tokio-rate-limit.workspace = true` to `openauth-core`.
- [ ] Replace `RateLimitStorage` with an async atomic store trait using the repo's boxed-future style:
  ```rust
  pub type RateLimitFuture<'a> =
      Pin<Box<dyn Future<Output = Result<RateLimitDecision, OpenAuthError>> + Send + 'a>>;

  pub trait RateLimitStore: Send + Sync + 'static {
      fn consume<'a>(
          &'a self,
          input: RateLimitConsumeInput,
      ) -> RateLimitFuture<'a>;
  }
  ```
- [ ] Add:
  ```rust
  pub struct RateLimitConsumeInput {
      pub key: String,
      pub rule: RateLimitRule,
      pub now_ms: i64,
  }

  pub struct RateLimitDecision {
      pub permitted: bool,
      pub retry_after: u64,
      pub limit: u64,
      pub remaining: u64,
      pub reset_after: u64,
  }
  ```
- [ ] Use milliseconds internally for new stores; preserve serialized `RateLimitRecord` field names for schema compatibility.
- [ ] Update tests to assert the new decision object and atomic single-call storage behavior.

### Task 3: Use Tokio Local Memory Backend

**Files:**
- Modify: `crates/openauth-core/src/rate_limit.rs`
- Modify: `crates/openauth-core/src/context.rs`
- Modify: `crates/openauth-core/src/context/builder.rs`
- Test: `crates/openauth-core/tests/rate_limit/rate_limiter.rs`

- [ ] Replace the default memory backend used by async routing with a `TokioMemoryRateLimitStore`.
- [ ] Implement it as a cache of `tokio_rate_limit::RateLimiter` instances keyed by `(window, max)`, because OpenAuth supports different rules per path/plugin.
- [ ] Configure each limiter as:
  - `requests_per_second = max / window`, rounded up to at least `1`;
  - `burst = max`;
  - request key remains `normalized_ip|normalized_path`.
- [ ] Map `tokio-rate-limit` decisions to `RateLimitDecision`.
- [ ] Keep rule resolution unchanged.
- [ ] Add tests:
  - sign-in special rule still denies the 4th request;
  - custom wildcard rule still wins;
  - dynamic rule still wins;
  - different IPs remain isolated;
  - async handler uses Tokio backend.

### Task 4: Make Router Rate Limiting Async And Atomic

**Files:**
- Modify: `crates/openauth-core/src/api/router.rs`
- Modify: `crates/openauth-core/src/rate_limit.rs`
- Test: `crates/openauth-core/tests/api/main.rs`
- Test: `crates/openauth-core/tests/rate_limit/rate_limiter.rs`

- [ ] Replace the current `on_request_rate_limit` + `on_response_rate_limit` split with one async `consume_rate_limit`.
- [ ] In `handle_async`, call `consume_rate_limit` before endpoint middleware reaches the endpoint handler.
- [ ] Remove response-time counter increments for async routing.
- [ ] Keep disabled paths from touching rate limit storage.
- [ ] If `handler()` cannot support the configured backend, return `OpenAuthError::Api("async rate limit storage requires AuthRouter::handle_async")`.
- [ ] Add tests for:
  - denied request does not call endpoint handler;
  - disabled path does not consume a token;
  - sync handler error is explicit for async-only backend;
  - async sync-endpoint execution still rate-limits correctly.

### Task 5: Implement SQLx Atomic Backends

**Files:**
- Modify: `crates/openauth-sqlx/src/lib.rs`
- Modify: `crates/openauth-sqlx/src/sqlite/mod.rs`
- Modify: `crates/openauth-sqlx/src/postgres/mod.rs`
- Modify: `crates/openauth-sqlx/src/mysql/mod.rs`
- Test: `crates/openauth-sqlx/tests/sqlite_adapter.rs`
- Test: `crates/openauth-sqlx/tests/postgres_adapter.rs`
- Test: `crates/openauth-sqlx/tests/mysql_adapter.rs`

- [ ] Add `SqliteRateLimitStore`, `PostgresRateLimitStore`, and `MySqlRateLimitStore`.
- [ ] Do not add SQLx to `openauth-core`; stores live entirely in `openauth-sqlx`.
- [ ] Use existing `rate_limits` table shape: `key`, `count`, `last_request`.
- [ ] Implement one atomic consume operation per database:
  - reset count to `1` when `now_ms - last_request > window_ms`;
  - increment only when current count is below `max`;
  - do not increment denied requests;
  - return retry metadata from stored `last_request`.
- [ ] Use native SQL per backend:
  - SQLite: transaction plus upsert/update returning behavior compatible with SQLite support.
  - Postgres: `INSERT ... ON CONFLICT ... DO UPDATE ... RETURNING`.
  - MySQL: transaction with row lock or atomic upsert equivalent.
- [ ] Add tests that simulate two concurrent requests against `max = 1`; exactly one must pass.
- [ ] Add tests that verify the SQLx backend works through `OpenAuth::handler_async`.

### Task 6: Add Redis Atomic Backend

**Files:**
- Modify: root `Cargo.toml`
- Create: `crates/openauth-redis/Cargo.toml`
- Create: `crates/openauth-redis/src/lib.rs`
- Test: `crates/openauth-redis/tests/redis_rate_limit.rs`

- [ ] Add workspace member `crates/openauth-redis`.
- [ ] Add dependency only in this crate:
  ```toml
  redis = { version = "0.32", default-features = false, features = ["tokio-comp", "connection-manager"] }
  ```
- [ ] Implement `RedisRateLimitStore`.
- [ ] Use a Redis Lua script for atomic consume:
  - read `count` and `last_request`;
  - reset expired buckets;
  - increment only when allowed;
  - preserve denied bucket state;
  - set `PEXPIRE` to `window_ms`.
- [ ] Use key prefix `openauth:` by default, configurable as `RedisRateLimitOptions { key_prefix }`.
- [ ] Add Redis tests gated behind an env var such as `OPENAUTH_REDIS_URL`; skip cleanly when not set.
- [ ] Add one test for atomic concurrency with `max = 1`.

### Task 7: Add Hybrid Local + Distributed Mode

**Files:**
- Modify: `crates/openauth-core/src/options/rate_limit.rs`
- Modify: `crates/openauth-core/src/rate_limit.rs`
- Test: `crates/openauth-core/tests/rate_limit/rate_limiter.rs`

- [ ] Add:
  ```rust
  pub struct HybridRateLimitOptions {
      pub enabled: bool,
      pub local_multiplier: u64,
  }
  ```
- [ ] Add `hybrid: HybridRateLimitOptions` to `RateLimitOptions`, default disabled.
- [ ] Implement `HybridRateLimitStore`:
  - local Tokio store runs first as a prefilter;
  - distributed store runs second and remains authoritative;
  - if local denies, return local denial;
  - if global denies, return global denial.
- [ ] Default `local_multiplier = 2`, meaning the local prefilter allows twice the global rule before denying, reducing false local denials while still shedding bursts.
- [ ] Add tests:
  - local denial stops before global store is called;
  - global denial is returned when local permits;
  - hybrid disabled preserves direct distributed behavior.

### Task 8: Update Public Initialization And Docs

**Files:**
- Modify: `crates/openauth/src/lib.rs`
- Modify: `crates/openauth-core/src/options/rate_limit.rs`
- Modify: `README.md`
- Test: `crates/openauth/tests/public_api.rs`

- [ ] Re-export new decision/store/input types from `openauth`.
- [ ] Document recommended modes:
  - local/dev/single instance: `Memory` using Tokio backend;
  - multi-instance with existing SQL DB: SQLx store;
  - high-throughput multi-instance: Redis store;
  - very high traffic: Redis or SQLx plus hybrid local prefilter.
- [ ] Document that non-atomic custom storage is not safe for distributed enforcement unless the implementation's `consume` method is atomic.
- [ ] Add public API tests for new reexports and initialization with each backend type.

### Task 9: Remove Or Deprecate Legacy `get`/`set` Behavior

**Files:**
- Modify: `crates/openauth-core/src/options/rate_limit.rs`
- Modify: `crates/openauth-core/src/rate_limit.rs`
- Test: `crates/openauth-core/tests/context/runtime.rs`

- [ ] If backward compatibility is required, keep legacy `RateLimitStorage` behind `LegacyRateLimitStorageAdapter`.
- [ ] Mark it as non-distributed-safe in docs and debug output.
- [ ] Prefer new `custom_store: Option<Arc<dyn RateLimitStore>>`.
- [ ] Keep `storage: RateLimitStorageOption` for user intent, but make backend availability explicit:
  - `Memory` always available;
  - `Database` requires a concrete SQLx store or future DbAdapter-backed store;
  - `SecondaryStorage` requires a concrete Redis/secondary atomic store.
- [ ] Add config tests that reject `Database` and `SecondaryStorage` without a concrete store.

## Test Plan

- Run focused core tests:
  ```bash
  cargo test -p openauth-core rate_limit
  cargo test -p openauth-core --test api
  ```
- Run SQLx backend tests:
  ```bash
  cargo test -p openauth-sqlx --all-features
  ```
- Run Redis tests only when Redis is available:
  ```bash
  OPENAUTH_REDIS_URL=redis://127.0.0.1:6379 cargo test -p openauth-redis
  ```
- Run full workspace:
  ```bash
  cargo test --workspace --all-features
  cargo clippy --workspace --all-targets --all-features
  cargo fmt --check
  ```
- Acceptance criteria:
  - default memory rate limiting still works;
  - distributed SQLx and Redis stores enforce limits across concurrent calls;
  - denied requests do not increment counters;
  - hybrid mode never replaces the distributed decision as authority;
  - core has no SQLx or Redis dependency;
  - Better Auth route-specific rules still behave as before.

## Assumptions And Defaults

- Use `tokio-rate-limit` as a dependency, not copied source.
- Do not make Axum part of this work; `tokio-rate-limit` is used through its core API, not its Axum middleware feature.
- Do not add SQLx to `openauth-core`; SQLx stores live in `openauth-sqlx`.
- Add Redis as a separate `openauth-redis` crate so users only compile Redis support when they opt in.
- Use milliseconds for new rate limit timing because upstream Better Auth stores `lastRequest` in milliseconds.
- Prefer async `handler_async` for production; sync `handler` must fail clearly when the configured backend cannot be used synchronously.
- Hybrid mode is opt-in, not default, because local prefilters can deny on one instance even when global capacity remains.
