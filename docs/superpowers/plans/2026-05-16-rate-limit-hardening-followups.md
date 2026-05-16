# Rate Limit Hardening Followups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden the atomic rate limit backend implementation by fixing schema derivation, SQLx physical column support, Redis concurrency, memory backend timing metadata, memory key eviction, and module size.

**Architecture:** Keep the public atomic `RateLimitStore` contract unchanged. Tighten backend implementations behind the existing API: core derives the database schema from rate limit options, SQLx stores carry resolved physical names, Redis no longer serializes all calls through a mutex, and memory limiting gets safer retry metadata and key eviction.

**Tech Stack:** Rust 2021, Tokio, `tokio-rate-limit 0.8`, SQLx, Redis `0.32`, existing OpenAuth core options/builders/tests.

---

## Findings

- `OpenAuth::create_schema()` currently builds `auth_schema(Default::default())`, so database rate limiting does not automatically add the `rate_limits` table.
- SQLx rate limit stores resolve the custom physical table name but still hard-code `key`, `count`, and `last_request` columns.
- `RedisRateLimitStore` wraps `ConnectionManager` in `Arc<Mutex<_>>`, serializing all consume calls.
- Tokio memory backend maps `Duration` to seconds with truncation, allowing `Retry-After: 0` for subsecond denial windows.
- Tokio memory backend uses `TokenBucket::new`, which does not evict idle keys.
- Core rate-limit and public API tests are growing large enough to justify later modularization.

## Task 1: Derive Rate Limit Schema From Options

**Files:**
- Modify: `crates/openauth-core/src/context/builder.rs`
- Test: `crates/openauth/tests/public_api.rs`

- [x] Derive `AuthSchemaOptions.rate_limit_storage` from `OpenAuthOptions.rate_limit.storage`.
- [x] Add a public API test that builds `OpenAuth` with `RateLimitOptions::database(...)`, calls `create_schema(None)`, and verifies the schema includes the rate limit table.
- [x] Run `cargo test -p openauth --test public_api`.
- [ ] Commit: `fix(core): include rate limit table for database store`.

## Task 2: Respect SQLx Physical Rate Limit Columns

**Files:**
- Modify: `crates/openauth-sqlx/src/lib.rs`
- Modify: `crates/openauth-sqlx/src/sqlite/mod.rs`
- Modify: `crates/openauth-sqlx/src/postgres/mod.rs`
- Modify: `crates/openauth-sqlx/src/mysql/mod.rs`
- Test: `crates/openauth-sqlx/tests/sqlite_adapter.rs`
- Test: `crates/openauth-sqlx/tests/postgres_adapter.rs`
- Test: `crates/openauth-sqlx/tests/mysql_adapter.rs`

- [x] Add a small `RateLimitSqlNames` helper that stores quoted table, key, count, and last_request names.
- [x] Build `RateLimitSqlNames` from each adapter's `DbSchema` in `From<&Adapter>`.
- [x] Update SQL statements to use resolved physical column names.
- [x] Add custom physical column tests for SQLite, Postgres, and MySQL.
- [x] Run `cargo test -p openauth-sqlx --all-features`.
- [ ] Commit: `fix(sqlx): honor rate limit physical columns`.

## Task 3: Remove Redis Per-Store Mutex

**Files:**
- Modify: `crates/openauth-redis/src/lib.rs`
- Test: `crates/openauth-redis/tests/redis_rate_limit.rs`

- [x] Store `ConnectionManager` directly instead of `Arc<Mutex<ConnectionManager>>`.
- [x] Clone the manager per consume call before invoking the Lua script.
- [x] Keep Lua script as the only atomicity mechanism.
- [x] Add or update the concurrent test so calls share one store but are not serialized by a store mutex.
- [x] Run `cargo test -p openauth-redis`.
- [ ] Commit: `perf(redis): avoid serializing rate limit consumes`.

## Task 4: Fix Tokio Memory Retry Metadata

**Files:**
- Modify: `crates/openauth-core/src/rate_limit.rs`
- Test: `crates/openauth-core/tests/rate_limit/rate_limiter.rs`

- [x] Replace duration truncation with ceiling seconds for positive durations.
- [x] Add a focused test that a denied memory request never returns `X-Retry-After: 0`.
- [x] Run `cargo test -p openauth-core --test rate_limit`.
- [ ] Commit: `fix(core): ceil memory rate limit retry seconds`.

## Task 5: Add Memory Backend Idle TTL

**Files:**
- Modify: `crates/openauth-core/src/options/rate_limit.rs`
- Modify: `crates/openauth-core/src/rate_limit.rs`
- Test: `crates/openauth-core/tests/rate_limit/rate_limiter.rs`
- Test: `crates/openauth/tests/public_api.rs`

- [x] Add `memory_idle_ttl: Option<std::time::Duration>` to `RateLimitOptions`, defaulting to a conservative value such as one hour.
- [x] Pass the TTL into `RateLimitContext` and `TokioMemoryRateLimitStore`.
- [x] Build local limiters with `tokio_rate_limit::algorithm::TokenBucket::with_ttl`.
- [x] Add public builder coverage for configuring the TTL.
- [x] Run core and public API rate limit tests.
- [ ] Commit: `feat(core): evict idle memory rate limit keys`.

## Task 6: Modularize Hot Files If Still Worth It

**Files:**
- Modify/Create under `crates/openauth-core/src/rate_limit/`
- Modify/Create under `crates/openauth-sqlx/src/*/rate_limit.rs`
- Modify/Create under `crates/openauth/tests/`

- [ ] Re-evaluate file sizes after functional fixes.
- [ ] Split only if the module boundaries are obvious and tests stay simple.
- [ ] Run full workspace verification.
- [ ] Commit any split separately as `refactor(...)`.

## Verification

- [ ] `cargo fmt --check`
- [ ] `cargo check --workspace --all-features`
- [ ] `cargo clippy --workspace --all-targets --all-features`
- [ ] `cargo test --workspace --all-features`
