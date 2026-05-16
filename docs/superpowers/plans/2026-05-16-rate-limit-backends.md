# Rate Limit Backends Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild OpenAuth rate limiting around atomic storage decisions, fast local Tokio-backed limiting, SQLx distributed limiting, Redis distributed limiting, and optional hybrid local+distributed protection.

**Architecture:** Keep route/rule resolution in `openauth-core`, but replace the current `get`/`set` storage contract with an atomic async consume API. Local memory uses `tokio-rate-limit`; SQLx and Redis live outside core so core does not depend on SQLx or Redis. Distributed backends are authoritative for multi-instance deployments, and hybrid mode adds a local prefilter before the distributed backend.

**Tech Stack:** Rust 2021, Tokio, `tokio-rate-limit 0.8`, existing SQLx adapters, Redis `0.32` in a new integration crate, Better Auth upstream parity for rule semantics.

---

## Summary

The current rate limiter works for one process, but `Database` and `SecondaryStorage` are not real backends yet; without `custom_storage`, they are rejected during context creation. This plan makes rate limiting production-grade by making every real backend atomic and async.

Upstream Better Auth defaults to memory, switches to secondary storage when `secondaryStorage` exists, supports database storage, and supports custom storage, but still uses `get`/`set`. OpenAuth intentionally improves on that by using an atomic `consume` operation.

## Key Changes

- Add `tokio-rate-limit = "0.8"` to workspace dependencies and use it only for local in-process limiting.
- Add an atomic async `RateLimitStore` contract with `RateLimitConsumeInput` and `RateLimitDecision`.
- Keep legacy `RateLimitStorage` behind an adapter for compatibility, but prefer `custom_store`.
- Make async router rate limiting consume before endpoint execution.
- Add SQLx stores in `openauth-sqlx`.
- Add Redis store in a new `openauth-redis` crate.
- Add optional hybrid local-prefilter plus distributed-authoritative store.

## Test Plan

- `cargo test -p openauth-core rate_limit`
- `cargo test -p openauth-core --test api`
- `cargo test -p openauth-sqlx --all-features`
- `OPENAUTH_REDIS_URL=redis://127.0.0.1:6379 cargo test -p openauth-redis`
- `cargo test --workspace --all-features`
- `cargo clippy --workspace --all-targets --all-features`
- `cargo fmt --check`

## Assumptions

- Do not copy `tokio-rate-limit`; use it as a dependency.
- Keep `openauth-core` free of SQLx and Redis dependencies.
- Use milliseconds for new rate-limit timing.
- Hybrid mode is opt-in.
