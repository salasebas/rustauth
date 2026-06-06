# Upstream parity — openauth-fred

Better Auth **1.6.9** behavioral reference for contributors and parity audits.
OpenAuth is inspired by Better Auth; it is not a line-by-line port.

| Field | Value |
| --- | --- |
| **Parity pin** | [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md) (`1.6.9`) |
| **Upstream package** | `@better-auth/redis-storage` (ioredis) |
| **Upstream path** | `reference/upstream-src/1.6.9/repository/packages/redis-storage/` |
| **Rust crate** | `crates/openauth-fred/` |
| **Parity level** | **~75%** vs literal upstream adapter; **~98%** vs OpenAuth secondary-storage contract |
| **Scope** | Server-side Redis/Valkey: `SecondaryStorage`, `RateLimitStore`, connection helpers. Sibling: [`openauth-redis`](../openauth-redis/UPSTREAM.md). Session key names and HTTP rate-limit middleware live in [`openauth-core`](../openauth-core/UPSTREAM.md). |

## Summary

`openauth-fred` is the `fred` backend for OpenAuth secondary KV and distributed
rate limiting. Adapter CRUD, TTL handling, `list_keys`/`clear`, and physical key
layout match `openauth-redis` on a shared instance. Literal parity with
`@better-auth/redis-storage` is partial: OpenAuth namespaces keys under
`secondary:`, adds `set_if_not_exists`/`take`, and uses different `ttl=0`
semantics. Rate limiting is a dedicated Lua store (`rate-limit:`) instead of
upstream's JSON blobs in secondary KV when `rateLimit.storage` defaults to
`secondary-storage` (`create-context.ts`).

## Feature parity

| Area | Status | Notes |
| --- | --- | --- |
| Secondary storage (`get`/`set`/`delete`) | ⚠️ Partial | Upstream `redis-storage.ts` exposes three ops; OpenAuth `SecondaryStorage` trait |
| `set_if_not_exists` / `take` | 🎯 Extension | Required by `openauth-core`; absent from upstream redis adapter |
| `list_keys` / `clear` | ✅ High | `SCAN` on `{prefix}secondary:*`; upstream `KEYS` on `{prefix}*` |
| Rate limit Redis store | 🎯 Extension | `FredRateLimitStore` + Lua; upstream reuses secondary KV as JSON |
| Shared connection bundle | ✅ High | `FredOpenAuthStores` — one shared `fred` connection (`src/bundle.rs`) |
| Cross-adapter wire format | ✅ High | `{prefix}secondary:{key}`; byte-compatible with `openauth-redis` |
| Better Auth Redis data import | ❌ Low | Upstream flat `{prefix}{key}` vs OpenAuth `secondary:` namespace |
| Auto RL when secondary configured | ⚠️ Partial | Upstream defaults `rateLimit.storage` to `secondary-storage`; OpenAuth needs explicit `RateLimitOptions` |
| Valkey URL aliases | 🎯 Extension | `valkey://` → `redis://` (`src/url.rs`) |
| TLS (`rediss://` / `valkeys://`) | ✅ High | Opt-in `native-tls` or `rustls` features on `fred` |

## Test coverage

| Surface | OpenAuth (Rust) | Upstream (server) | Notes |
| --- | --- | --- | --- |
| Adapter unit + validation | 27 | 0 | `src/storage.rs`, `src/script.rs`, `tests/config.rs` — no live Redis |
| Live Redis/Valkey integration | 17 | 0 | `tests/fred_rate_limit.rs` |
| Secondary-storage server flows | 3 | 4 | Sign-up, DB+secondary, password-reset vs `secondary-storage.test.ts` |
| Rate-limit store atomicity | 5 | ~4 relevant | Lua boundary, concurrency, handler `429`; upstream RL+secondary-KV in `rate-limiter.test.ts` (~20 total, mostly middleware rules) |
| Cross-adapter (`openauth-redis`) | 2 | — | Shared physical keys and `take` |
| `set_if_not_exists` | 0 | — | Implemented in `src/storage.rs`; no dedicated test |
| Context defaults (RL storage mode) | — | 2 | `create-context.test.ts` (`secondary-storage` when `secondaryStorage` set) |
| **Total (this crate)** | **44** | **0 adapter + 4 secondary + ~6 RL/context** | `cargo nextest list -p openauth-fred` |

Verify:

```bash
cargo nextest run -p openauth-fred
```

Integration tests expect Redis on `127.0.0.1:6379` and/or Valkey on `127.0.0.1:6380`.
Override with `OPENAUTH_FRED_REDIS_URL` / `OPENAUTH_FRED_VALKEY_URL` (explicit URLs
fail closed when unreachable).

## Intentional differences

| Topic | Better Auth 1.6.9 | OpenAuth | Why |
| --- | --- | --- | --- |
| Key layout | `{prefix}{logical_key}` | `{prefix}secondary:{logical_key}` | Isolate secondary KV from `rate-limit:` keys; match `openauth-redis` |
| `ttl = 0` on `set` | Store without expiry | Delete key | `openauth-core` expired-value contract |
| `list_keys` / `clear` | `KEYS` on full prefix | `SCAN` on `secondary:` only | Production-safe scans; `clear()` preserves rate-limit state (OPE-37) |
| Rate-limit backing | JSON in secondary KV | Dedicated Lua hash (`rate-limit:`) | Atomic multi-instance increments |
| Window reset | `timeSinceLastRequest > window` | Same (`>` in Lua) | Matches Better Auth server middleware |
| Default prefix | `better-auth:` | `openauth:` | OpenAuth namespace |
| Redis connection | Caller-owned ioredis instance | `FredOpenAuthStores` shares one `fred` connection | Fewer connections when both stores are used |

## Open gaps and risks

| ID | Gap / risk | Severity | Notes |
| --- | --- | --- | --- |
| G1 | Better Auth Redis import | High | Flat upstream keys ≠ `{prefix}secondary:`; rewrite required |
| G2 | Explicit rate-limit wiring | Med | Upstream auto-selects `secondary-storage` RL mode in `create-context.ts`; OpenAuth requires `RateLimitOptions::secondary_storage` |
| G3 | `set_if_not_exists` untested | Med | No unit or live-redis test (unlike `take`, which has concurrency coverage) |
| G4 | Legacy Fred key layout | Med | Pre-`secondary:` physical keys not read after namespace change ([CHANGELOG](./CHANGELOG.md)) |
| G5 | Live Redis/Valkey required | Med | 17 integration tests skip unavailable default endpoints |
| G6 | Reconnect / cluster | Low | Delegated to `fred`; no OpenAuth retry wrapper |
| G7 | Example app coverage | Low | `examples/full-app` demos `FredRateLimitStore` only, not `FredSecondaryStorage` / `FredOpenAuthStores` |

## Hardening notes

- Empty key prefix and zero scan count/window/max rejected before Redis I/O (fail-closed config).
- Rate limiting uses atomic Lua (`evalsha_with_reload`) for multi-instance safety.
- `clear()` scoped to `secondary:` so co-located `rate-limit:` keys survive (OPE-37).
- `SCAN` patterns escape Redis glob metacharacters in prefixes.
- `take()` uses `GETDEL`; concurrent take verified under live Redis.

## Upstream lookup

1. Read the pin in [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md).
2. Run `./scripts/fetch-upstream-better-auth.sh` if `reference/upstream-src/1.6.9/repository/` is missing.
3. Open the upstream server paths below (server-side only).
4. Map upstream → Rust:

| Upstream (server) | Rust |
| --- | --- |
| `packages/redis-storage/src/redis-storage.ts` | `src/storage.rs` (`FredSecondaryStorage`) |
| `packages/core/src/db/type.ts` (`SecondaryStorage`) | `openauth-core` `SecondaryStorage` trait → `src/storage.rs` |
| `packages/better-auth/src/context/create-context.ts` (`rateLimit.storage` default) | `openauth-core` `RateLimitOptions` + `src/bundle.rs` |
| `packages/better-auth/src/api/rate-limiter/index.ts` | `src/store.rs`, `src/script.rs` (`FredRateLimitStore`) |
| `packages/better-auth/src/db/secondary-storage.test.ts` | `tests/fred_rate_limit.rs` (sign-up / revoke flows) |
| `packages/better-auth/src/db/internal-adapter.ts` | Session logical keys (`active-sessions-*`, token keys) — [`openauth-core`](../openauth-core/UPSTREAM.md), not this crate |
| `packages/better-auth/src/api/rate-limiter/rate-limiter.test.ts` | `tests/fred_rate_limit.rs` (atomicity, `429`, window `>`) |
| — | `src/bundle.rs`, `src/url.rs`, `src/config.rs`, `src/error.rs` |

5. Add a failing Rust integration test before behavior changes; match key layout, TTL side effects, and rate-limit decisions.

### Crate files audited (14/14)

| Path | Role |
| --- | --- |
| `src/lib.rs`, `src/storage.rs`, `src/store.rs`, `src/script.rs` | Public surface + implementations |
| `src/bundle.rs`, `src/config.rs`, `src/url.rs`, `src/error.rs` | Wiring, options, URL normalize, errors |
| `tests/fred_rate_limit.rs`, `tests/config.rs` | Integration + config/Lua parsing |
| `README.md`, `Cargo.toml`, `CHANGELOG.md` | User docs, deps, migration notes |
| `examples/full-app` (fred usage) | `FredRateLimitStore` only — see G7 |

### Upstream server files audited

| Path | Relevance |
| --- | --- |
| `packages/redis-storage/src/redis-storage.ts` | Direct adapter contract (`get`/`set`/`delete`/`listKeys`/`clear`) |
| `packages/redis-storage/src/index.ts`, `README.md`, `CHANGELOG.md` | Exports; no behavior changes in 1.6.9 |
| `packages/core/src/db/type.ts` | Upstream `SecondaryStorage` interface (3 ops) |
| `packages/better-auth/src/context/create-context.ts` | `rateLimit.storage` default when secondary configured |
| `packages/better-auth/src/context/create-context.test.ts` | RL storage default + secondary wiring tests |
| `packages/better-auth/src/api/rate-limiter/index.ts` | Secondary-KV JSON rate-limit mode |
| `packages/better-auth/src/api/rate-limiter/rate-limiter.test.ts` | Server RL middleware (20 `it()`) |
| `packages/better-auth/src/db/secondary-storage.test.ts` | Server session + secondary flows (4 `it()`) |
| `packages/better-auth/src/db/internal-adapter.ts` | Logical key patterns (`active-sessions-*`, tokens) |

### Audit status (server-only)

**Complete** for the `openauth-fred` crate boundary: Redis/Valkey adapter
(`SecondaryStorage`, `RateLimitStore`, connection helpers). All crate source,
tests, and upstream adapter contract files above were reviewed.

**Out of crate scope** (not required to finish this audit; tracked elsewhere):

| Area | Why |
| --- | --- |
| [`openauth-core`](../openauth-core/UPSTREAM.md) | Session/verification logical keys, RL middleware rules, auto-wiring |
| Upstream plugin consumers (`api-key`, `oauth-provider`, `sso`, `device-authorization`) | Call `secondaryStorage`; do not define Redis adapter behavior |
| `internal-adapter.test.ts` (~33 server tests) | Session persistence layer, not `redis-storage.ts` |
| `get-tables.ts` / schema tests | DB schema when secondary storage is enabled |
| `test/unit/magic-link-secondary-storage.test.ts` | Plugin E2E — not redis adapter scope |

**Open implementation gaps** (documented above, not audit blockers): G3
(`set_if_not_exists` test), G7 (example app), G1/G2 (core wiring / key import).

## Related docs

- [Crate README](./README.md) — usage and quick start
- [Parity index](../../docs/parity/README.md)
