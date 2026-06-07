# Upstream parity — openauth-redis

Better Auth **1.6.9** behavioral reference for contributors and parity audits.
OpenAuth is inspired by Better Auth; it is not a line-by-line port.

| Field | Value |
| --- | --- |
| **Parity pin** | [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md) |
| **Upstream package** | `@better-auth/redis-storage` (ioredis) |
| **Upstream path** | `reference/upstream-src/1.6.9/repository/packages/redis-storage/` |
| **Rust crate** | `crates/openauth-redis/` |
| **Parity level** | **High** vs OpenAuth secondary-storage contract; **partial** vs literal upstream adapter |
| **Scope** | Server-side Redis/Valkey: `SecondaryStorage`, `RateLimitStore`, connection helpers. Sibling: [`openauth-fred`](../openauth-fred/UPSTREAM.md). Session logical keys and HTTP rate-limit middleware live in [`openauth-core`](../openauth-core/UPSTREAM.md). |

## Summary

`openauth-redis` is the `redis-rs` backend for OpenAuth secondary KV and distributed
rate limiting. Adapter CRUD, TTL handling, `list_keys`/`clear`, and physical key
layout match [`openauth-fred`](../openauth-fred/UPSTREAM.md) on a shared instance.
Literal parity with `@better-auth/redis-storage` is partial: OpenAuth namespaces
keys under `secondary:`, adds `set_if_not_exists`/`take`, and uses different
`ttl=0` semantics. Rate limiting is a dedicated Lua store (`rate-limit:`) instead
of upstream JSON blobs in secondary KV when `rateLimit.storage` defaults to
`secondary-storage`.

Status symbols are defined in the [parity index](../../docs/parity/README.md#status-symbols).

## Feature parity

| Area | Status | Notes |
| --- | --- | --- |
| Secondary storage (`get`/`set`/`delete`) | ✅ High | `{prefix}secondary:` namespace; `ttl=0` deletes key per `openauth-core` contract |
| `set_if_not_exists` / `take` | 🎯 Extension | Required by `openauth-core`; absent from upstream redis adapter |
| `list_keys` / `clear` | ✅ High | `SCAN` on `{prefix}secondary:*`; upstream uses `KEYS` on `{prefix}*` |
| Rate limit Redis store | 🎯 Extension | `RedisRateLimitStore` + Lua; upstream reuses secondary KV as JSON |
| Shared connection bundle | ✅ High | `RedisOpenAuthStores` — one `ConnectionManager` for both stores |
| Cross-adapter wire format | ✅ High | Byte-compatible with `openauth-fred` on same Redis instance |
| Better Auth Redis data import | ➖ Out of scope | Upstream flat `{prefix}{key}` vs OpenAuth `secondary:` namespace; requires an explicit migration/rewrite tool, not adapter fallback reads |
| Auto RL when secondary configured | ✅ High | `RedisOpenAuthStores::apply_to_options` wires secondary storage and distributed RL together; core default policy remains explicit |
| Session payload interchange | ➖ Out of scope | Logical keys and JSON live in `openauth-core`; this crate stores opaque strings only |
| Valkey URL aliases | 🎯 Extension | `valkey://` / `valkeys://` normalized to `redis://` / `rediss://` |
| TLS (`rediss://` / `valkeys://`) | ✅ High | Opt-in `rustls` or `native-tls` crate features |

## Test coverage

| Surface | OpenAuth (Rust) | Upstream | Notes |
| --- | --- | --- | --- |
| Adapter unit + validation | 10 | 0 | `src/lib.rs`, `src/secondary.rs`, `src/rate_limit.rs`, `tests/config.rs` |
| Live Redis/Valkey integration | 11 | 0 | `tests/redis_rate_limit.rs` — secondary CRUD, `set_if_not_exists`, rate-limit atomicity, shared bundle |
| Secondary-storage server flows | — | 4 `it()` | `packages/better-auth/src/db/secondary-storage.test.ts` (covered in `openauth-fred` E2E) |
| Rate-limit middleware + storage mode | — | ~6 relevant | `rate-limiter.test.ts` + `create-context.test.ts` (middleware in `openauth-core`) |
| **Total (this crate)** | **21** | **0 adapter + 4 secondary + ~6 RL/context** | `cargo nextest list -p openauth-redis` |

Verify:

```bash
cargo nextest run -p openauth-redis
```

Integration tests expect Redis on `127.0.0.1:6379` and/or Valkey on `127.0.0.1:6380`.
Override with `OPENAUTH_REDIS_URL` / `OPENAUTH_VALKEY_URL`.

## Intentional differences

| Topic | Better Auth 1.6.9 | OpenAuth | Why |
| --- | --- | --- | --- |
| Key layout | `{prefix}{logical_key}` | `{prefix}secondary:{logical_key}` | Isolate secondary KV from `rate-limit:` keys; match `openauth-fred` |
| `ttl = 0` on `set` | Store without expiry | Delete key | `openauth-core` expired-value contract |
| `list_keys` / `clear` | `KEYS` on full prefix | `SCAN` on `secondary:` only | Production-safe scans; `clear()` preserves rate-limit state |
| Rate-limit backing | JSON in secondary KV | Dedicated Lua hash (`rate-limit:`) | Atomic multi-instance increments |
| Default prefix | `better-auth:` | `openauth:` | OpenAuth namespace |
| TLS URLs | Caller configures ioredis TLS | `rediss://` / `valkeys://` require `rustls` or `native-tls` feature | Explicit compile-time TLS backend |
| Redis client | Caller-owned ioredis | `redis-rs` `ConnectionManager` | Idiomatic Rust async stack |

## Open gaps and risks

| ID | Gap / risk | Severity | Notes |
| --- | --- | --- | --- |
| G1 | Better Auth Redis import | High | Intentional out of scope for this adapter: flat upstream keys need an explicit migration/rewrite tool instead of fallback reads that broaden the key namespace |
| G2 | Session payloads not portable | Med | Out of scope: logical keys and JSON live in `openauth-core`; this crate treats values as opaque strings |
| G3 | Live Redis/Valkey required | Med | Integration tests skip when default endpoints are unreachable |

## Hardening notes

- Empty key prefix and zero scan count/window/max rejected before Redis I/O (fail-closed config).
- Rate limiting uses atomic Lua (`evalsha` with reload) for multi-instance safety.
- `clear()` scoped to `secondary:` so co-located `rate-limit:` keys survive.
- `SCAN` patterns escape Redis glob metacharacters in prefixes.
- `take()` uses `GETDEL` for one-shot reads.
- `set_if_not_exists()` uses Redis `SET NX` and is covered under live Redis/Valkey
  for overwrite protection, concurrent create-once behavior, and TTL expiry.

## Upstream lookup

1. Read the pin in [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md).
2. Run `./scripts/fetch-upstream-better-auth.sh` if `reference/upstream-src/` is missing.
3. Open `reference/upstream-src/1.6.9/repository/packages/redis-storage/`.
4. Map upstream → Rust:

| Upstream | Rust |
| --- | --- |
| `packages/redis-storage/src/redis-storage.ts` | `src/secondary.rs` (`RedisSecondaryStorage`) |
| `packages/core/src/db/type.ts` (`SecondaryStorage`) | `openauth-core` `SecondaryStorage` trait → `src/secondary.rs` |
| `packages/better-auth/src/context/create-context.ts` | `openauth-core` `RateLimitOptions` + `src/bundle.rs` |
| `packages/better-auth/src/api/rate-limiter/index.ts` | `src/rate_limit.rs` (`RedisRateLimitStore`) |
| `packages/better-auth/src/db/secondary-storage.test.ts` | `tests/redis_rate_limit.rs` (adapter flows); sign-up E2E in `openauth-fred` |
| — | `src/bundle.rs`, `src/url.rs` |

5. Add a failing Rust integration test before behavior changes; match key layout, TTL side effects, and rate-limit decisions—not TypeScript types.

## Related docs

- [Crate README](./README.md) — usage and quick start
- [Sibling `openauth-fred`](../openauth-fred/UPSTREAM.md) — same contract, `fred` client
- [Parity index](../../docs/parity/README.md)
