# Fred Upstream Parity Audit Plan

## Summary

Audit target: `crates/openauth-fred`, matching upstream Better Auth package
`@better-auth/redis-storage`.

The Fred crate already matches the main server-side secondary-storage contract:
it provides async `get`, `set`, and `delete`, accepts a user-created `fred`
client through `new`, keeps Redis support outside core, and propagates command
failures as `OpenAuthError` values instead of panicking.

No dependency changes are needed.

## Upstream Files Inspected

- `upstream/better-auth/1.6.9/repository/packages/redis-storage/src/redis-storage.ts`
- `upstream/better-auth/1.6.9/repository/packages/redis-storage/src/index.ts`
- `upstream/better-auth/1.6.9/repository/packages/redis-storage/package.json`
- `upstream/better-auth/1.6.9/repository/packages/redis-storage/README.md`
- `upstream/better-auth/1.6.9/repository/e2e/smoke/test/redis.spec.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/db/secondary-storage.test.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/db/internal-adapter.test.ts`
- `upstream/better-auth/1.6.9/repository/packages/core/src/types/init-options.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/api/rate-limiter/index.ts`

## OpenAuth Files Inspected

- `crates/openauth-fred/src/lib.rs`
- `crates/openauth-fred/src/config.rs`
- `crates/openauth-fred/src/storage.rs`
- `crates/openauth-fred/src/store.rs`
- `crates/openauth-fred/src/script.rs`
- `crates/openauth-fred/src/url.rs`
- `crates/openauth-fred/src/error.rs`
- `crates/openauth-fred/tests/config.rs`
- `crates/openauth-fred/tests/fred_rate_limit.rs`
- `crates/openauth-fred/README.md`
- `crates/openauth-core/src/options/storage.rs`
- `crates/openauth-core/src/options/rate_limit.rs`
- `crates/openauth-core/src/session.rs`
- `crates/openauth-core/src/verification.rs`
- `crates/openauth-plugins/src/api_key/storage/secondary.rs`

## Confirmed Matches

- `FredSecondaryStorage::new` accepts a `fred::clients::Client`, equivalent in
  spirit to upstream `redisStorage({ client })` accepting a caller-created
  `ioredis` client.
- `get`, `set`, and `delete` are async and return typed OpenAuth errors.
- `set(..., Some(ttl))` applies expiration only when `ttl > 0`; `None` and
  `Some(0)` store without expiration, matching upstream's `ttl !== undefined &&
  ttl > 0` branch.
- `list_keys` returns keys without the configured prefix.
- `clear` removes keys under the configured prefix.
- Redis support remains optional in a separate crate, and TLS behavior is
  delegated to `fred` feature flags.
- Fred-backed secondary storage works through the OpenAuth email sign-up and
  get-session flow, matching the upstream Redis smoke test's core server-side
  session-storage assertion.
- Fred-backed secondary storage works when sessions are also stored in the
  database and deletes the secondary copy on sign-out even if the database
  session is preserved.
- Fred-backed secondary storage works for password-reset verification token
  creation and deletion.

## Confirmed Differences

- The default prefix is `openauth:` instead of upstream `better-auth:`. This is
  intentional crate identity behavior.
- `list_keys` and `clear` use `SCAN` instead of upstream `KEYS`. This preserves
  the helper behavior while avoiding a production-blocking full keyspace scan.
- `FredRateLimitStore` is an OpenAuth-specific atomic distributed rate-limit
  backend. Upstream `@better-auth/redis-storage` only exposes a secondary
  storage adapter; upstream rate limiting consumes secondary storage through
  core.
- Fred supports `valkey://` and `valkeys://` aliases. This is an OpenAuth
  extension.
- OpenAuth core storage key names differ from Better Auth internal key names.
  This belongs to the Rust core/session architecture, not the Fred adapter.

## Risks

- Redis glob metacharacters in `FredSecondaryStorageOptions::key_prefix` can make
  the `SCAN MATCH` pattern broader, narrower, or otherwise surprising if treated
  as a Redis glob. This affects `list_keys` and therefore `clear`.
- An empty Fred secondary-storage prefix would make `list_keys` and `clear`
  operate across the whole Redis keyspace. Upstream allows an empty `keyPrefix`,
  but OpenAuth should reject this for operational helpers because `clear` is
  server-side destructive.
- A zero `scan_count` is invalid for OpenAuth's SCAN-based helpers and should be
  rejected before Redis I/O.
- Upstream's `KEYS` helper has the same glob-character exposure and can block on
  large keyspaces. OpenAuth should keep the safer `SCAN` implementation while
  matching literal prefix intent.
- Redis-backed integration tests depend on local Redis or Valkey availability.
  Tests should continue to skip unavailable default targets and fail only when an
  explicit env-configured target is unavailable.

## Proposed Fixes

- Escape Redis glob metacharacters in the configured Fred secondary-storage
  prefix before building the `SCAN MATCH` pattern.
- Reject an empty Fred secondary-storage prefix for `list_keys` and `clear`
  before issuing Redis commands.
- Reject `scan_count = 0` for `list_keys` and `clear` before issuing Redis
  commands.
- Preserve literal `strip_prefix` filtering after scanning.
- Preserve the public API, option names, defaults, and crate feature flags.
- Document parity status and intentional differences in `crates/openauth-fred/PARITY.md`.

## Tests To Add Or Update

- Unit tests for Redis SCAN pattern escaping of `*`, `?`, `[`, `]`, and `\`.
- Fred integration coverage that uses a key prefix containing Redis glob
  metacharacters and verifies `set`, `list_keys`, and `clear` use the prefix
  literally.
- Fred integration coverage that `set(..., Some(0))` stores without expiration.
- Fred unit coverage that `list_keys` and `clear` reject an empty prefix without
  touching Redis.
- Fred unit coverage that `list_keys` and `clear` reject `scan_count = 0`
  without touching Redis.
- Fred integration coverage that OpenAuth stores sign-up session data in Fred
  secondary storage and can read it back through `get-session`.
- Fred integration coverage for database-backed sessions with Fred secondary
  storage and preserved database sessions.
- Fred integration coverage for password-reset verification storage.

## Items Intentionally Left Unchanged

- No change to the default `openauth:` prefix.
- No switch from `SCAN` back to upstream `KEYS`.
- No removal of `FredRateLimitStore`.
- No change to Valkey URL aliases.
- No new dependencies, feature flags, re-exports, database schemas, request
  shapes, or public API types.
- No rejection of empty prefixes for `get`, `set`, or `delete`; the guard is
  limited to keyspace-wide operational helpers.

## Verification Commands

```bash
cargo fmt --all --check
cargo clippy -p openauth-fred --all-targets -- -D warnings
cargo nextest run -p openauth-fred
```
