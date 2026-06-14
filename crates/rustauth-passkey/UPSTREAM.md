# rustauth-passkey upstream parity

| Field | Value |
| --- | --- |
| Parity pin | Better Auth `1.6.9` |
| Upstream package/path | `@better-auth/passkey` at `reference/upstream-src/1.6.9/repository/packages/passkey` |
| Rust crate | `rustauth-passkey` |
| Parity level | High server-side parity |
| Scope | Server runtime only: plugin registration, HTTP routes, schema contribution, WebAuthn challenge state, server hooks, error codes, and management endpoints |

`rustauth-passkey` tracks the Better Auth passkey plugin's server behavior.
RustAuth exposes the same seven `/passkey/*` routes, keeps the public passkey
JSON shape aligned, and adds Rust/RustAuth hardening around one-time challenges,
verification state, rate limits, and multi-instance storage expectations.

Status symbols are defined in the [parity index](../../docs/parity/README.md#status-symbols).

## Feature Parity

| Area | Status | Notes |
| --- | --- | --- |
| Plugin registration | ✅ | `passkey(PasskeyOptions)` maps to upstream plugin id `passkey` and registers the same server route set. |
| Registration options | ✅ | `GET /passkey/generate-register-options`; supports session-required and pre-auth `resolve_user` flows, query `name`, `context`, and `authenticatorAttachment`. |
| Registration verification | ✅ | `POST /passkey/verify-registration`; verifies WebAuthn state, creates a passkey, handles `after_verification`, rejects duplicate credential IDs, and consumes the challenge. |
| Authentication options | ✅ | `GET /passkey/generate-authenticate-options`; supports session-scoped allow lists and discoverable credentials without a session. |
| Authentication verification | ✅ | `POST /passkey/verify-authentication`; verifies credential, updates counter, creates a session, returns `{ session, user }`, and consumes the challenge. |
| Passkey management | ✅ | `GET /passkey/list-user-passkeys`, `POST /passkey/update-passkey`, and `POST /passkey/delete-passkey` match upstream paths and response shapes. |
| Schema contribution | ✅ | Same logical passkey model; RustAuth defaults to `passkeys` and snake_case database columns, supports physical table/column renames through `PasskeySchemaOptions`, and adds a hidden `webauthn_credential` JSON field for `webauthn-rs`. |
| Error codes | ✅ | All 14 upstream `PASSKEY_ERROR_CODES` are exported as plugin metadata. |
| Version metadata | ✅ | Upstream exposes the package version from `src/version.ts`; RustAuth sets the plugin version from `CARGO_PKG_VERSION`. |

## Test Coverage

| Surface | RustAuth tests | Upstream tests | Notes |
| --- | --- | --- | --- |
| Registration routes | `tests/passkey/register.rs` | `packages/passkey/src/passkey.test.ts` | Covers session-required, pre-auth `resolve_user`, context/name, extensions, stale sessions, duplicate credentials, challenge cleanup, and after-verification user override. |
| Authentication routes | `tests/passkey/authenticate.rs` | `packages/passkey/src/passkey.test.ts` | Covers discoverable credentials, session allow lists, counter updates, session creation, credential enumeration resistance, replay rejection, and missing-origin failures. |
| Management routes | `tests/passkey/management.rs` | `packages/passkey/src/passkey.test.ts` | Covers list/update/delete, missing passkeys, cross-user ownership, and RustAuth's fresh-session hardening. |
| Rate limits and cookies | `tests/passkey/rate_limit.rs`, `tests/passkey/cookie_config.rs` | Global Better Auth limiter behavior, no dedicated upstream package tests | RustAuth adds ceremony and per-challenge limits plus cookie prefix/attribute tests. |
| Schema and adapters | `tests/passkey/schema.rs`, `tests/passkey/sql.rs`, `tests/passkey/sqlite.rs`, `tests/passkey/secondary_storage.rs` | Upstream adapter behavior through Better Auth test harness | Covers plural table name, physical schema renames, unique credential ID indexes, SQLite/Postgres/MySQL migrations, and secondary storage for shared deployments. |
| OpenAPI and WebAuthn config | `tests/passkey/openapi.rs`, `tests/passkey/webauthn_config.rs`, `src/webauthn.rs` unit tests | Upstream route metadata and SimpleWebAuthn behavior | Covers operation metadata, RP ID/origin derivation, fail-closed config, and `webauthn-rs` option/verification shape. |
| Counts and verify command | 96 Rust `#[test]` / `#[tokio::test]` functions | 17 upstream server Vitest cases plus 1 Node smoke test under `e2e/smoke/test/passkey-preauth.spec.ts` | Verify with `cargo nextest run -p rustauth-passkey`. The installed nextest may not support `-- --list-tests`; use `rg '#\[(test|tokio::test)\]' crates/rustauth-passkey` for a static count. |

## Intentional Differences

| Topic | Better Auth | RustAuth | Why |
| --- | --- | --- | --- |
| WebAuthn backend | Uses `@simplewebauthn/server`. | Uses `webauthn-rs`. | Idiomatic Rust cryptographic verification while preserving observable HTTP behavior. |
| Database naming | Model `passkey` with camelCase fields such as `publicKey`, `userId`, and `credentialID`; `options.schema` can customize adapter names through `mergeSchema`. | Table defaults to `passkeys` with snake_case columns; public JSON remains camelCase and keeps `credentialID`; `PasskeySchemaOptions` customizes physical table/column names. | Rust/database convention internally without breaking public HTTP contracts. |
| Stored credential state | Stores the base64 COSE public key and passkey metadata. | Stores the same public fields plus hidden `webauthn_credential` JSON. | `webauthn-rs` needs full credential state for secure authentication and counter updates. |
| Challenge lifecycle | Signed `better-auth-passkey` cookie references a 5 minute verification record. | Same cookie and TTL, but verification records are consumed atomically. | Prevent challenge replay and make verification one-time-use. |
| Authentication failures | Unknown credentials can return `PASSKEY_NOT_FOUND`. | Unknown, invalid, and out-of-session credentials return `AUTHENTICATION_FAILED`. | Reduce credential-ID enumeration on an auth boundary. |
| Management freshness | Requires a session and resource ownership. | Requires ownership and a fresh session by default for update/delete. | Hardens high-impact credential management mutations. |
| Rate limiting | Relies on Better Auth global rate limiting. | Adds passkey ceremony limits and per-challenge verify limits. | Limit brute force and replay attempts per route and per challenge token. |

## Open Gaps / Risks

| ID | Gap | Severity | Notes |
| --- | --- | --- | --- |
| PK-1 | Closed: physical passkey schema renames are ported. | Low | `PasskeySchemaOptions` maps the logical `passkey` model to custom database table/column names, covering the server-observable portion of Better Auth `options.schema` / `mergeSchema`; arbitrary TypeScript type metadata is client/tooling scope and intentionally out of scope. |
| PK-2 | Deployment risk: multi-origin/proxy configuration can break WebAuthn if misconfigured. | Medium | Intentional fail-closed behavior. Set stable public `base_url`, `origin`, and `rp_id`; tests cover missing-origin/RP-ID fail-closed paths. |
| PK-3 | Deployment risk: in-memory storage is not safe for multi-instance production. | Medium | Intentional RustAuth boundary. Share adapter or secondary storage for verification records, challenge limits, and sessions. |
| PK-4 | Data migration risk: legacy `publicKey`-only rows with invalid or unsupported COSE keys cannot authenticate until re-registered. | Low | Intentional cryptographic boundary. Valid legacy rows are reconstructed at authentication time and backfilled after success; corrupt rows are omitted from `allowCredentials`. |

## Hardening

- Verification records are one-time-use and expire after 5 minutes.
- Signed challenge cookies use the upstream `better-auth-passkey` default name and inherit RustAuth cookie prefix/attribute settings.
- Authentication verifies that session-scoped challenges cannot be satisfied by another user's credential.
- Duplicate credential IDs are checked before insert and remapped after insert races to `PREVIOUSLY_REGISTERED`.
- Counter updates include the expected previous counter, so concurrent authentications fail closed.
- Per-challenge rate-limit keys are scoped with RustAuth core HMAC storage; raw challenge tokens are not persisted as limiter keys.
- Passkey-created sessions use RustAuth's configured IP resolver instead of trusting spoofable forwarding headers directly.

## Upstream Lookup

1. Read the pin in [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md).
2. Open `reference/upstream-src/1.6.9/repository/packages/passkey/`; run `./scripts/fetch-upstream-better-auth.sh` from the repository root if missing.
3. Inspect the server runtime files: `package.json`, `src/index.ts`,
   `src/routes.ts`, `src/schema.ts`, `src/error-codes.ts`, `src/types.ts`,
   `src/utils.ts`, `src/version.ts`, `src/passkey.test.ts`, and
   `e2e/smoke/test/passkey-preauth.spec.ts`.
4. Compare observable contracts first: route path/method, status code, JSON error code, cookie name, DB mutation, and session side effect.
5. Verify local behavior with `cargo nextest run -p rustauth-passkey`.

| Upstream source | Rust source |
| --- | --- |
| `packages/passkey/package.json` package metadata and server entry | `Cargo.toml`, `src/lib.rs` |
| `src/index.ts` plugin endpoints/schema/error codes | `src/lib.rs`, `src/routes.rs`, `src/schema.rs`, `src/errors.rs` |
| `src/routes.ts` registration endpoints | `src/routes/registration.rs`, `tests/passkey/register.rs` |
| `src/routes.ts` authentication endpoints | `src/routes/authentication.rs`, `tests/passkey/authenticate.rs` |
| `src/routes.ts` management endpoints | `src/routes/management.rs`, `tests/passkey/management.rs` |
| `src/schema.ts` passkey model | `src/schema.rs`, `src/store.rs`, SQL/SQLite schema tests |
| `src/error-codes.ts` | `src/errors.rs`, route error responses |
| `src/types.ts` server option and record types | `src/options.rs`, `src/store.rs`, `src/challenge.rs` |
| `src/utils.ts` RP ID derivation | `src/routes.rs`, `tests/passkey/webauthn_config.rs` |
| `src/version.ts` plugin version | `src/lib.rs` plugin version metadata |
| `src/passkey.test.ts` and Node pre-auth smoke test | `tests/passkey/*.rs`, especially `register.rs`, `authenticate.rs`, and `management.rs` |

## Audited Server Files

| Area | Files reviewed |
| --- | --- |
| Upstream server package | `package.json`, `src/index.ts`, `src/routes.ts`, `src/schema.ts`, `src/error-codes.ts`, `src/types.ts`, `src/utils.ts`, `src/version.ts`, `src/passkey.test.ts` |
| Upstream server smoke | `e2e/smoke/test/passkey-preauth.spec.ts` |
| RustAuth implementation | `src/lib.rs`, `src/routes.rs`, `src/routes/registration.rs`, `src/routes/authentication.rs`, `src/routes/management.rs`, `src/schema.rs`, `src/store.rs`, `src/options.rs`, `src/errors.rs`, `src/challenge.rs`, `src/challenge_rate_limit.rs`, `src/cookies.rs`, `src/response.rs`, `src/openapi.rs`, `src/session.rs`, `src/webauthn.rs` |
| RustAuth tests | `tests/passkey/*.rs`, `tests/passkey.rs` |

## Links

- [README](./README.md)
- [Upstream parity index](../../docs/parity/README.md)
