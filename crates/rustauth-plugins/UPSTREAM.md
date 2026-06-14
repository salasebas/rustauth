# rustauth-plugins upstream parity

| Field | Value |
| --- | --- |
| Parity pin | Better Auth `1.6.9` |
| Upstream package/path | `packages/better-auth/src/plugins/` plus `packages/api-key/` |
| Rust crate | `rustauth-plugins` |
| Parity level | High server-side parity |
| Scope | Server plugin IDs, auth routes, schema contributions, hooks, cookies, responses, and plugin options |

`rustauth-plugins` consolidates Better Auth server plugin behavior into Rust
plugin modules. It is aligned with Better Auth 1.6.9 where observable server
contracts matter, while keeping RustAuth's Rust server boundaries.

Status symbols are defined in the [parity index](../../docs/parity/README.md#status-symbols).

## Feature Parity

| Area | Status | Notes |
| --- | --- | --- |
| Plugin inventory | ✅ | Covers all Better Auth server plugin exports plus `@better-auth/api-key`; `additional_fields` is an RustAuth server helper. |
| Access control | ✅ | Role, statement, and request authorization helpers covered by focused tests. |
| Additional fields server helper | 🎯 | RustAuth-only helper around core user/session additional field schema; not counted as a Better Auth server plugin export. |
| Admin | ✅ | User/session management, impersonation, permissions, schema fields, and OpenAPI metadata are implemented. |
| Anonymous users | ✅ | Anonymous sign-in, deletion, custom identity callbacks, and link hooks are implemented. |
| API key | ✅ | Lifecycle, verification, metadata, sessions, org references, configuration, hashing, schema, storage modes, and listing behavior are implemented; pure secondary-storage listing indexes use the atomic `SecondaryStorage` CAS contract. |
| Bearer sessions | ✅ | Authorization header parsing and session lookup behavior are covered. |
| CAPTCHA | ✅ | Server verify hooks and provider handlers are implemented. |
| Custom session | ✅ | Session response extension hooks and cookie behavior are implemented. |
| Device authorization | ✅ | Device code, decision, verification, token, options, and schema paths are implemented. |
| Email OTP | ✅ | OTP send/verify, explicit expired-OTP errors, sign-up/sign-in, password reset alias, change-email current-email verification, hooks, storage modes, resend strategies, rate limits, additional fields, and race protection are implemented. |
| Generic OAuth | ✅ | Provider config, discovery, callback routes, token/userinfo hooks, PKCE, and provider helpers are implemented. |
| Have I Been Pwned | ✅ | k-anonymity range lookup, padding, and hash handling are implemented. |
| JWT | ✅ | JWKS, token, sign/verify endpoints, claims, schema options, and crypto adapter paths are implemented. |
| Last login method | ✅ | OAuth and credential method persistence plus session response metadata are implemented. |
| Magic link | ✅ | Sign-in, verify, token generation, failure redirects, and rate limits are implemented. |
| MCP | 🎯 | Replaced by the sibling `rustauth-oauth-provider` crate via `OAuthProviderOptions::mcp`; OAuth flows use `/oauth2/*`. |
| Multi-session | ✅ | Signed per-session cookies, switching, revocation, max-session limiting, forged-cookie rejection, and sign-out cleanup are implemented. |
| OAuth proxy | ✅ | Callback rewriting, encrypted preview payloads, replay max-age, state cleanup, production passthrough, skip headers, custom secrets, and database-backed state are implemented. |
| One Tap | ✅ | Server callback, account linking, disabled sign-up, session/cookie behavior, additional fields, and metadata are implemented; missing-email response shape intentionally differs. |
| One-time token | ✅ | Token generation, verification, session/user output, cookie-cache preservation, and expiry rejection are implemented. |
| OpenAPI | ✅ | Generated auth schemas and optional Scalar reference UI are implemented. |
| Organization | ✅ | Core org/member/invitation/team/session/access-control paths are implemented, including dynamic AC custom resources, missing-permission reporting, creator-role guards, hook mutations, default-team response shape, and shared server-side provisioning for sibling crates. |
| Phone number | ✅ | OTP, sign-in, verification, password reset, hooks, schema, and rate limit paths are implemented. |
| SIWE | ✅ | Nonce, verify, wallet account linking, schema, and address handling are implemented. |
| Two-factor | ✅ | TOTP, OTP, backup codes, trust-device cookies, passwordless option, custom table, storage paths, verified-method filtering, credential-only enforcement scope, and session rotation on enable/disable are implemented. |
| Username | ✅ | Sign-in, availability validation, normalization hooks, display username behavior, validation ordering, duplicate update checks, and schema are implemented. |
| `oidc-provider` | 🎯 | Replaced by the sibling `rustauth-oauth-provider` crate. |
| SSO, SCIM, Stripe, Passkey, adapters | ➖ | Covered by sibling crates or out of scope here. |

## Test Coverage

| Surface | RustAuth tests | Upstream tests | Notes |
| --- | ---: | ---: | --- |
| Mapped server plugin scope | 677 | 931 | Verify with `cargo nextest run -p rustauth-plugins`. |
| Server module inventory | 26 | 25 | Upstream count is exported server plugins after excluding `test-utils` and replaced `oidc-provider`, plus `@better-auth/api-key`; Rust adds `additional_fields` as a server helper. |
| Server route literals | 139 | 132 | No upstream server-route candidates were missing after excluding replaced/non-server paths; Rust includes additional hardening/support endpoints. |
| API key | 64 | 176 | Rust covers lifecycle, verify, expiry, refill windows, metadata, sessions, org refs, org RBAC, schema, storage, configurations, and pure/fallback secondary-storage behavior with atomic reference-index CAS. |
| Organization | 70 | 180 | Rust covers all 35 upstream server routes via the plugin-on-core router (`/api/auth/organization/*`), dynamic AC, comma-separated/multi-role merge, teams, session, limits, hook mutation/order, invitation edge cases (expired reject, re-invite cancel, rejected filtering), owner-role guards, shared provisioning helper semantics, server-only `userId` contracts, and additional fields; parity risk remains on the large upstream matrix, not missing routes. |
| Email OTP | 37 | 73 | Rust covers send/verify, expired OTPs, hooks, storage, server behavior, password reset and legacy alias, change-email current-email verification, resend, rate limits, race protection, and additional fields. |
| Two-factor | 25 | 55 | Rust covers TOTP, OTP, backup codes, cookies, storage, passwordless option, trust-device validation, session rotation, and enforcement scope. |
| Username | 17 | 33 | Rust covers flow, availability validation, duplicate checks, display username behavior, normalization, and schema. |

## Intentional Differences

| Topic | Better Auth | RustAuth | Why |
| --- | --- | --- | --- |
| Environment URL | `BETTER_AUTH_URL` | `RUSTAUTH_URL` | Crate uses RustAuth-specific runtime naming. |
| One Tap missing email | `200 { error }` | `400 EMAIL_NOT_AVAILABLE` | Missing auth identity data is treated as a failed server contract. |
| Serializable metadata | Exposes callback-driven plugin options | Omits closure/callback fields, preserves observable values | Runtime callbacks are not serializable metadata. |
| OAuth proxy payloads | Object transport | Rust-owned encrypted structs | Payload is RustAuth-to-RustAuth transport, not a public cross-implementation API. |
| Generic OAuth HTTP | Baseline outbound fetch behavior | SSRF-guarded default HTTP transport | Auth boundary should fail closed for private/internal targets. |
| API-key cache revalidation | Cache-first secondary storage | Optional DB revalidation for cache hits | Preserves compatibility by default while offering immediate revocation visibility. |
| API-key pure secondary listing across processes | Cache-first `customStorage` get/set/delete index | Atomic `SecondaryStorage::compare_and_set` / `delete_if_value` index updates, plus database fallback/revalidation options | Rust storage backends can provide cross-process compare-and-set semantics without forcing database fallback. |
| Additional fields helper | Core user/session additional fields | Dedicated Rust server plugin helper | Gives Rust callers a plugin-shaped way to contribute schema/runtime metadata. |
| `oidc-provider` | Built-in plugin export | `rustauth-oauth-provider` sibling crate | OAuth/OIDC provider behavior is large enough to own separately. |

## Open Gaps / Risks

| ID | Gap | Severity | Notes |
| --- | --- | --- | --- |
| G1 | Test count is below upstream | Low | 677 Rust tests vs 931 mapped upstream declarations because Rust ports observable server scenarios rather than the full TypeScript/client matrix; API-key org/config/lifecycle/verify and Organization query/invitation/owner/team/provisioning edges were re-audited against Better Auth 1.6.9 and covered with focused parity tests. |
| G2 | Organization behavior is broad and complex | Med | Routes and core plugin surface exist in `rustauth-plugins` (mounted through `rustauth-core`); residual risk is edge-case parity (hooks, roles, teams, dynamic policy), not a missing organization plugin. Continue adding focused tests in `tests/organization/` as upstream scenarios are mapped. |
| G3 | API-key pure secondary-storage listing consistency | Low | Closed for backends that implement atomic `SecondaryStorage` CAS; default best-effort implementations are still suitable only for single-process/local storage. |

## Hardening Notes

- Keep Generic OAuth and OAuth proxy outbound requests on SSRF-guarded HTTP transports.
- Prefer explicit errors at auth boundaries; avoid silent fallbacks for malformed
  cookies, forged API keys, expired OTPs, or invalid OAuth state.
- Use API-key database fallback/revalidation or a secondary-storage backend with
  atomic `compare_and_set` / `delete_if_value` for strict multi-process
  `/api-key/list` consistency.
- Add focused tests for status codes, JSON error codes, DB mutations, cookies,
  and headers before changing plugin behavior.
- Run adapter migrations after enabling plugins that contribute schema.

## Upstream Lookup

1. Read the pin in
   [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md).
2. Open `reference/upstream-src/1.6.9/repository/packages/better-auth/src/plugins/`
   and `reference/upstream-src/1.6.9/repository/packages/api-key/`.
3. If the upstream tree is missing, run `./scripts/fetch-upstream-better-auth.sh`.
4. Map server-only upstream exports from `packages/better-auth/package.json`,
   `src/plugins/index.ts`, route registrations, and `*.test.ts` files to Rust.
5. Verify with `cargo nextest run -p rustauth-plugins`.

| Upstream | Rust |
| --- | --- |
| `packages/better-auth/src/plugins/index.ts` | `crates/rustauth-plugins/src/lib.rs` |
| `packages/better-auth/src/plugins/<plugin>/` | `crates/rustauth-plugins/src/<plugin>/` |
| `packages/api-key/src/` | `crates/rustauth-plugins/src/api_key/` |
| `packages/better-auth/src/plugins/**/*.test.ts` | `crates/rustauth-plugins/tests/<plugin>/` |
| `packages/api-key/src/*.test.ts` | `crates/rustauth-plugins/tests/api_key/` |
| `packages/better-auth/package.json` plugin exports | `PLUGIN_IDS` and public Rust modules |
| RustAuth-only helper | `crates/rustauth-plugins/src/additional_fields/` |
| Excluded upstream paths | `test-utils`, `oidc-provider`, and non-server helper paths |

## Links

- [README](./README.md)
- [Upstream parity index](../../docs/parity/README.md)
