# openauth-plugins upstream parity

| Field | Value |
| --- | --- |
| Parity pin | Better Auth `1.6.9` |
| Upstream package/path | `packages/better-auth/src/plugins/` plus `packages/api-key/` |
| Rust crate | `openauth-plugins` |
| Parity level | High server-side parity |
| Scope | Server plugin IDs, auth routes, schema contributions, hooks, cookies, responses, and plugin options |

`openauth-plugins` consolidates Better Auth server plugin behavior into Rust
plugin modules. It is aligned with Better Auth 1.6.9 where observable server
contracts matter, while keeping OpenAuth's Rust server boundaries.

## Feature Parity

| Area | Status | Notes |
| --- | --- | --- |
| Plugin inventory | ✅ | Covers all Better Auth server plugin exports plus `@better-auth/api-key`; `additional_fields` is an OpenAuth server helper. |
| Access control | ✅ | Role, statement, and request authorization helpers covered by focused tests. |
| Additional fields server helper | 🎯 | OpenAuth-only helper around core user/session additional field schema; not counted as a Better Auth server plugin export. |
| Admin | ✅ | User/session management, impersonation, permissions, schema fields, and OpenAPI metadata are implemented. |
| Anonymous users | ✅ | Anonymous sign-in, deletion, custom identity callbacks, and link hooks are implemented. |
| API key | ⚠️ | Lifecycle, verification, metadata, sessions, org references, configuration, hashing, schema, and storage modes are implemented; pure secondary-storage listing has multi-process caveats. |
| Bearer sessions | ✅ | Authorization header parsing and session lookup behavior are covered. |
| CAPTCHA | ✅ | Server verify hooks and provider handlers are implemented. |
| Custom session | ✅ | Session response extension hooks and cookie behavior are implemented. |
| Device authorization | ✅ | Device code, decision, verification, token, options, and schema paths are implemented. |
| Email OTP | ⚠️ | OTP send/verify, password reset, hooks, storage, and additional fields are implemented; upstream has deeper edge-case coverage. |
| Generic OAuth | ✅ | Provider config, discovery, callback routes, token/userinfo hooks, PKCE, and provider helpers are implemented. |
| Have I Been Pwned | ✅ | k-anonymity range lookup, padding, and hash handling are implemented. |
| JWT | ✅ | JWKS, token, sign/verify endpoints, claims, schema options, and crypto adapter paths are implemented. |
| Last login method | ✅ | OAuth and credential method persistence plus session response metadata are implemented. |
| Magic link | ✅ | Sign-in, verify, token generation, failure redirects, and rate limits are implemented. |
| MCP | ✅ | OAuth-style metadata, registration, consent, token hardening, userinfo, and login resume paths are implemented. |
| Multi-session | ✅ | Signed per-session cookies, switching, revocation, max-session limiting, forged-cookie rejection, and sign-out cleanup are implemented. |
| OAuth proxy | ✅ | Callback rewriting, encrypted preview payloads, replay max-age, state cleanup, production passthrough, skip headers, custom secrets, and database-backed state are implemented. |
| One Tap | ⚠️ | Server callback and metadata are implemented; missing-email response shape intentionally differs. |
| One-time token | ✅ | Token generation, verification, session/user output, cookie-cache preservation, and expiry rejection are implemented. |
| OpenAPI | ✅ | Generated auth schemas and optional Scalar reference UI are implemented. |
| Organization | ⚠️ | Core org/member/invitation/team/session/access-control paths are implemented; hook ordering, dynamic policy, role merge, and team/member edge cases need ongoing parity tests. |
| Phone number | ✅ | OTP, sign-in, verification, password reset, hooks, schema, and rate limit paths are implemented. |
| SIWE | ✅ | Nonce, verify, wallet account linking, schema, and address handling are implemented. |
| Two-factor | ⚠️ | TOTP, OTP, backup codes, trust-device cookies, passwordless option, custom table, and storage paths are implemented; upstream has deeper edge-case coverage. |
| Username | ⚠️ | Sign-in, availability, normalization hooks, validation, and schema are implemented; upstream has more validation coverage. |
| `oidc-provider` | 🎯 | Replaced by the sibling `openauth-oauth-provider` crate. |
| SSO, SCIM, Stripe, Passkey, adapters | ➖ | Covered by sibling crates or out of scope here. |

## Test Coverage

| Surface | OpenAuth tests | Upstream tests | Notes |
| --- | ---: | ---: | --- |
| Mapped server plugin scope | 631 | 931 | Verify with `cargo nextest run -p openauth-plugins`. |
| Server module inventory | 26 | 25 | Upstream count is exported server plugins after excluding `test-utils` and replaced `oidc-provider`, plus `@better-auth/api-key`; Rust adds `additional_fields` as a server helper. |
| Server route literals | 139 | 132 | No upstream server-route candidates were missing after excluding replaced/non-server paths; Rust includes additional hardening/support endpoints. |
| API key | 53 | 176 | Rust covers lifecycle, verify, metadata, sessions, org refs, schema, storage, and configurations; upstream has broader matrix coverage. |
| Organization | 36 | 180 | Rust covers core routes, teams, session, limits, hooks, and additional fields; parity risk remains high due large upstream surface. |
| Email OTP | 32 | 73 | Rust covers send/verify, hooks, storage, server behavior, password reset, and additional fields. |
| Two-factor | 23 | 55 | Rust covers TOTP, OTP, backup codes, cookies, storage, and passwordless option. |
| Username | 12 | 33 | Rust covers flow, validation, and schema. |

## Intentional Differences

| Topic | Better Auth | OpenAuth | Why |
| --- | --- | --- | --- |
| Environment URL | `BETTER_AUTH_URL` | `OPENAUTH_URL` | Crate uses OpenAuth-specific runtime naming. |
| One Tap missing email | `200 { error }` | `400 EMAIL_NOT_AVAILABLE` | Missing auth identity data is treated as a failed server contract. |
| Serializable metadata | Exposes callback-driven plugin options | Omits closure/callback fields, preserves observable values | Runtime callbacks are not serializable metadata. |
| OAuth proxy payloads | Object transport | Rust-owned encrypted structs | Payload is OpenAuth-to-OpenAuth transport, not a public cross-implementation API. |
| Generic OAuth HTTP | Baseline outbound fetch behavior | SSRF-guarded default HTTP transport | Auth boundary should fail closed for private/internal targets. |
| API-key cache revalidation | Cache-first secondary storage | Optional DB revalidation for cache hits | Preserves compatibility by default while offering immediate revocation visibility. |
| Additional fields helper | Core user/session additional fields | Dedicated Rust server plugin helper | Gives Rust callers a plugin-shaped way to contribute schema/runtime metadata. |
| `oidc-provider` | Built-in plugin export | `openauth-oauth-provider` sibling crate | OAuth/OIDC provider behavior is large enough to own separately. |

## Open Gaps / Risks

| ID | Gap | Severity | Notes |
| --- | --- | --- | --- |
| G1 | Test depth is below upstream | Medium | 631 Rust tests vs 931 mapped upstream declarations; focus next on organization, API key, email OTP, two-factor, and username. |
| G2 | Organization behavior is broad and complex | High | Async hook ordering, dynamic organization creation policy, role merge semantics, and team/member edges need continued parity tests. |
| G3 | API-key pure secondary-storage listing is process-local | Medium | Multi-process deployments need atomic secondary-storage collection semantics or database fallback for `/api-key/list`. |
| G4 | Plugin rate-limit knobs are not uniformly public | Medium | Implemented for selected surfaces; check upstream before exposing new public options. |

## Hardening Notes

- Keep Generic OAuth and OAuth proxy outbound requests on SSRF-guarded HTTP transports.
- Prefer explicit errors at auth boundaries; avoid silent fallbacks for malformed
  cookies, forged API keys, expired OTPs, or invalid OAuth state.
- Use database fallback or an atomic secondary-storage backend for multi-process
  API-key deployments.
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
5. Verify with `cargo nextest run -p openauth-plugins`.

| Upstream | Rust |
| --- | --- |
| `packages/better-auth/src/plugins/index.ts` | `crates/openauth-plugins/src/lib.rs` |
| `packages/better-auth/src/plugins/<plugin>/` | `crates/openauth-plugins/src/<plugin>/` |
| `packages/api-key/src/` | `crates/openauth-plugins/src/api_key/` |
| `packages/better-auth/src/plugins/**/*.test.ts` | `crates/openauth-plugins/tests/<plugin>/` |
| `packages/api-key/src/*.test.ts` | `crates/openauth-plugins/tests/api_key/` |
| `packages/better-auth/package.json` plugin exports | `PLUGIN_IDS` and public Rust modules |
| OpenAuth-only helper | `crates/openauth-plugins/src/additional_fields/` |
| Excluded upstream paths | `test-utils`, `oidc-provider`, and non-server helper paths |

## Links

- [README](./README.md)
- [Upstream parity index](../../docs/parity/README.md)
