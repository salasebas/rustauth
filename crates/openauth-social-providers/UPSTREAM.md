# Upstream parity — openauth-social-providers

Better Auth **1.6.9** behavioral reference for contributors and parity audits.
OpenAuth is inspired by Better Auth; it is not a line-by-line port.

| Field | Value |
| --- | --- |
| **Parity pin** | [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md) |
| **Upstream package** | `@better-auth/core` |
| **Upstream path** | `reference/upstream-src/1.6.9/repository/packages/core/src/social-providers/` |
| **Rust crate** | `crates/openauth-social-providers/` |
| **Parity level** | **High** — all in-scope server provider gaps resolved; remaining differences are intentional Rust API or hardening choices |
| **Scope** | Server-side provider definitions (URLs, scopes, profile mapping, token auth). Out of scope: HTTP routes (`/sign-in/social`, callbacks) → [`openauth-core`](../openauth-core/UPSTREAM.md); OAuth client primitives → [`openauth-oauth`](../openauth-oauth/UPSTREAM.md). |

## Summary

All **35** upstream built-in social providers are implemented with matching
`PROVIDER_IDS` order. Authorize/token URLs, default scopes, PKCE defaults, and
profile field mapping align with Better Auth for the in-scope server provider
surface. The Facebook opaque-token and Twitch JWKS differences are intentional
fail-closed hardening. OpenAuth adds **326** provider-focused Rust tests where
upstream ships **0** in `social-providers/`. Provider hook overrides use typed
Rust options on **10/35** providers instead of cloning TypeScript's global
callback fields into every provider option struct; this is an intentional
Rust API boundary, not an open parity gap.

Status symbols are defined in the [parity index](../../docs/parity/README.md#status-symbols).

## Feature parity

| Area | Status | Notes |
| --- | --- | --- |
| Provider registry (`PROVIDER_IDS`) | ✅ High | All **35** providers; order matches upstream catalog |
| Wire parity (URLs, scopes, defaults) | ✅ High | All **35** providers; Discord/Roblox `+` scopes and Railway optional PKCE aligned |
| Profile → user mapping | ✅ High | Per-provider normalization; static mappers on all providers |
| `mapProfileToUser` / `getUserInfo` overrides | 🎯 Intentional Rust API | Typed callbacks on **10/35**: Atlassian, Cognito, GitHub, Hugging Face, Linear, PayPal, Polar, Salesforce, Twitter/X, Vercel; shared `ProviderOptions` stays serializable and route/runtime customization goes through typed provider APIs |
| `SocialOAuthProvider` trait | 🎯 Extension | Async trait via `openauth-oauth`; replaces upstream sync provider functions |
| Provider unit / wire tests | 🎯 Extension | **326** Rust tests; upstream has **0** under `social-providers/` |
| Facebook opaque-token verify | 🎯 Hardened | Stricter than upstream for safer server-side token acceptance |
| Twitch JWKS verify | 🎯 Hardened | Stricter than upstream for safer server-side token acceptance |
| Social sign-in HTTP routes | ➖ Out of scope | `/sign-in/social`, callbacks, account linking → `openauth-core` |
| Social E2E (`social.test.ts`) | ➖ Out of scope | Route-level E2E owned by `openauth-core`, not this crate |

## Test coverage

| Surface | OpenAuth (Rust) | Upstream | Notes |
| --- | --- | --- | --- |
| Provider wire + mapping tests | **326** | **0** in `social-providers/` | `rg '#\[(tokio::)?test\]' crates/openauth-social-providers` |
| Per-provider integration files | **35** files under `tests/` | — | One file per provider (e.g. `tests/github.rs`) |
| Module / registry smoke | **5** in `tests/module_structure.rs` | — | `PROVIDER_IDS` and export surface |
| Social route E2E | — | `social.test.ts` | Mapped to `openauth-core/tests/api/routes/social_oauth.rs` |

```bash
cargo nextest run -p openauth-social-providers
```

## Intentional differences

| Topic | Better Auth 1.6.9 | OpenAuth | Why |
| --- | --- | --- | --- |
| Hook overrides | Global `ProviderOptions` callbacks on every provider | Typed `map_profile_to_user` on **10/35** providers | Idiomatic Rust; explicit opt-in per provider |
| Provider interface | Synchronous provider functions | Async `SocialOAuthProvider` trait | Rust async I/O and trait objects |
| Facebook token path | Accepts opaque tokens with lighter verification | Stricter opaque-token verification | Fail-closed server-side token acceptance |
| Twitch token path | JWKS verification aligned with upstream leniency | Stricter JWKS verification | Safer validation of provider-issued tokens |
| Error handling | Thrown JS errors | Typed `OAuthError` | Explicit Rust error boundaries |

## Resolved gaps and residual risks

There are no unresolved in-scope server-provider parity gaps for this crate.
Items below are intentional hardening choices, Rust API differences,
sibling-crate scope, or operational risks that do not require implementation in
`openauth-social-providers`.

| ID | Gap / risk | Status | Notes |
| --- | --- | --- | --- |
| SP-1 | Facebook/Twitch verification stricter than upstream | 🎯 Hardened | Intentional fail-closed token acceptance; may reject edge-case tokens upstream accepts |
| SP-2 | `mapProfileToUser` / `getUserInfo` not on all **35** providers | 🎯 Intentional Rust API | Shared `ProviderOptions` is serializable OAuth config, not a callback bag; typed hooks are exposed only where this crate has an explicit provider-specific API |
| SP-3 | OAuth route and account-linking E2E | ➖ Sibling scope | Owned by `openauth-core`; this crate only owns provider definitions and runtime provider implementations |
| SP-4 | No live provider conformance matrix | ➖ Operational risk | Wire contracts are tested locally; live IdP smoke requires credentials and belongs in periodic integration operations, not upstream source parity |

## Hardening notes

- Outbound provider HTTP uses `openauth-oauth` SSRF-aware clients where applicable.
- Token verification paths (Facebook opaque, Twitch JWKS) fail closed on malformed or untrusted tokens.
- Provider secrets live in `ProviderOptions` / typed option structs; avoid logging raw tokens or profile payloads.
- Multi-instance deployments share no in-process provider state; each node validates tokens independently.

## Upstream lookup

1. Read the pin in `reference/upstream-better-auth/VERSION.md`.
2. Run `./scripts/fetch-upstream-better-auth.sh` if `reference/upstream-src/` is missing.
3. Open `reference/upstream-src/1.6.9/repository/packages/core/src/social-providers/`.
4. Map upstream → Rust:

| Upstream | Rust |
| --- | --- |
| `social-providers/index.ts` (registry) | `src/lib.rs` (`PROVIDER_IDS`, module exports) |
| `social-providers/{id}.ts` | `src/{id}.rs` (options, wire constants) |
| Provider runtime / `getUserInfo` | `src/runtime/{id}.rs` (when split) |
| `social-providers/*.test.ts` | — (none upstream); `tests/{id}.rs` |
| `better-auth` `social.test.ts` | `openauth-core/tests/api/routes/social_oauth.rs` |

5. Add a failing Rust test before behavior changes; match wire URLs, scopes, defaults, and profile fields—not TypeScript types.

## Related docs

- [Crate README](./README.md) — usage and quick start
- [Parity index](../../docs/parity/README.md)
- [`openauth-oauth`](../openauth-oauth/UPSTREAM.md) — OAuth client primitives consumed by providers
- [`openauth-core`](../openauth-core/UPSTREAM.md) — social sign-in routes and account linking
