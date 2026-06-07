# openauth-oidc upstream parity

| Field | Value |
| --- | --- |
| Parity pin | Better Auth `1.6.9` (`reference/upstream-better-auth/VERSION.md`, commit `f484269`) |
| Upstream package/path | `@better-auth/sso` → `reference/upstream-src/1.6.9/repository/packages/sso/` (primary helper surface: `src/oidc/`) |
| Rust crate | `openauth-oidc` |
| Parity level | High for low-level OIDC relying-party helpers |
| Scope | Server-side discovery, endpoint validation, provider config types, runtime hydration, and redirect URI helpers consumed by `openauth-sso` |

## Summary

`openauth-oidc` matches the Better Auth 1.6.9 server-side OIDC discovery helper surface where it belongs in OpenAuth: validating and hydrating external IdP configuration before `openauth-sso` uses it. It intentionally excludes SSO routes, provider storage, ID token validation, UserInfo exchange, account linking, sessions, and organization provisioning. Those server-side flows are audited as `openauth-sso` boundaries below.

Status symbols are defined in the [parity index](../../docs/parity/README.md#status-symbols).

## Feature Parity

| Area | Status | Notes |
| --- | --- | --- |
| Discovery URL, fetch, and validation | ✅ Implemented | Preserves issuer paths, uses `reqwest::Client`, enforces a 10 second timeout, and requires `issuer`, `authorization_endpoint`, `token_endpoint`, and `jwks_uri`. |
| Issuer and endpoint normalization | ✅ Implemented | Rejects issuer mismatch, normalizes one trailing slash, and resolves relative endpoints against the issuer origin/path. |
| Trusted-origin checks | ✅ Implemented | Validates discovery, required endpoints, optional endpoints, and stored/manual endpoints when `openauth-sso` enables strict manual endpoint origin checks. |
| Runtime discovery | ✅ Implemented | Hydrates missing authorization, token, and JWKS endpoints for stored configs; `SignIn` and `Callback` currently share the same required endpoint set. |
| Token endpoint auth selection | ✅ Implemented | Supports `client_secret_basic` and `client_secret_post`; defaults to basic like upstream. |
| Provider config and mapping types | ✅ Implemented | Rust structs mirror OIDC config, claim mapping, scopes, PKCE, and override fields; applying claim mapping is `openauth-sso` callback scope. |
| Public discovery helper exports | ✅ Implemented | Exports `REQUIRED_DISCOVERY_FIELDS`, `validate_discovery_url`, `fetch_discovery_document`, `validate_discovery_document`, `normalize_discovery_urls`, and `select_token_endpoint_authentication` to match upstream `packages/sso/src/oidc/index.ts`. |
| Secret handling | 🎯 Intentional difference | `SecretString` redacts in `Debug` while still serializing for provider persistence. |
| Revocation/end-session/introspection endpoints | 🎯 Intentional difference | Upstream normalizes these during discovery but does not persist them; OpenAuth models and hydrates them as a server-side superset. |
| OIDC provider registration | ➖ Out of scope | `packages/sso/src/routes/sso.ts` maps to `openauth-sso`, which calls this crate for discovery. |
| OIDC sign-in and callbacks | ➖ Out of scope | Authorization URL generation, token exchange, ID token validation, UserInfo, sessions, and redirects are `openauth-sso` scope. |
| Provider management routes | ➖ Out of scope | `packages/sso/src/routes/providers.ts` maps to `openauth-sso`; this crate only defines reusable config/discovery primitives. |
| SSO schema and hooks | ➖ Out of scope | Plugin schema, SAML sign-out hooks, and organization hooks are server-side `openauth-sso` behavior. |

## Test Coverage

| Surface | OpenAuth tests | Upstream tests | Notes |
| --- | --- | --- | --- |
| OIDC discovery helpers | 33 unit tests in `src/discovery.rs` plus 3 tests in `tests/flow.rs` | 71 `it`/`test` declarations in `packages/sso/src/oidc/discovery.test.ts` | Core upstream discovery scenarios are covered; verify with `cargo nextest run -p openauth-oidc`. |
| OIDC server routes | Covered in `openauth-sso` route tests | 22 declarations in `packages/sso/src/oidc.test.ts` | Registration, sign-in, callback, default SSO, shared redirect, provisioning; verify with `cargo nextest run -p openauth-sso --test sso`. |

## Intentional Differences

| Topic | Better Auth | OpenAuth | Why |
| --- | --- | --- | --- |
| HTTP client ownership | Uses `betterFetch` internally. | Requires a caller-supplied `reqwest::Client`. | Lets applications and `openauth-sso` own proxy, DNS, timeout, and SSRF policy. |
| Origin validation timing | Validates discovery and normalized endpoints. | Revalidates after merging caller overrides and exposes stored-endpoint validation for `openauth-sso`. | Prevents an override or manual config from bypassing trust policy. |
| Secret debug output | `clientSecret` is stored as a plain provider config value. | `SecretString` redacts in `Debug`. | Avoids accidental log disclosure in Rust applications. |
| Optional metadata | Persists only endpoints used by Better Auth's SSO flow. | Models revocation, end-session, and introspection endpoints too. | Keeps discovered IdP metadata available without changing route behavior. |
| SSO plugin config type | Uses one `OIDCConfig` interface in the SSO package. | `openauth-sso` has its own `OidcConfig` and converts to/from `openauth_oidc::OidcConfig`. | Keeps the helper crate usable without depending on plugin internals. |
| Request scopes | Discovery exposes `scopes_supported`; request scopes are chosen in routes. | `HydratedOidcDiscovery` exposes `scopes_supported`, but `OidcConfig.scopes` is not auto-mutated. | Preserves explicit caller scopes; default request scopes live in `openauth-sso`. |
| Unsupported token auth methods | Falls back to `client_secret_basic`; `unsupported_token_auth_method` exists but is not thrown in 1.6.9. | Same fallback. | Preserves Better Auth 1.6.9 behavior; stricter rejection would be a behavior change. |
| Private-key JWT / mTLS client auth | Not implemented; falls back to `client_secret_basic`. | Same fallback via `select_token_endpoint_authentication`. | Matches Better Auth 1.6.9; enterprise IdP methods are a future extension, not a 1.6.9 gap. |
| SSRF policy ownership | Uses internal `betterFetch` without caller-controlled origin policy. | Caller supplies `reqwest::Client` and `is_trusted_origin`; `openauth-sso` wires private-IP checks. | Rust auth boundary design; production safety depends on restrictive origin predicates and HTTP client policy. |

## Open Gaps / Risks

No open in-scope gaps remain for Better Auth 1.6.9 OIDC discovery helpers. Route-level SSO behavior, account linking, and provisioning are tracked in `openauth-sso/UPSTREAM.md`.

## Hardening Notes

- Treat the trusted-origin predicate as part of the auth boundary; private, loopback, link-local, metadata-service, and internal DNS targets should fail closed.
- Use bounded HTTP timeouts and avoid proxy/DNS behavior that can route discovery calls into private infrastructure.
- Remember the full SSRF guard is split: `openauth-oidc` accepts an origin predicate, while `openauth-sso` wires private-IP checks for discovery, token, JWKS, and UserInfo requests.
- Keep `client_secret` out of logs and API responses; `SecretString` only redacts formatting, not serialization.
- Preserve issuer mismatch checks before using any discovered endpoint for token or JWKS operations.

## Upstream Lookup

1. Read `reference/upstream-better-auth/VERSION.md`.
2. If `reference/upstream-src/1.6.9/repository/` is missing, run `./scripts/fetch-upstream-better-auth.sh`.
3. Inspect `packages/sso/package.json`, `packages/sso/src/index.ts`, `packages/sso/src/oidc/*.ts`, `packages/sso/src/routes/sso.ts`, `packages/sso/src/routes/providers.ts`, `packages/sso/src/routes/schemas.ts`, `packages/sso/src/routes/domain-verification.ts`, `packages/sso/src/linking/`, `packages/sso/src/types.ts`, and `packages/sso/src/utils.ts`.
4. Count tests with `rg '^\s*(it|test)\(' .../packages/sso/src/oidc/discovery.test.ts` and `rg '#\[(test|tokio::test)\]' crates/openauth-oidc`.
5. Verify with `cargo nextest run -p openauth-oidc`.

| Upstream | Rust |
| --- | --- |
| `packages/sso/src/oidc/index.ts` | `src/lib.rs` re-exports; `openauth-sso` also re-exports this crate as `openauth_sso::oidc` with the `oidc` feature |
| `packages/sso/src/oidc/discovery.ts` | `src/discovery.rs` |
| `packages/sso/src/oidc/types.ts` `REQUIRED_DISCOVERY_FIELDS` | `discovery::REQUIRED_DISCOVERY_FIELDS` |
| `packages/sso/src/oidc/types.ts` (config/error types) | `src/discovery.rs`, `src/options.rs` |
| `packages/sso/src/oidc/errors.ts` | `OidcDiscoveryError::code()` / `status()` plus `openauth-sso/src/routes/registration.rs` error responses |
| `packages/sso/src/types.ts` `OIDCConfig` / `OIDCMapping` | `OidcConfig`, `OidcProfileMapping` in `src/options.rs` |
| `packages/sso/src/routes/sso.ts` `getOIDCRedirectURI` | `src/flow.rs`, `tests/flow.rs` |
| `packages/sso/src/routes/sso.ts` registration/sign-in/callback | `openauth-sso/src/routes/registration.rs`, `sign_in.rs`, `oidc.rs`; uses this crate through `openauth_oidc` |
| `packages/sso/src/routes/providers.ts` provider management | `openauth-sso` routes; this crate has no DB/provider route layer |
| `packages/sso/src/routes/schemas.ts` update schemas | `openauth-sso/src/routes/provider_update.rs` plus `OidcConfig` data shape |
| `packages/sso/src/routes/domain-verification.ts` | `openauth-sso` domain verification routes; no helper surface here |
| `packages/sso/src/linking/` | `openauth-sso` account/organization provisioning; no helper surface here |
| `packages/sso/src/index.ts` schema/hooks/endpoints | `openauth-sso`; OIDC helper re-exports map to this crate |
| `packages/sso/src/oidc/discovery.test.ts` | Unit tests in `src/discovery.rs` |
| `packages/sso/src/oidc.test.ts` | `openauth-sso/tests/sso/endpoints/oidc_upstream_parity.rs`, `registration/discovery.rs`, `sign_in/defaults_discovery.rs`, and `oidc_callback/` |
| `packages/sso/src/providers.test.ts` | Provider management tests in `openauth-sso`; includes OIDC config sanitization |
| `packages/sso/src/domain-verification.test.ts` | Domain verification tests in `openauth-sso` |
| `packages/sso/src/utils.test.ts` | Domain matching utility tests in `openauth-sso` |
| `packages/sso/src/constants.ts`, `routes/helpers.ts`, `saml-state.ts`, `saml/`, `samlify.ts`, `saml.test.ts`, `version.ts` | SAML-only or package metadata; no OIDC helper surface |

Links: [README](./README.md), [Upstream parity index](../../docs/parity/README.md).
