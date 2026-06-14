# Upstream parity — rustauth-sso

Better Auth **1.6.9** behavioral reference for contributors and parity audits.
RustAuth is inspired by Better Auth; it is not a line-by-line port.

| Field | Value |
| --- | --- |
| **Parity pin** | [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md) |
| **Upstream package** | `@better-auth/sso` |
| **Upstream path** | `reference/upstream-src/1.6.9/repository/packages/sso/` |
| **Rust crate** | `crates/rustauth-sso/` |
| **Parity level** | High (OIDC E2E, SAML routes, org-aware sign-in); ⚠️ production SAML depends on signed feature + IdP smoke |
| **Scope** | Server-side SSO plugin: routes, storage, callbacks, provisioning. Low-level OIDC helpers → [`rustauth-oidc`](../rustauth-oidc/UPSTREAM.md); SAML XML/crypto → [`rustauth-saml`](../rustauth-saml/UPSTREAM.md); SCIM → [`rustauth-scim`](../rustauth-scim/UPSTREAM.md). TypeScript `ssoClient()` is ➖ N/A (server-only). |

## Summary

`rustauth-sso` is the Better Auth `sso` plugin surface in Rust: provider CRUD,
OIDC sign-in/callback, optional SAML HTTP routes, domain verification, account
linking, organization assignment, audit hooks, and rate limits. It re-exports
`rustauth_oidc` and `rustauth_saml` under feature flags for convenience, but
owns the `AuthPlugin`, `sso_providers` schema, and HTTP boundaries. OIDC
end-to-end behavior matches upstream `oidc.test.ts` closely; SAML route behavior
is covered with signed/encrypted fixture tests behind the `saml` feature.

Status symbols are defined in the [parity index](../../docs/parity/README.md#status-symbols).

## Feature parity

| Area | Status | Notes |
| --- | --- | --- |
| Provider registration (`/sso/register`) | ✅ High | Discovery, manual endpoints, validation, limits |
| Provider list/get/update/delete | ✅ High | Mirrors `providers.ts` routes |
| OIDC sign-in (`/sign-in/sso`) | ✅ High | Email domain, `providerId`, `defaultSSO`, PKCE |
| OIDC callback (`/sso/callback`, `/sso/callback/:providerId`) | ✅ High | Shared redirect URI, ID token + UserInfo, linking |
| `provisionUser` (first / every login) | ✅ High | Callback provisioning hooks |
| Domain verification | ✅ High | Request + verify TXT; gates SAML sign-in |
| Account linking / profile mapping | ✅ High | Normalized profile + org assignment helpers; real organization plugin installs provision through member hooks/limits/role validation |
| Organization slug sign-in | ✅ High | Resolves provider by organization slug when the `organization` plugin is installed; email/domain/`providerId` remain available without it |
| SAML metadata / ACS / SLO / logout | ✅ High | Metadata, RelayState, ACS, replay, signed/encrypted ACS, SLO state/session cleanup, logout routes |
| Audit events + rate limits | ✅ High | Per-route rules for register, callback, SAML, domain |
| `ssoClient()` browser helper | ➖ N/A | Upstream client-only; RustAuth is server-only |
| SCIM provisioning | ➖ N/A | Lives in `rustauth-scim` |

### Route inventory (server)

| Route | Upstream | Feature |
| --- | --- | --- |
| `POST /sso/register` | `routes/sso.ts` | always |
| `POST /sign-in/sso` | `routes/sso.ts` | `oidc` / `saml` |
| `GET /sso/callback`, `GET /sso/callback/:providerId` | `routes/sso.ts` | `oidc` |
| `GET /sso/providers`, `GET /sso/get-provider` | `routes/providers.ts` | always |
| `POST /sso/update-provider`, `POST /sso/delete-provider` | `routes/providers.ts` | always |
| `GET /sso/saml2/sp/metadata?providerId=...` | `routes/sso.ts` | `saml` |
| `GET/POST /sso/saml2/callback/:providerId`, `POST /sso/saml2/sp/acs/:providerId` | `routes/sso.ts` | `saml` |
| `GET/POST /sso/saml2/sp/slo/:providerId`, `GET /sso/saml2/logout/:providerId` | `routes/sso.ts` | `saml` |
| `POST /sso/request-domain-verification`, `POST /sso/verify-domain` | `routes/domain-verification.ts` | optional |

## Test coverage

| Surface | RustAuth (Rust) | Upstream | Notes |
| --- | --- | --- | --- |
| Integration tests (`--test sso`) | 326 tests with `--features saml` | — | `cargo nextest run -p rustauth-sso --features saml --test sso` |
| OIDC E2E (`oidc.test.ts`) | 22 scenarios covered + 6 in `oidc_upstream_parity.rs` | 22 `it()` | Explicit upstream-alignment module |
| OIDC discovery helpers | — (in `rustauth-oidc`) | 71 `it()` in `oidc/discovery.test.ts` | See [`rustauth-oidc`](../rustauth-oidc/UPSTREAM.md) |
| SAML routes (`saml.test.ts`) | Broad coverage under `tests/sso/endpoints/saml/` | 108 `it()` | Run with `--features saml` |
| Provider management | `providers.rs`, `provider_update.rs`, `registration/` | 40 `it()` in `providers.test.ts` | |
| Domain verification | `domain_verification/` | 19 `it()` | |
| Org assignment / linking | `linking.rs`, `non_sso_linking.rs` | 8 `it()` in `linking/org-assignment.test.ts` | |
| Domain utilities | `linking.rs` | 21 `it()` in `utils.test.ts` | |

```bash
cargo nextest run -p rustauth-sso --test sso
cargo nextest run -p rustauth-sso --features saml --test sso   # SAML routes
```

## Intentional differences

| Topic | Better Auth 1.6.9 | RustAuth | Why |
| --- | --- | --- | --- |
| Crate split | Single `@better-auth/sso` package | `rustauth-sso` + `rustauth-oidc` + `rustauth-saml` | Idiomatic Rust modules; reuse helpers without plugin coupling |
| Re-exports | N/A | `rustauth_sso::oidc`, `rustauth_sso::saml` under features | Convenience for plugin users; parity audited per sibling crate |
| SAML crypto default | `samlify` always available | Unsigned-only unless `saml-signed` | Fail closed when verification/decryption unavailable |
| Secrets | Plain strings in provider config | `SecretString` redacts in `Debug` | Avoid accidental log disclosure |
| HTTP client | Internal `betterFetch` | Caller-owned `reqwest::Client` + origin predicates | SSRF and timeout policy owned by the application |
| Browser client | `ssoClient()` export | None | Server-only Rust boundary |
| Error surface | TypeScript union codes | `SsoErrorDescriptor` + HTTP status mapping | Explicit Rust error taxonomy |
| Organization provisioning implementation | Direct membership writes | Delegates to `rustauth-plugins::organization` when the real plugin is installed, with a fallback only for minimal test stubs | Keeps SSO assignment consistent with organization hooks and limits. |

## Open gaps and risks

| ID | Gap / risk | Severity | Notes |
| --- | --- | --- | --- |
| SSO-1 | SAML smoke not in CI | Med | Manual `scripts/saml-smoke.sh`; see [SMOKE-SAML.md](./SMOKE-SAML.md) |
| SSO-2 | SSRF policy is application-configurable | High | Discovery/token/JWKS/UserInfo use guarded clients by default; production must keep private endpoint access disabled unless explicitly required |
| SSO-3 | Duplicate OIDC test maintenance | Low | Some overlap remains between `tests/sso/oidc.rs` and `rustauth-oidc/tests/flow.rs` |
| SSO-4 | No typed browser SSO client | Low | Expected for server-only crate |

Closed/stale audit items: organization slug sign-in is implemented for installs
that include the `organization` plugin; SAML metadata, ACS, RelayState,
assertion replay, signed/encrypted ACS, SLO, logout, session cleanup, and
provider fixtures are covered by `tests/sso/endpoints/saml/`; organization
assignment now uses the real organization plugin provisioning semantics when
available; SSRF-sensitive
OIDC calls use trusted-origin validation and guarded HTTP clients by default.

## Hardening notes

- Rate-limit registration, domain verification, OIDC callback, and SAML ACS/SLO routes (`SsoRateLimitOptions`).
- Reject discovery/token/JWKS/UserInfo calls to private or untrusted origins; wire a restrictive origin predicate in production.
- SAML: default build rejects signed/encrypted IdP messages without `saml-signed`; do not enable unsigned SAML in production.
- Domain verification must succeed before SAML sign-in when enabled; DNS TXT resolver is injectable for tests.
- Multi-instance: provider store and replay/state keys must share storage; assertion replay and logout state use prefixed keys aligned with upstream.
- Keep `client_secret` and SAML keys out of logs and API responses.

## Upstream lookup

1. Read the pin in `reference/upstream-better-auth/VERSION.md`.
2. Run `./scripts/fetch-upstream-better-auth.sh` if `reference/upstream-src/` is missing.
3. Open `reference/upstream-src/1.6.9/repository/packages/sso/`.
4. Map upstream → Rust:

| Upstream | Rust |
| --- | --- |
| `src/index.ts` (plugin, schema, hooks) | `src/lib.rs`, `src/schema.rs`, `src/hooks.rs` |
| `src/routes/sso.ts` | `src/routes/sign_in.rs`, `oidc.rs`, `saml_*.rs`, `slo.rs` |
| `src/routes/providers.ts` | `src/routes/providers.rs`, `provider_update.rs` |
| `src/routes/domain-verification.ts` | `src/routes/domain_verification.rs` |
| `src/routes/registration.rs` | `src/routes/registration.rs` |
| `src/linking/` | `src/linking.rs`, `src/org.rs`, `src/hooks.rs` |
| `src/oidc/` | [`rustauth-oidc`](../rustauth-oidc/UPSTREAM.md); re-exported as `rustauth_sso::oidc` |
| `src/saml/`, `samlify.ts` | [`rustauth-saml`](../rustauth-saml/UPSTREAM.md); re-exported as `rustauth_sso::saml` |
| `src/oidc.test.ts` | `tests/sso/endpoints/oidc_upstream_parity.rs`, `oidc_callback/`, `sign_in/` |
| `src/saml.test.ts` | `tests/sso/endpoints/saml/` |
| `src/providers.test.ts` | `tests/sso/endpoints/providers.rs`, `provider_update.rs`, `registration/` |
| `src/domain-verification.test.ts` | `tests/sso/endpoints/domain_verification/` |

5. Add a failing Rust test before behavior changes; match HTTP status, error codes, and DB side effects—not TypeScript types.

## Related docs

- [Crate README](./README.md) — usage and quick start
- [SAML smoke checklist](./SMOKE-SAML.md) — manual signed/encrypted validation
- [rustauth-oidc UPSTREAM](../rustauth-oidc/UPSTREAM.md) — discovery and OIDC types
- [rustauth-saml UPSTREAM](../rustauth-saml/UPSTREAM.md) — SAML helpers and crypto
- [Parity index](../../docs/parity/README.md)
