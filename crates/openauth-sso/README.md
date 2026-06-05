# openauth-sso

Enterprise single sign-on plugin for OpenAuth-RS.

## What It Is

`openauth-sso` is the plugin-level enterprise SSO surface. It stores SSO
providers, exposes SSO management and login routes, consumes external OIDC
providers, optionally exposes SAML compatibility routes, verifies domains, and
links/provisions users and organizations.

Use `openauth-oidc` directly only when you need low-level OIDC discovery/config
helpers. Use `openauth-oauth-provider` when your OpenAuth server should issue
OAuth/OIDC tokens.

## What It Provides

- Provider registration, lookup, update, and deletion.
- OIDC sign-in and callback routes with discovery support.
- Optional SAML metadata, ACS, SLO, and logout compatibility routes.
- Domain verification and organization assignment helpers.
- Account linking and profile mapping.
- Audit hooks and rate-limit rules for SSO routes.

## Quick Start

```rust
use openauth::OpenAuth;
use openauth_sso::{sso, SsoOptions};

let auth = OpenAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .base_url("https://app.example.com/api/auth")
    .plugin(sso(SsoOptions::default()))
    .build()?;
# let _ = auth;
# Ok::<(), Box<dyn std::error::Error>>(())
```

The default feature set enables OIDC. Enable the `saml` feature only when you
are testing SAML compatibility and understand the current SAML limitations.

## Feature Flags

- `oidc`: external OIDC IdP login support. Enabled by default.
- `saml`: SAML metadata, ACS, SLO, and logout routes.
- `saml-signed`: forwards the explicit signed-SAML feature surface.

## SAML Status

SAML support is experimental. Unsigned compatibility flows are covered, but
signed responses, signed logout messages, outbound signing, and encrypted
assertions are not a production-ready path yet. Prefer OIDC for new IdP
integrations.

## Status

Experimental beta. OIDC is the recommended path. SAML remains WIP until XML
signature/encryption support is backed by an auditable implementation.

## Upstream parity (Better Auth 1.6.9)

Parity pin: [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md)
(commit `f484269`). Upstream package: `@better-auth/sso` at `packages/sso/`.
OpenAuth splits OIDC discovery/types into `openauth-oidc` and SAML into
`openauth-saml` (feature `saml`); this crate owns HTTP routes, DB storage,
callbacks, and provisioning. TypeScript `ssoClient()` is N/A (server-only).

**Parity level (OIDC E2E):** High for provider registration, sign-in (email,
domain, `providerId`), callback with ID token and UserInfo, shared `redirectURI`
and `/sso/callback`, `defaultSSO`, and `provisionUser` first/every login.
Organization slug sign-in is partial (requires `organization` plugin). SAML is
documented separately and remains experimental.

**Test coverage:** All **22** scenarios in upstream `oidc.test.ts` are covered
across `tests/sso/endpoints/` plus `oidc_upstream_parity.rs` (six explicit
upstream-alignment tests added June 2026). OIDC discovery has **71** upstream
Vitest cases in `openauth-oidc`. Run: `cargo nextest run -p openauth-sso --test sso`.

**Open gaps:** SAML production readiness (signing/encryption); duplicate
maintenance between `tests/sso/oidc.rs` and `openauth-oidc/tests/flow.rs`; no
typed browser client. SCIM and full SAML parity live in sibling crates.

### Upstream lookup

1. Pin: [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md).
2. SSO plugin: `reference/upstream-src/<version>/repository/packages/sso/` (fetch via `./scripts/fetch-upstream-better-auth.sh`).
3. OIDC discovery/types: [`openauth-oidc`](../openauth-oidc/README.md#upstream-lookup); SAML SP XML:
   [`openauth-saml`](../openauth-saml/README.md#upstream-lookup).
4. Tests: `packages/sso/src/oidc.test.ts` → `cargo nextest run -p openauth-sso --test sso`.

## Links

- [Root README](../../README.md)
- [openauth-oidc](../../crates/openauth-oidc/README.md) — discovery and OIDC types
- [Repository](https://github.com/sebasxsala/openauth-rs)
