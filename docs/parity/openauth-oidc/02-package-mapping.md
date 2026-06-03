# 02 — Mapeo de paquetes y archivos

## 1. Relación npm ↔ crates

| Capa | Upstream (BA 1.6.9) | OpenAuth |
| --- | --- | --- |
| Módulo discovery + tipos OIDC | `packages/sso/src/oidc/` | `crates/openauth-oidc/src/` |
| Barrel export | `packages/sso/src/oidc/index.ts` | `crates/openauth-oidc/src/lib.rs` |
| Errores HTTP (APIError) | `packages/sso/src/oidc/errors.ts` | `openauth-sso` / `openauth-core` (no en `openauth-oidc`) |
| Redirect URI | `packages/sso/src/routes/sso.ts` → `getOIDCRedirectURI()` (privado) | `crates/openauth-oidc/src/flow.rs` → `oidc_redirect_uri()` (público) |
| Tipos `OIDCConfig` / mapping | `packages/sso/src/types.ts` | `crates/openauth-oidc/src/options.rs` + re-export en `openauth-sso/src/options.rs` |
| Flujo OIDC HTTP | `packages/sso/src/routes/sso.ts` | `crates/openauth-sso/src/routes/oidc.rs`, `sign_in.rs`, `registration.rs`, … |
| Cliente | `packages/sso/src/client.ts` | **No portado** |

**Política de empaquetado:** 1 submódulo upstream (`oidc/`) → **1 crate** Rust. El resto de `@better-auth/sso` → `openauth-sso` + `openauth-saml`.

## 2. Mapa archivo ↔ módulo

| Upstream | OpenAuth | Notas |
| --- | --- | --- |
| `oidc/discovery.ts` | `src/discovery.rs` | Lógica principal |
| `oidc/types.ts` | `discovery.rs` (documento) + `options.rs` (config) | `DiscoveryError` → `OidcDiscoveryError` |
| `oidc/errors.ts` | — | Ver `openauth-sso` para mapeo a errores API |
| `oidc/index.ts` | `lib.rs` | Re-exports |
| `oidc/discovery.test.ts` | `discovery.rs` (`mod tests`) + `tests/flow.rs` | 71 vs **26** tests |
| `types.ts` (`OIDCConfig`, `OIDCMapping`) | `options.rs` | OpenAuth añade endpoints opcionales |
| `routes/sso.ts` (OIDC) | `openauth-sso/src/routes/oidc.rs` | Ver [06-boundary-sso.md](./06-boundary-sso.md) |
| `oidc.test.ts` | `openauth-sso/tests/sso/**/oidc*` | E2E / integración |

## 3. Dependencias

| Upstream | OpenAuth (`openauth-oidc`) |
| --- | --- |
| `@better-fetch/fetch` (discovery HTTP) | `reqwest` (inyectado por el caller) |
| `better-auth` / URL parsing implícito | `url`, `openidconnect::IssuerUrl` (solo validación issuer) |
| `zod` (en rutas SSO, no en `oidc/`) | `serde` / `serde_json` |
| — | `thiserror`, `http` (status sugerido en errores) |

## 4. Features Cargo

| Crate | Features OIDC |
| --- | --- |
| `openauth-oidc` | **Ninguna** (`[features]` vacío) |
| `openauth-sso` | `oidc` (default) → activa `openauth-oidc`, `reqwest`, `base64` |
| `openauth` (umbrella) | `oidc` → `openauth-oidc` + `openauth-sso?/oidc` |

## 5. Consumidores en el workspace

| Consumidor | Uso |
| --- | --- |
| `openauth-sso` | `pub use openauth_oidc as oidc`; rutas llaman discovery + `oidc_redirect_uri` |
| `openauth` | Re-export opcional `openauth::oidc` con feature `oidc` |

## 6. Upstream relacionado (no es este crate)

| Paquete / plugin | Relación con OIDC |
| --- | --- |
| `@better-auth/oauth-provider` | OP — dirección opuesta a `openauth-oidc` |
| `generic-oauth` | Cliente OAuth genérico; callback `/oauth2/callback/:id` |
| `@better-auth/core/oauth2` | Primitivas compartidas; en OpenAuth: `openauth-oauth` + `openauth-core` |
