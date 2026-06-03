# 06 — Frontera con `openauth-sso` y `routes/sso.ts`

Este documento acota qué OIDC **no** está en `openauth-oidc` pero sí en Better Auth `@better-auth/sso` y su contraparte Rust.

## División de responsabilidades

| Capa | `openauth-oidc` | `openauth-sso` |
| --- | --- | --- |
| Tipos + discovery + redirect URI | **Sí** | Re-export + conversión tipos |
| Rutas HTTP | No | **Sí** |
| Persistencia `ssoProvider` | No | **Sí** |
| PKCE + state OAuth | No | **Sí** (`sign_in.rs`) |
| Token endpoint exchange | No | **Sí** (`openauth-oauth`) |
| Validación `id_token` + JWKS fetch | No | **Sí** (`openidconnect` en `routes/oidc.rs`) |
| UserInfo fallback | No | **Sí** (`fetch_oidc_user_info`) |
| `handleOAuthUserInfo` / linking | No | **Sí** (`openauth-core`) |
| Domain verification | No | **Sí** |
| SAML | No | **`openauth-saml`** |
| `mapDiscoveryErrorToAPIError` equivalente | `OidcDiscoveryError` only | `oidc_discovery_error_response` en `registration.rs` |
| `OidcOptions` (SSRF / strict origins) | N/A en BA 1.6.9 | `strict_manual_endpoint_origins`, `allow_private_endpoint_ips` |
| Persistencia revoke/end_session/introspect | No en register upstream | Sí en `build_oidc_config` — ver `registration/discovery.rs` test |

## Rutas HTTP (upstream `packages/sso/src/routes/`)

| Método | Ruta | Paridad OpenAuth |
| --- | --- | --- |
| POST | `/sso/register` | `openauth-sso` registration |
| POST | `/sign-in/sso` | sign-in OIDC/SAML |
| GET | `/sso/callback/:providerId` | `callback_endpoint` en `oidc.rs` |
| GET | `/sso/callback` | callback compartido (state lleva provider) |
| GET/POST | providers CRUD, domain verification | módulos `providers`, `domain_verification` |
| SAML | `/sso/saml2/*` | `openauth-saml` + rutas SSO |

## Funciones upstream en `routes/sso.ts` (OIDC)

| Función / comportamiento upstream | Implementación OpenAuth |
| --- | --- |
| `getOIDCRedirectURI` | `openauth_oidc::oidc_redirect_uri` |
| `discoverOIDCConfig` / `ensureRuntimeDiscovery` | `openauth_oidc::discover_*` / `ensure_runtime_*` |
| `mapDiscoveryErrorToAPIError` | Errores en rutas registration/update (códigos estables) |
| `createAuthorizationURL` + PKCE | `openauth-oauth` + sign-in |
| `validateAuthorizationCode` | `validate_authorization_code_with_client` |
| `decodeJwt` | `CoreIdToken` + `validate_oidc_id_token` |
| `handleOAuthUserInfo` | `handle_oauth_user_info` |
| Org assignment / `provisionUser` | `linking_impl`, options |

Archivo principal Rust: `crates/openauth-sso/src/routes/oidc.rs` (~670 líneas).

## Archivos de test SSO (OIDC)

| Ruta bajo `crates/openauth-sso/tests/` | Tema |
| --- | --- |
| `sso/oidc.rs` | Redirect URI helpers |
| `sso/endpoints/registration/discovery.rs` | Registro + discovery |
| `sso/endpoints/oidc_callback.rs` + `oidc_callback/**` | Callback, tokens, id_token, errores |
| `sso/endpoints/sign_in/oidc_basic.rs` | Sign-in básico |
| `sso/endpoints/sign_in/defaults_discovery.rs` | defaultSSO + discovery |
| `sso/endpoints/provider_update.rs` | Validación issuer/endpoints |
| `sso/endpoints/helpers/oidc_server.rs` | Mock IdP |
| `sso/endpoints/oidc_upstream_parity.rs` | Seis tests alineados a huecos de `oidc.test.ts` |

Auditoría E2E del plugin SSO: [`docs/parity/openauth-sso/`](../openauth-sso/README.md) (matriz en [06-tests.md](../openauth-sso/06-tests.md)).

## Checklist E2E (`oidc.test.ts` → SSO)

Estado **2026-06-01** (detalle en `openauth-sso/06-tests.md`):

- [x] Registro proveedor OIDC válido / issuer inválido / `providerId` duplicado
- [x] Sign-in por email, dominio, `providerId`
- [x] Runtime hydration de `authorizationEndpoint` (y token/jwks si faltan)
- [x] Email normalizado a minúsculas en callback
- [x] `signUp` deshabilitado / habilitado con flag
- [x] `provisionUser` primera vez vs subsiguientes (según opción)
- [x] `redirectURI` compartido en registro, authorize URL y callback compartido
- [x] `defaultSSO` por `providerId`, dominio, endpoints explícitos
- [x] Login solo con UserInfo (sin `id_token`)

## Dependencias cruzadas

```text
openauth-sso (feature oidc)
  ├── openauth-oidc     ← este documento de paridad
  ├── openauth-oauth    ← authorization URL, code exchange
  ├── openauth-core     ← OAuth user linking
  └── openidconnect     ← id_token + JWKS (en sso, no en oidc crate)
```
