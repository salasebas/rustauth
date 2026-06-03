# 03 — API, tipos y comportamiento

Leyenda: **≈** paridad alta · **△** divergencia intencional · **⊘** no aplica / fuera del crate · **+** superset OpenAuth

## Funciones exportadas (discovery)

| Upstream (`discovery.ts`) | OpenAuth | Paridad | Notas |
| --- | --- | --- | --- |
| `computeDiscoveryUrl` | `compute_discovery_url` | ≈ | |
| `validateDiscoveryUrl` | (integrado en `discover_*` + `validate_trusted_url`) | △ | No exportado como función suelta en Rust |
| `fetchDiscoveryDocument` | `fetch_discovery_document` (privado) | △ | Upstream público; Rust requiere `reqwest::Client` del caller |
| `validateDiscoveryDocument` | `validate_discovery_document` (privado) | ≈ | Mismos campos requeridos |
| `normalizeDiscoveryUrls` | `normalize_discovery_document` (privado) | ≈ | |
| `normalizeUrl(name, endpoint, issuer)` | `normalize_endpoint_url` + `normalize_url` | ≈ | `normalize_url` solo parsea; resolución relativa en `normalize_endpoint_url` |
| — | `normalize_absolute_http_url` | + | Validación HTTP(S) estricta |
| — | `validate_issuer_url` | + | `openidconnect::IssuerUrl` |
| `selectTokenEndpointAuthMethod` | `select_token_endpoint_authentication` (privado) | ≈ | Misma prioridad basic > post > default basic |
| `discoverOIDCConfig` | `discover_oidc_config` / `discover_oidc_config_with_origin_validator` | ≈ | Firma distinta: sin `timeout` param; con `Client` |
| `needsRuntimeDiscovery` | `needs_runtime_discovery` | ≈ | Rust añade `OidcRuntimeRequirement` (SignIn/Callback; misma condición hoy) |
| `ensureRuntimeDiscovery` | `ensure_runtime_oidc_config_with_origin_validator` | △ | Rust hidrata más campos; flag `validate_configured_origins` |
| `mapDiscoveryErrorToAPIError` | — | ⊘ | En `packages/sso/src/oidc/errors.ts`; ver SSO |
| — | `validate_configured_oidc_endpoint_origins` | + | Valida todos los endpoints en config almacenada |
| — | `OidcEndpointConfig` trait | + | Abstrae getters para validación |
| — | `OidcDiscoveryError::code` / `status` | + | Códigos estables + HTTP status sugerido |

## Tipos de configuración

| Upstream (`OIDCConfig` en `types.ts`) | OpenAuth (`OidcProviderConfig`) | Paridad |
| --- | --- | --- |
| `issuer` | `issuer` | ≈ |
| `pkce` | `pkce` | ≈ |
| `clientId` | `client_id` | ≈ |
| `clientSecret` (string) | `client_secret` (`SecretString`) | △ | Redacción en `Debug` en Rust |
| `discoveryEndpoint` | `discovery_endpoint` | ≈ |
| `authorizationEndpoint?` | `authorization_endpoint?` | ≈ |
| `tokenEndpoint?` | `token_endpoint?` | ≈ |
| `userInfoEndpoint?` | `user_info_endpoint?` | ≈ |
| `jwksEndpoint?` | `jwks_endpoint?` | ≈ |
| `tokenEndpointAuthentication?` | `token_endpoint_authentication?` | ≈ |
| `scopes?` | `scopes?` | ≈ |
| `mapping?` | `mapping?` | ≈ |
| `overrideUserInfo?` | `override_user_info` | ≈ |
| — | `revocation_endpoint?` | + | No en `OIDCConfig` upstream 1.6.9 |
| — | `end_session_endpoint?` | + | |
| — | `introspection_endpoint?` | + | |

### `HydratedOIDCConfig` vs `HydratedOidcDiscovery`

| Campo | Upstream hydrated | OpenAuth hydrated |
| --- | --- | --- |
| issuer, discoveryEndpoint, authorization, token, jwks, userInfo | Sí | Sí |
| tokenEndpointAuthentication | Sí | Sí |
| scopesSupported | Sí (en objeto hydrated) | Sí en struct, **no** se vuelca a `OidcConfig.scopes` |
| revocation / end_session / introspection | Normalizados en doc; **no** en `HydratedOIDCConfig` ni registro Zod | **Sí** en `HydratedOidcDiscovery` + persistencia SSO |

## Documento discovery (`OIDCDiscoveryDocument`)

Campos alineados con OpenID Provider Metadata que ambos parsean:

`issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `userinfo_endpoint`, `token_endpoint_auth_methods_supported`, `scopes_supported`, `response_types_supported`, `subject_types_supported`, `id_token_signing_alg_values_supported`, `claims_supported`, `code_challenge_methods_supported`, `revocation_endpoint`, `end_session_endpoint`, `introspection_endpoint`.

Upstream permite `[key: string]: unknown` en TypeScript; Rust ignora campos extra vía serde.

## Redirect URI

| Upstream | OpenAuth |
| --- | --- |
| `getOIDCRedirectURI(baseURL, providerId, options?)` privado en `routes/sso.ts` | `oidc_redirect_uri(base_url, provider_id, impl OidcFlowOptions)` |
| `SSOOptions.redirectURI` | `SsoOptions` impl `OidcFlowOptions::redirect_uri` |

Comportamiento compartido:

1. Si `redirectURI` es URL absoluta válida → usar tal cual.
2. Si es path relativo → `{baseURL}{path}` (con `/` normalizado).
3. Si no hay override → `{baseURL}/sso/callback/{providerId}`.

## Códigos de error (`DiscoveryErrorCode`)

| Código | Upstream | OpenAuth `OidcDiscoveryError` |
| --- | --- | --- |
| `discovery_timeout` | Sí | `Timeout` |
| `discovery_not_found` | Sí | `NotFound` |
| `discovery_invalid_json` | Sí | `InvalidJson` |
| `discovery_invalid_url` | Sí | `InvalidUrl` |
| `discovery_untrusted_origin` | Sí | `UntrustedOrigin` |
| `issuer_mismatch` | Sí | `IssuerMismatch` |
| `discovery_incomplete` | Sí | `MissingField` / `MissingFields` |
| `unsupported_token_auth_method` | Tipo existe; **no** lanzado en `select*` | Igual — default `client_secret_basic` |
| `discovery_unexpected_error` | Sí | `Request` |

Mapeo HTTP upstream (`mapDiscoveryErrorToAPIError`): timeout/unexpected → **502**; resto listado → **400**. OpenAuth expone lo mismo vía `OidcDiscoveryError::status()`.

## Flujo OIDC (fuera de este crate)

| Capacidad | Upstream | OpenAuth |
| --- | --- | --- |
| `createAuthorizationURL` + PKCE | `routes/sso.ts` + `better-auth` | `openauth-sso` / `openauth-oauth` |
| `validateAuthorizationCode` | core oauth2 | `validate_authorization_code_with_client` |
| `decodeJwt` / validación `id_token` | `jose` | `openidconnect` en `routes/oidc.rs` |
| UserInfo HTTP | `betterFetch` en callback | `fetch_oidc_user_info` |
| `handleOAuthUserInfo` | `better-auth/oauth2` | `openauth_core::auth::oauth` |

Ver [06-boundary-sso.md](./06-boundary-sso.md).
