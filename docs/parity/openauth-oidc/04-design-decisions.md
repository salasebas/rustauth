# 04 — Decisiones de diseño y divergencias

## Tabla resumen

| Tema | Upstream | OpenAuth | Motivo |
| --- | --- | --- | --- |
| Empaquetado | `oidc/` dentro de `@better-auth/sso` | Crate `openauth-oidc` | Publicar RP OIDC sin SAML/XML; dependencias mínimas |
| HTTP discovery | `betterFetch` + `timeout` param | `reqwest::Client` del caller | SSRF/timeouts/proxy bajo control del integrador; SSO usa cliente endurecido |
| `fetchDiscoveryDocument` público | Sí | Privado | API surface más pequeña; discovery vía `discover_*` |
| `validateDiscoveryUrl` exportado | Sí | Integrado | Misma semántica en el pipeline |
| Secretos | `string` en JSON/DB | `SecretString` | Idioma Rust: no filtrar en `Debug` |
| Endpoints revocation / end_session / introspection en `OIDCConfig` | No en tipos 1.6.9 | Sí en `OidcProviderConfig` | Preparar OP metadata completa; discovery los normaliza |
| `ensureRuntimeDiscovery` merge | 5 campos | Incluye revocation, end_session, introspection | Superset en runtime; verificado en `ensure_runtime_oidc_config_*` |
| Registro: revoke/end_session/introspect | No en schema Zod ni `buildOIDCConfig` | Persistidos tras discovery | Superset SSO; test `register_discovers_oidc_endpoints_*` |
| `scopes_supported` → `scopes` | Hydrated sí; DB usa `body.oidcConfig.scopes` | Igual: `input.scopes` solo | **No es divergencia** — test upstream 59 solo cubre retorno de discover |
| Post-merge origin validation | No re-valida overrides de `existingConfig` | `validate_trusted_url` en cada URL final | Hardening OpenAuth — ver [07-deep-audit.md](./07-deep-audit.md) §1 |
| `OidcRuntimeRequirement` | N/A (solo `needsRuntimeDiscovery(config)`) | Enum SignIn/Callback | API explícita; hoy misma condición que upstream |
| `mapDiscoveryErrorToAPIError` | `oidc/errors.ts` | En capa SSO/core | Crate de librería sin `APIError` de Better Auth |
| `openidconnect` crate | N/A (jose en SSO callback) | Solo `IssuerUrl` en discovery | Validación issuer; JWT en `openauth-sso` |
| Cliente `ssoClient()` | `@better-auth/sso/client` | No portado | **Server-only** — sin SDK browser |
| Features Cargo | N/A en submódulo | Sin features en `openauth-oidc` | Superficie fija; activación en `openauth-sso` |

## Por categoría

### Server-only

- No se portan inferencias TypeScript del plugin registry ni `ssoClient()`.
- La documentación de paridad **no** penaliza la ausencia de helpers cliente.

### Rust / ecosystem

- Errores con `thiserror` + `code()`/`status()` en lugar de clase `DiscoveryError` + mapper separado.
- Serde `camelCase` en config para JSON compatible con registros SSO existentes.
- Async con `async`/`.await` nativo (no `Awaitable` de TS).

### Seguridad

- Validación de origins en discovery y, opcionalmente, en config ya persistida (`validate_configured_oidc_endpoint_origins`).
- `normalize_absolute_http_url` rechaza esquemas no HTTP(S) — alineado con SSRF en SSO.
- El intercambio de tokens y fetch JWKS/UserInfo aplican allowlist de IPs en **`openauth-sso`** (`oidc.allow_private_endpoint_ips`), no en este crate.

### No es gap: otros paquetes upstream

| Upstream | Por qué no es `openauth-oidc` |
| --- | --- |
| `@better-auth/oauth-provider` | OpenAuth como **issuer** → `openauth-oauth-provider` |
| `generic-oauth` | Producto distinto (multi-provider, linking, `/oauth2/callback`) |
| `oidc-provider` (deprecated) | Reemplazado por oauth-provider en ambos ecosistemas |
| Social providers en `@better-auth/core` | `openauth` social / oauth integraciones separadas |

### Paridad deliberadamente distinta

| Comportamiento | Detalle |
| --- | --- |
| Hidratación `scopes_supported` | Upstream test: *"should include scopes_supported in hydrated config"*. OpenAuth mantiene `scopes_supported` en resultado de discovery pero **no** sobrescribe `config.scopes` al persistir — evita ampliar scopes sin consentimiento explícito. |
| Auth methods no soportados (`tls_client_auth`, etc.) | Ambos hacen default `client_secret_basic` sin error `unsupported_token_auth_method` en el selector (el código de error existe upstream para uso futuro / mapper). |

## Gaps cerrados (segunda pasada)

| Tema | Estado |
| --- | --- |
| Endpoints opcionales `Some("")` | **Cerrado** — `is_configured_oidc_endpoint`, merge discovery, `merge_oidc_config` |
| Normalización URL slashes dobles | **Cerrado** — test unitario en `discovery.rs` |

## Cuándo usar cada crate OpenAuth

| Necesidad | Crate |
| --- | --- |
| Solo discovery + tipos + redirect URI | `openauth-oidc` |
| SSO empresarial completo (OIDC + SAML + DB + rutas) | `openauth-sso` (+ `openauth-saml`) |
| Tu app emite tokens OIDC | `openauth-oauth-provider` |
