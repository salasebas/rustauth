# 08 — Segunda pasada (código + tests, 2026-06-01)

Relectura completa de `discovery.ts` ↔ `discovery.rs`, `registration.rs`, `provider_update.rs`, `sign_in.rs`, `oidc.rs`, `providers.ts` (upstream), y tests SSO. Hallazgos **nuevos** respecto a [07-deep-audit.md](./07-deep-audit.md).

## Crítico / comportamiento

### 1. `needs_runtime_discovery` y endpoints vacíos (`""`) — **cerrado**

| | Upstream `needsRuntimeDiscovery` | OpenAuth (después del fix) |
| --- | --- | --- |
| `authorizationEndpoint: ""` | falsy → necesita discovery | `is_configured_oidc_endpoint` → necesita discovery |

**Cambios:** `is_configured_oidc_endpoint`, merge en `discover_*` ignora `""`, `merge_oidc_config` normaliza `""` → `None`.

**Tests:** `runtime_discovery_treats_empty_string_endpoints_as_missing`, `discover_ignores_empty_existing_endpoint_overrides`, `update_provider_empty_authorization_endpoint_triggers_runtime_discovery_on_sign_in`.

### 2. Issuer usado en runtime discovery

Sign-in y callback llaman:

```text
ensure_runtime_oidc_config(..., &provider.issuer, config, ...)
```

- `validate_discovery_document(doc, issuer)` usa **`provider.issuer`** (tabla proveedor).
- El partial incluye `issuer: Some(config.issuer.as_str())` para el merge del hidratado.
- Validación `id_token` prueba **`provider.issuer` y, si difiere, `config.issuer`** (`routes/oidc.rs`).

Si `provider.issuer` ≠ `config.issuer` (datos corruptos o update parcial), discovery puede fallar con `issuer_mismatch` aunque el documento coincida con `config.issuer`. Upstream usa el mismo patrón (`provider.issuer` en `ensureRuntimeDiscovery`).

**No es bug nuevo** — conviene documentar para operadores.

## Superset OpenAuth (confirmado en código)

### 3. `strict_manual_endpoint_origins` sin discovery

`ensure_runtime_oidc_config_with_origin_validator`: si `needs_runtime_discovery` es false y `validate_configured_origins == true`, ejecuta `validate_configured_oidc_endpoint_origins` antes de devolver.

Upstream `ensureRuntimeDiscovery`: si no necesita discovery, **devuelve config sin re-validar** origins.

Cubierto por SSO: `sign_in_sso_rejects_untrusted_default_sso_manual_oidc_endpoint_when_strict_policy_is_enabled`.

### 4. Registro: endpoints opcionales en DB

Test `register_discovers_oidc_endpoints_when_skip_discovery_is_false` exige `revocationEndpoint`, `endSessionEndpoint`, `introspectionEndpoint` en respuesta y JSON almacenado.

Upstream `buildOIDCConfig` (líneas 725–743) **no** persiste esos campos; Zod de registro tampoco los expone.

### 5. `update-provider`: merge de endpoints opcionales

`merge_oidc_config` (Rust) actualiza `revocation_endpoint`, `end_session_endpoint`, `introspection_endpoint`.

Upstream `mergeOIDCConfig` en `providers.ts` (362–385) **no** incluye esos campos — aunque el body de update en OpenAuth sí los acepta (`UpdateOidcConfig`).

### 6. Post-merge trusted origins

Ya en 07 — reconfirmado línea por línea en `discover_oidc_config_with_origin_validator` (165–199).

## Paridad / detalles menores

### 7. `scopes_supported` en `PartialOidcDiscoveryConfig`

Upstream `discoverOIDCConfig` hidrata:

`scopesSupported: existingConfig?.scopesSupported ?? normalizedDoc.scopes_supported`

Rust `PartialOidcDiscoveryConfig` **no** tiene campo `scopes_supported`; hidratado usa solo `normalized.scopes_supported` (línea 163).

En runtime upstream pasa `OIDCConfig` como `existingConfig`, que **no** define `scopesSupported` en `types.ts` — efecto igual. Solo afecta llamadas directas al crate con partial custom.

### 8. `code_challenge_methods_supported`

Parseado en `OidcDiscoveryDocument` en ambos lados; **ninguno** elige método PKCE desde metadata (solo flag `config.pkce` en sign-in). Paridad: ignorado igual.

### 9. HTTP discovery

Rust: header `Accept: application/json` + timeout 10s en la request (no configurable por param).

Upstream: `betterFetch` con `timeout` param en `discoverOIDCConfig` (default 10s).

### 10. `discover_oidc_config` sin validador

`discover_oidc_config(..., |_| true, ...)` — API pública acepta cualquier origin si se usa el crate sin SSO. Documentar como **caller responsibility**.

### 11. `normalize_url` vs `normalizeUrl` (3 argumentos)

Rust exporta `normalize_url(&str)` solo para URLs absolutas; resolución relativa = `normalize_endpoint_url`.

Upstream `normalizeUrl(name, endpoint, issuer)` unifica ambos.

Test Rust añadido: `normalize_endpoint_resolves_relative_urls_with_duplicate_slashes`.

### 12. `validate_issuer_url` (OpenID IssuerUrl)

Registro/update OpenAuth: `openidconnect::IssuerUrl`. Upstream registro: `issuer: z.string()` sin validación OIDC en el fragmento revisado.

### 13. Duplicación de tests redirect

`openauth-sso/tests/sso/oidc.rs` repite los 3 tests de `openauth-oidc/tests/flow.rs` vía re-export — mantenimiento doble, no gap funcional.

### 14. `provider_update` no re-ejecuta discovery

Ni upstream ni OpenAuth vuelven a llamar `discover_*` en update — solo merge + validación URL/origins. Paridad.

### 15. Feature `oidc` desactivado en SSO

`registration.rs`: sin feature, `validate_issuer_url` = `url::Parse` simple. Comportamiento degradado documentado en crate SSO, no en `openauth-oidc`.

## Matriz rápida: ¿bug o decisión?

| Hallazgo | Clasificación |
| --- | --- |
| Endpoints `""` y runtime discovery | **Cerrado** (2026-06-01) |
| Issuer provider vs config | **Operacional** (igual que upstream) |
| strict_manual sin discovery | **Superset intencional** |
| Revoke/end_session/introspect en DB/update | **Superset intencional** |
| Post-merge origins | **Superset seguridad** |
| scopes_supported en partial | **Menor / N/A en SSO** |
| Slashes dobles en normalize | **Cerrado** — `normalize_endpoint_resolves_relative_urls_with_duplicate_slashes` |
| Auditoría `oidc.test.ts` en SSO | **Cerrado** — ver [openauth-sso/06-tests.md](../openauth-sso/06-tests.md) + `oidc_upstream_parity.rs` |

## Siguiente acción sugerida

Ninguna acción bloqueante para discovery/OIDC RP en BA 1.6.9. Mantener la matriz al añadir escenarios upstream nuevos.
