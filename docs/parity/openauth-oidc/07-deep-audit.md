# 07 — Auditoría profunda (código + tests, 2026-06-01)

Revisión línea a línea de:

- `reference/upstream-src/1.6.9/repository/packages/sso/src/oidc/*` (525 + 219 + 92 + 32 LOC)
- `crates/openauth-oidc/src/*` (1292 + 136 + 31 + 26 LOC)
- Usos en `crates/openauth-sso` y tests bajo `crates/openauth-sso/tests/`

**No se usó el README como fuente de verdad** — solo confirmación posterior.

## Inventario de archivos

| Upstream | LOC | OpenAuth | LOC |
| --- | --- | --- | --- |
| `discovery.ts` | 525 | `discovery.rs` | 1292 (incl. ~650 LOC tests) |
| `types.ts` | 219 | `options.rs` + tipos en `discovery.rs` | 136 + ~90 |
| `errors.ts` | 92 | `OidcDiscoveryError` en `discovery.rs` | (inline) |
| `index.ts` | 32 | `lib.rs` | 26 |
| `discovery.test.ts` | 1244 | `discovery.rs` tests + `tests/flow.rs` | ~650 + 45 |
| — | — | `flow.rs` | 31 |
| `routes/sso.ts` (`getOIDCRedirectURI`) | privado | `flow.rs` | público |

## Exports: upstream `oidc/index.ts` vs `openauth-oidc` `lib.rs`

| Export upstream | OpenAuth | Notas |
| --- | --- | --- |
| `computeDiscoveryUrl` | `compute_discovery_url` | ≈ |
| `discoverOIDCConfig` | `discover_oidc_config` (+ `_with_origin_validator`) | Firma distinta |
| `ensureRuntimeDiscovery` | `ensure_runtime_oidc_config_with_origin_validator` | Más parámetros |
| `fetchDiscoveryDocument` | **privado** | Upstream público |
| `needsRuntimeDiscovery` | `needs_runtime_discovery` (+ `OidcRuntimeRequirement`) | Upstream acepta `undefined` |
| `normalizeDiscoveryUrls` | **privado** (`normalize_discovery_document`) | |
| `normalizeUrl` | `normalize_url` + `normalize_endpoint_url` | API partida |
| `selectTokenEndpointAuthMethod` | **privado** | |
| `validateDiscoveryDocument` | **privado** | |
| `validateDiscoveryUrl` | **no exportado** (lógica en `discover_*`) | |
| `mapDiscoveryErrorToAPIError` | **no** (en `openauth-sso`) | |
| `DiscoveryError`, códigos, tipos | `OidcDiscoveryError`, etc. | |
| `REQUIRED_DISCOVERY_FIELDS` | **no exportado** | Constante TS pública |
| — | `normalize_absolute_http_url` | + |
| — | `validate_issuer_url` | + |
| — | `validate_configured_oidc_endpoint_origins` | + |
| — | `OidcEndpointConfig` | + |
| — | `PartialOidcDiscoveryConfig` | + |
| — | `OidcRuntimeRequirement` | + |
| — | `oidc_redirect_uri`, `OidcFlowOptions` | En `flow.rs` (upstream en `routes/sso.ts`) |
| — | `VERSION` | + |

## Hallazgos de comportamiento (verificados en fuente)

### 1. Validación de origins **después** del merge (hardening OpenAuth)

Upstream `discoverOIDCConfig` normaliza el documento con `normalizeDiscoveryUrls` (trusted check) y luego aplica overrides de `existingConfig` **sin** re-validar origins en los valores finales.

OpenAuth `discover_oidc_config_with_origin_validator` valida **cada URL hidratada** tras el merge (`authorization`, `token`, `jwks`, `userinfo`, `revocation`, `end_session`, `introspection`).

**Impacto:** override manual de un endpoint malicioso fallaría en OpenAuth; upstream podría aceptarlo si el documento discovery era trusted. **Superset de seguridad.**

### 2. Endpoints opcionales en hidratación y runtime

| Campo | `discoverOIDCConfig` hydrated upstream | `HydratedOidcDiscovery` Rust | `ensureRuntimeDiscovery` upstream | `ensure_runtime_*` Rust |
| --- | --- | --- | --- | --- |
| revocation / end_session / introspection | Normalizados en doc, **no** en tipo hydrated | **Sí** en struct | **No** merge | **Sí** merge a `OidcConfig` |
| `scopesSupported` | **Sí** en hydrated | **Sí** en struct | **No** merge | **No** → `scopes` |

Persistencia en registro (verificado en tests SSO):

- Upstream `buildOIDCConfig`: solo campos del schema Zod (sin revocation/end_session/introspection).
- OpenAuth `build_oidc_config`: persiste los tres endpoints opcionales desde hydrated — test `register_discovers_oidc_endpoints_when_skip_discovery_is_false` en `openauth-sso/tests/sso/endpoints/registration/discovery.rs`.

**Conclusión:** superset en **SSO + tipos**, no solo en el crate `openauth-oidc`.

### 3. `scopes` vs `scopes_supported`

Ambos ecosistemas **no** copian `scopes_supported` del discovery a `scopes` en DB:

- Upstream `buildOIDCConfig`: `scopes: body.oidcConfig.scopes` (líneas 714, 737).
- OpenAuth: `scopes: input.scopes` tras discovery; test explícito en crate y en SSO registration.

El test upstream *"should include scopes_supported in hydrated config"* solo cubre el **retorno** de `discoverOIDCConfig`, no persistencia — alineado con OpenAuth.

### 4. Duplicación de tipos `OidcConfig`

`openauth-oidc/src/options.rs` y `openauth-sso/src/options.rs` definen estructuras casi idénticas (`OidcConfig`, mapping, token auth). SSO convierte con `oidc_config_to_impl` / `from_impl` en `routes/oidc.rs`.

**No es divergencia de paridad upstream** — decisión de crate boundary (SSO no depende de re-export único para serde de plugin).

### 5. Opciones solo en `openauth-sso` (`OidcOptions`)

No están en Better Auth 1.6.9:

| Campo | Default | Propósito |
| --- | --- | --- |
| `strict_manual_endpoint_origins` | `false` | Tras `skip_discovery`, validar origins con `validate_configured_oidc_endpoint_origins` |
| `allow_private_endpoint_ips` | `false` | SSRF: bloquear IPs privadas en discovery/token/JWKS/userinfo |

Documentar en paridad SSO; **fuera del crate `openauth-oidc`**.

### 6. `validate_issuer_url`

Rust: `openidconnect::IssuerUrl::new` en registro/actualización.

Upstream registro: `issuer: z.string()` sin validación OIDC-specific en el fragmento Zod revisado — OpenAuth más estricto en registro.

### 7. HTTP fetch

| Aspecto | Upstream | OpenAuth |
| --- | --- | --- |
| Cliente | `betterFetch` interno | `reqwest::Client` inyectado |
| Timeout | param `timeout` (default 10s) | `Duration::from_secs(10)` en builder |
| 500 | `discovery_unexpected_error` | `error_for_status` → `Request` → mismo código |
| AbortError timeout | `discovery_timeout` | `error.is_timeout()` → `Timeout` |
| 408 | `discovery_timeout` | `Timeout` |

### 8. `normalize_discovery_document` vs `normalizeDiscoveryUrls`

Upstream valida trust **durante** normalización por endpoint.

OpenAuth normaliza sin trust, valida trust **después** en URLs finales (incl. overrides). Equivalente o más estricto (§1).

### 9. `needsRuntimeDiscovery`

Upstream: `undefined` config → `true`.

Rust: siempre `&OidcConfig`; endpoints faltantes = `None` → necesita discovery. `user_info_endpoint` **no** cuenta para satisfacer runtime (igual que upstream: solo authz, token, jwks).

### 10. `getOIDCRedirectURI` vs `oidc_redirect_uri`

Lógica equivalente; Rust hace `trim_end_matches('/')` en `base_url` antes de concatenar.

Tests duplicados: `openauth-oidc/tests/flow.rs` y `openauth-sso/tests/sso/oidc.rs` (mismos 3 escenarios vía re-export).

## Registro upstream: campos OIDC en Zod (líneas 193–235 `routes/sso.ts`)

Presentes: `clientId`, `clientSecret`, `authorizationEndpoint`, `tokenEndpoint`, `userInfoEndpoint`, `tokenEndpointAuthentication`, `jwksEndpoint`, `discoveryEndpoint`, `skipDiscovery`, `scopes`, `pkce`, `mapping`.

**Ausentes** vs OpenAuth `RegisterOidcConfig`: `revocationEndpoint`, `endSessionEndpoint`, `introspectionEndpoint` (solo vía discovery en OpenAuth, no en body upstream).

## Mapeo de errores HTTP

| Código | `OidcDiscoveryError::status()` | `mapDiscoveryErrorToAPIError` |
| --- | --- | --- |
| `discovery_timeout` | 502 | 502 |
| `discovery_unexpected_error` / `Request` | 502 | 502 |
| Resto | 400 | 400 |
| `unsupported_token_auth_method` | (no emitido por selector) | 400 si existiera |

SSO: `oidc_discovery_error_response` usa `error.status()` + `error.code()` — equivalente funcional.

## Gaps de tests en el crate (respecto a 71 `it` upstream)

Ver [05-tests.md](./05-tests.md) matriz completa. Tras la pasada **2026-06-01**, lo que queda **sin test unitario dedicado solo en `openauth-oidc`** es mayormente N/A o cubierto en SSO:

| Escenario upstream | Cobertura OpenAuth |
| --- | --- |
| `needsRuntimeDiscovery` undefined | **N/A** (`&OidcConfig` en Rust) |
| `discoverOIDCConfig` custom/existing discovery URL | Parcial (mock SSO + async unit) |
| `ensureRuntimeDiscovery` ×5 | Parcial unit + SSO runtime/callback |
| `fetch` unknown error genérico | Parcial vía `reqwest` |
| `include scopes_supported` → DB `scopes` | **Alineado** — test `runtime_discovery_preserves_only_explicit_request_scopes` |

**Cerrados en esta ronda:** HTTP/HTTPS (`normalize_absolute_http_url_*`), issuer trailing slash, prefer basic / post-only en selector.

**Cobertura combinada crate + SSO:** `registration/discovery.rs`, `oidc_callback/discovery.rs`, `sign_in/defaults_discovery.rs`, `oidc_upstream_parity.rs`. E2E: [openauth-sso/06-tests.md](../openauth-sso/06-tests.md).

## Conteos de tests (recontados)

| Suite | Count |
| --- | --- |
| `oidc/discovery.test.ts` | **71** `it(` |
| `oidc.test.ts` (E2E SSO) | **22** `it(` |
| `openauth-oidc` | **26** |
| `openauth-sso` `oidc_upstream_parity.rs` | **6** |
| `openauth-sso` `registration/discovery.rs` | **6** |
| `openauth-sso` `oidc_callback/discovery.rs` | **8** |
| `openauth-sso` `oidc.rs` | **3** (duplicado de `flow.rs`) |

## Acciones sugeridas (documentación / código)

1. Mantener paridad de persistencia `scopes` documentada (no es gap).
2. Superset de endpoints opcionales en DB: documentado en [04-design-decisions.md](./04-design-decisions.md) — no revertir sin decisión de producto.
3. ~~Tests unitarios issuer slash / token auth~~ **Hecho** en `discovery.rs`.
4. ~~Auditoría `oidc.test.ts`~~ **Hecho** — [openauth-sso/06-tests.md](../openauth-sso/06-tests.md).
