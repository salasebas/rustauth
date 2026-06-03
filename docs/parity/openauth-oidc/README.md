# Paridad: `openauth-oidc` ↔ `@better-auth/sso` (módulo OIDC)

Documentación de paridad **solo servidor** entre el crate Rust `openauth-oidc` y el submódulo OIDC del paquete npm `@better-auth/sso` en Better Auth **v1.6.9**.

| Campo | Valor |
| --- | --- |
| Upstream npm | `@better-auth/sso@1.6.9` |
| Upstream OIDC (discovery) | `reference/upstream-src/1.6.9/repository/packages/sso/src/oidc/` |
| Upstream OIDC (flujo HTTP) | `packages/sso/src/routes/sso.ts` (+ tests `oidc.test.ts`) |
| Crate Rust | `crates/openauth-oidc` |
| Integración del flujo | `crates/openauth-sso` (feature `oidc`) |
| Paridad pin | [`reference/upstream-better-auth/VERSION.md`](../../../reference/upstream-better-auth/VERSION.md) |
| Specs históricos | [`docs/superpowers/specs/openauth-sso/`](../../superpowers/specs/openauth-sso/) |

## Relación de paquetes

| Rol | Upstream | OpenAuth |
| --- | --- | --- |
| Discovery + tipos OIDC RP | `packages/sso/src/oidc/*` (dentro de `@better-auth/sso`) | **`openauth-oidc`** (crate independiente) |
| Plugin SSO completo (rutas, callback, DB) | `@better-auth/sso` | `openauth-sso` (+ `openauth-saml` para SAML) |
| Cliente tipado | `@better-auth/sso/client` (`ssoClient()`) | **No portado** (server-only) |
| Tu app como authorization server | `@better-auth/oauth-provider` | `openauth-oauth-provider` |
| OAuth genérico / linking | `better-auth/plugins/generic-oauth` | Fuera de alcance de este crate |

**Split intencional:** Better Auth empaqueta discovery OIDC y el plugin SSO en **un solo npm package**. OpenAuth **extrajo** el módulo `oidc/` a `openauth-oidc` para publicar helpers de relying party sin arrastrar SAML, rutas ni almacenamiento. El flujo authorization-code, validación de `id_token`, UserInfo y rutas HTTP viven en **`openauth-sso`**, no en este crate.

**No confundir con:**

- `openauth-oauth-provider` — OpenAuth **como** OP (issuer).
- `better-auth/plugins/oidc-provider` — OP legacy deprecado en upstream.

## Índice

| Documento | Contenido |
| --- | --- |
| [01-overview.md](./01-overview.md) | Resumen ejecutivo, alcance, estado de paridad |
| [02-package-mapping.md](./02-package-mapping.md) | Mapa archivo ↔ módulo, frontera con `openauth-sso` |
| [03-api-and-types.md](./03-api-and-types.md) | Tabla función/tipo upstream ↔ Rust |
| [04-design-decisions.md](./04-design-decisions.md) | Divergencias intencionales y por stack |
| [05-tests.md](./05-tests.md) | Conteos Vitest ↔ Rust, matriz de escenarios |
| [06-boundary-sso.md](./06-boundary-sso.md) | Qué queda en `openauth-sso` vs upstream `routes/sso.ts` |
| [07-deep-audit.md](./07-deep-audit.md) | Auditoría código+fuentes (exports, seguridad, gaps reales) |
| [08-second-pass-findings.md](./08-second-pass-findings.md) | Segunda pasada: endpoints vacíos, issuer dual, gaps nuevos |

## Verificación rápida

```bash
cargo fmt --all --check
cargo clippy -p openauth-oidc --all-targets -- -D warnings
cargo nextest run -p openauth-oidc
```

| Métrica | Upstream (`sso/src/oidc`) | `openauth-oidc` |
| --- | --- | --- |
| Archivo de tests discovery | `oidc/discovery.test.ts` | `src/discovery.rs` (`mod tests`) + `tests/flow.rs` |
| `it(` en discovery | **71** | — |
| `#[test]` + `#[tokio::test]` | — | **26** (23 en `discovery.rs` + 3 en `tests/flow.rs`) |
| E2E OIDC SSO (`oidc.test.ts`) | **22** `it(` | Cubierto en **`openauth-sso`** — ver [openauth-sso/06-tests.md](../openauth-sso/06-tests.md) |

## Estado resumido (módulo discovery / tipos)

| Área | Paridad con BA 1.6.9 | Notas |
| --- | --- | --- |
| `computeDiscoveryUrl` | **Alta** | Misma regla issuer + `/.well-known/openid-configuration` |
| Fetch + validación discovery | **Alta** | Cliente HTTP distinto (`reqwest` vs `betterFetch`) |
| Normalización URLs relativas | **Alta** | APIs públicas extra en Rust (`normalize_endpoint_url`, etc.) |
| Trusted origins / SSRF | **Alta** | Predicado `is_trusted_origin`; SSRF del cliente en caller/`sso` |
| Runtime discovery | **Alta** | Rust `ensure_runtime_*` merge revocation/end_session/introspection; upstream `ensureRuntimeDiscovery` no |
| Registro: endpoints opcionales en DB | **Superset** | OpenAuth persiste revoke/end_session/introspection; upstream Zod/register no |
| `scopes_supported` → `scopes` en DB | **Alineado** | Ambos usan solo scopes explícitos del operador; hydrated puede llevar `scopes_supported` |
| Post-merge trusted origins | **Superset** | OpenAuth re-valida URLs finales tras overrides; upstream no |
| `mapDiscoveryErrorToAPIError` | **En `openauth-sso`** | No forma parte de este crate |
| Authorization code / ID token / UserInfo | **N/A aquí** | `openauth-sso` + `openauth-oauth` / `openidconnect` |
| `ssoClient()` | **N/A** | TS-only |

Última auditoría documentada: **2026-06-01** (Better Auth `v1.6.9`, commit `f484269`).
