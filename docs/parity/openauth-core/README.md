# Paridad: `openauth-core` ↔ `@better-auth/core` + runtime `better-auth`

Documentación de paridad **solo servidor** entre OpenAuth y Better Auth **v1.6.9**.

**Alcance de esta carpeta:** el núcleo de autenticación (tipos, contexto, DB, cookies, crypto, rutas HTTP integradas, plugins en core, rate limit). **Fuera de alcance** (otras sesiones / crates): `social-providers`, flujos OAuth2 de proveedor/callback, y el ecosistema de **plugins** npm (`admin`, `organization`, etc.).

| Campo | Valor |
| --- | --- |
| Paridad pin | [`reference/upstream-better-auth/VERSION.md`](../../../reference/upstream-better-auth/VERSION.md) |
| Upstream core | `@better-auth/core` → `reference/upstream-src/1.6.9/repository/packages/core/` |
| Upstream runtime | `better-auth` → `reference/upstream-src/1.6.9/repository/packages/better-auth/` |
| Crate Rust principal | `crates/openauth-core` |
| Fachada pública | `crates/openauth` (re-exporta core + integraciones opcionales) |
| Notas en crate | [`crates/openauth-core/SERVER_PARITY.md`](../../../crates/openauth-core/SERVER_PARITY.md), [`SQL_ADAPTER_PARITY.md`](../../../crates/openauth-core/SQL_ADAPTER_PARITY.md) |
| Roadmap general | [`PORTING.md`](../../../PORTING.md) |

## Relación de paquetes (split / merge)

Upstream separa **contratos** (`@better-auth/core`) del **producto** (`better-auth`). OpenAuth concentra casi todo el runtime servidor en **`openauth-core`** y usa **`openauth`** como fachada (equivalente al import principal de `better-auth`).

| Rol | Upstream | OpenAuth |
| --- | --- | --- |
| Tipos, esquema DB, adapter factory, endpoint helpers, env/error/utils | `@better-auth/core` | `openauth-core` (módulos `db`, `options`, `plugin`, `env`, `error`, `utils`, `api::endpoint`) |
| Runtime: rutas, cookies, crypto, internal adapter, router | `packages/better-auth/src` | `openauth-core` (`api`, `cookies`, `crypto`, `auth`, `context`, `session`, `user`, …) |
| OAuth2 cliente / validación JWKS | `@better-auth/core/oauth2` | `openauth-oauth` (crate aparte; **no** en este doc) |
| Social providers (~40 proveedores) | `@better-auth/core/social-providers` | `openauth-social-providers` (**no** en este doc) |
| OpenTelemetry en core | `@better-auth/core/instrumentation` | **No portado en core** (telemetría anónima → `openauth-telemetry`) |
| Cliente React/Vue/… | `better-auth/client`, `./react`, … | **N/A** (server-only) |
| Adapters Prisma/Drizzle/Kysely | Paquetes workspace + re-export | `openauth-sqlx`, `openauth-tokio-postgres`, … (**fuera** de core) |
| Plugins de producto (admin, 2FA, org, …) | `better-auth/plugins/*` | `openauth-plugins` + crates SSO/SCIM/… (**fuera** de este doc) |

**Merge importante:** lo que en TS son **dos paquetes** (`core` + mitad de `better-auth`) viven en **un solo crate** `openauth-core`. **Split importante:** OAuth2 y social salieron a crates opcionales con features Cargo.

## Índice

| Documento | Contenido |
| --- | --- |
| [01-overview.md](./01-overview.md) | Resumen ejecutivo, estado por área, diagrama |
| [02-package-mapping.md](./02-package-mapping.md) | Mapa upstream path ↔ módulo Rust, fachada `openauth` |
| [03-routes.md](./03-routes.md) | Inventario de endpoints HTTP (in-scope) |
| [04-modules.md](./04-modules.md) | Paridad módulo a módulo con tablas |
| [05-tests.md](./05-tests.md) | Conteos Vitest ↔ Rust, matriz por área |
| [06-design-decisions.md](./06-design-decisions.md) | Divergencias intencionales y huecos conocidos |
| [07-options-field-matrix.md](./07-options-field-matrix.md) | Campo a campo `BetterAuthOptions` ↔ `OpenAuthOptions` |
| [08-gaps-audit.md](./08-gaps-audit.md) | Segunda pasada: huecos código + tests + harness CSRF |
| [09-error-codes.md](./09-error-codes.md) | `BASE_ERROR_CODES` ↔ strings Rust |
| [10-user-lifecycle-gaps.md](./10-user-lifecycle-gaps.md) | delete-user / change-email vs upstream |

## Verificación rápida

```bash
cargo fmt --all --check
cargo clippy -p openauth-core --all-targets -- -D warnings
cargo nextest run -p openauth-core
```

Para paridad **sin** OAuth/social en tests de rutas (aprox. mismo alcance que este doc):

```bash
cargo nextest run -p openauth-core -- --skip social_oauth --skip account_tokens --skip oauth
```

| Métrica | Upstream (in-scope) | OpenAuth (`openauth-core`) |
| --- | --- | --- |
| Paquetes comparados | `@better-auth/core` + `better-auth` (server, sin plugins/oauth2/social/client) | `openauth-core` |
| Archivos `*.test.ts` | 14 (core) + 36 (better-auth server-ish) ≈ **50** | 76 `.rs` bajo `tests/` + 2 en `src/` |
| Casos `it(` Vitest (aprox.) | **184** en `@better-auth/core` tests; **~770** `it(` + **~14** `test(` en better-auth server-ish | **501** total Rust (**453** in-scope sin oauth/social) |
| Archivos test upstream in-scope | **50** `.test.ts` | **76** bajo `tests/` + **2** unit en `src/` |

Última auditoría: **2026-06-01** (revisión profunda código + tests; ver [08-gaps-audit.md](./08-gaps-audit.md)).
