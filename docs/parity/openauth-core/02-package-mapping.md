# Mapeo de paquetes y archivos

## Vista 1:1 y split/merge

| Upstream | OpenAuth | Relación |
| --- | --- | --- |
| `@better-auth/core` | `openauth-core` (subconjunto + extensiones) | **Merge parcial** en el mismo crate que el runtime |
| `better-auth` (servidor) | `openauth-core` + glue en `openauth` | **Merge**: runtime no es crate separado |
| `@better-auth/core/oauth2` | `openauth-oauth` | **Split** a crate; feature `oauth` en core |
| `@better-auth/core/social-providers` | `openauth-social-providers` | **Split** a crate; feature `social-providers` |
| `@better-auth/core/instrumentation` | — | **Gap**: OTEL no en core |
| `better-auth/client`, `./react`, … | — | **N/A** server-only |
| `better-auth/plugins/*` | `openauth-plugins`, SSO, SCIM, … | **Fuera** de este doc |
| `@better-auth/*-adapter` | `openauth-sqlx`, `tokio-postgres`, … | **Fuera** de core |

## `@better-auth/core` → `openauth-core`

| Upstream path | OpenAuth module | Paridad | Notas |
| --- | --- | --- | --- |
| `src/types/*` | `options/`, `plugin.rs`, `context.rs`, `cookies/types.rs` | Alta | Opciones repartidas en módulos Rust idiomáticos |
| `src/api/index.ts` | `api/endpoint.rs`, `api/plugin_pipeline.rs` | Alta | Sin dependencia de `better-call`; router propio |
| `src/context/*` | `context/`, `context/request_state.rs` | Alta | ALS → estado en `AuthContext` + request state |
| `src/db/schema/*` | `db/schema/` | Alta | |
| `src/db/adapter/*` | `db/adapter/`, `db/factory.rs` | Alta | Harness de contrato en Rust (`adapter_harness`) |
| `src/db/get-tables.ts` | `db/schema/builder.rs`, `auth_schema()` | Alta | |
| `src/env/*` | `env/` | Alta | Logger alineado; tests en `tests/env/` |
| `src/error/*` | `error.rs` | Alta | `OpenAuthError` vs `APIError` |
| `src/utils/host.ts` | `utils/host.rs` | Alta | |
| `src/utils/ip.ts` | `utils/ip.rs` | Alta | |
| `src/utils/url.ts` | `utils/url.rs` | Alta | |
| `src/utils/fetch-metadata.ts` | `utils/fetch_metadata.rs` | Alta | |
| `src/utils/id.ts` | `db/id.rs` | Alta | |
| `src/utils/async.ts` | — | Parcial | Concurrencia vía Tokio nativo |
| `src/async_hooks/*` | — | N/A | Rust: sin polyfill ALS browser |
| `src/instrumentation/*` | — | Gap | Ver `openauth-telemetry` para telemetría producto |
| `src/oauth2/*` | `auth/oauth/` (feature) | Excluido | Crate `openauth-oauth` |
| `src/social-providers/*` | — | Excluido | Crate `openauth-social-providers` |
| `src/types/plugin-client.ts` | — | N/A | Tipos solo cliente |

## `better-auth` runtime → `openauth-core`

| Upstream path | OpenAuth | Paridad | Notas |
| --- | --- | --- | --- |
| `src/api/index.ts` | `api/router.rs`, `api/routes/mod.rs` | Alta | `baseEndpoints` ↔ `core_auth_async_endpoints` |
| `src/api/to-auth-endpoints.ts` | `api/plugin_pipeline.rs` | Alta | Hooks before/after, errores |
| `src/api/routes/*.ts` | `api/routes/*.rs` | Alta (in-scope) | Social/oauth excluidos |
| `src/api/middlewares/origin-check.ts` | `auth/trusted_origins.rs`, router | Alta | |
| `src/api/rate-limiter/*` | `rate_limit.rs`, `options/rate_limit.rs` | Alta | |
| `src/auth/base.ts`, `full.ts`, `minimal.ts` | `openauth/src/auth.rs` | Media | Sin export `minimal` |
| `src/auth/trusted-origins.ts` | `auth/trusted_origins.rs` | Alta | |
| `src/context/create-context.ts` | `context/builder.rs` | Alta | ~400 líneas TS ↔ builder Rust |
| `src/cookies/*` | `cookies/*` | Alta | |
| `src/crypto/*` | `crypto/*` | Alta | `jwe` detrás de feature `jose` |
| `src/db/internal-adapter.ts` | `db/` stores + adapter | Alta | Lógica repartida en `session`, `user`, `verification` |
| `src/db/adapter-kysely.ts` | `db/sql/*` | Media | SQL genérico vs Kysely acoplado |
| `src/db/get-migration.ts` | `db/sql/migrations.rs` | Alta | |
| `src/integrations/*` | — | N/A | La app integra `handler()` |
| `src/client/*` | — | N/A | |
| `src/adapters/*` | crates adapter | Fuera | |
| `src/plugins/*` | `openauth-plugins` | Fuera | |
| `src/test-utils/*` | tests en `openauth-core/tests` | Parcial | Sin crate `openauth-test-utils` publicado aún |

## Fachada `openauth` ↔ paquete `better-auth` npm

| Superficie upstream | OpenAuth | Notas |
| --- | --- | --- |
| `import { betterAuth } from "better-auth"` | `open_auth()`, `OpenAuth::builder()` | `crates/openauth/src/auth.rs` |
| `auth.handler(request)` | `OpenAuth::handler` / `handler_async` | |
| Re-exports `core` en root | `lib.rs` `pub use openauth_core::…` | Curado; no 1:1 con cada subpath npm |
| `better-auth/minimal` | — | **Gap** documentado |
| Features npm por subpath | Features Cargo en `openauth` | `sqlx`, `sso`, `telemetry`, … |
| Default incluye social | `openauth-core` default: `jose`, `oauth`, `social-providers` | Fachada `openauth` no desactiva core defaults |

### Tests de fachada (referencia, no son `openauth-core`)

| Archivo | Rol |
| --- | --- |
| `crates/openauth/tests/public_api.rs` | E2E producto: builder, migraciones, hooks, features opcionales |
| `crates/openauth/tests/feature_flags.rs` | Composición de features Cargo |

## Features Cargo (`openauth-core`)

| Feature | Default | Equivalente upstream aproximado |
| --- | --- | --- |
| `jose` | sí | Uso de `jose` en cookies cache / JWE |
| `oauth` | sí | Rutas social + módulo `auth/oauth` + re-export `openauth-oauth` |
| `social-providers` | sí | `@better-auth/core/social-providers` |

Para auditorías alineadas con este doc, usar:

```toml
openauth-core = { workspace = true, default-features = false, features = ["jose"] }
```

(sin `oauth` / `social-providers`).
