# Paridad por módulo

Tablas **solo servidor**, sin OAuth2 proveedor, social providers ni plugins npm.

**Leyenda:** ✅ Alta · 🟡 Media · 🔴 Baja / gap · ➖ N/A (diseño server-only o split a otro crate)

## API y router

| Capacidad | Upstream | OpenAuth | Estado | Notas |
| --- | --- | --- | --- | --- |
| Factory endpoint + middleware | `@better-auth/core/api` | `api/endpoint.rs` | ✅ | Sin `better-call`; tipos propios |
| Router HTTP | `better-call` + `api/index.ts` | `api/router.rs` | ✅ | `AuthRouter::handler` |
| Pipeline hooks | `to-auth-endpoints.ts` | `api/plugin_pipeline.rs` | ✅ | before/after, errores |
| Body / query parsing | better-call | `api/body.rs` | ✅ | Tests `tests/api/body.rs` |
| OpenAPI | Desactivado por defecto | `api/openapi.rs` | 🟡 | Rust genera schema; upstream plugin open-api aparte |
| Conflictos de path plugins | `check-endpoint-conflicts.test.ts` | `tests/api/plugin_router.rs` | ✅ | |

## Auth (sesión HTTP, email/password, orígenes)

| Capacidad | Upstream | OpenAuth | Estado | Notas |
| --- | --- | --- | --- | --- |
| Resolver sesión desde cookie | `cookies` + `session.ts` routes | `auth/session.rs` | ✅ | `needs_refresh`, `defer_refresh` |
| Email/password helpers | rutas + crypto | `auth/email_password.rs` | ✅ | Tests `tests/auth/email_password.rs` |
| Trusted origins | `auth/trusted-origins.ts` | `auth/trusted_origins.rs` | ✅ | Tests `tests/utils/trusted_origins.rs` |
| OAuth linking policy | `oauth2/link-account.ts` | `auth/oauth/account_linking.rs` | ➖ | Feature `oauth`; ver SERVER_PARITY.md |
| Producto `betterAuth()` | `auth/full.ts` | `openauth::OpenAuth` | 🟡 | En crate fachada |
| Modo `minimal` (sin Kysely) | `auth/minimal.ts` | — | 🔴 | Sin equivalente exportado |

## Context y secrets

| Capacidad | Upstream | OpenAuth | Estado | Notas |
| --- | --- | --- | --- | --- |
| Bootstrap `AuthContext` | `create-context.ts` | `context/builder.rs` | ✅ | Tests `tests/context/runtime.rs` (15 tests) |
| Request state ALS | `context/request-state.ts` | `context/request_state.rs` | ✅ | Tests dedicados (10) |
| Secret material / rotation config | `secret-utils`, crypto | `context/secrets.rs`, `crypto/` | ✅ | |
| Plugin init merge | plugins init | `context/plugins.rs`, `plugin/init.rs` | ✅ | disabled_paths, rate rules |
| `getCurrentAdapter()` | core context | Acceso vía `AuthContext` | ✅ | Patrón Rust explícito |

## Cookies

| Capacidad | Upstream | OpenAuth | Estado | Notas |
| --- | --- | --- | --- | --- |
| Nombres / prefijos | `cookies/index.ts` | `cookies/config.rs`, `types.rs` | ✅ | |
| Firma HMAC | cookie-utils | `cookies/signing.rs` | ✅ | |
| Chunked cookies | sí | `cookies/chunked.rs` | ✅ | |
| Session store en cookie | `session-store.ts` | `cookies/session.rs` | ✅ | |
| Cookie cache cifrado | JWE | `cookies/cache.rs` (`jose`) | ✅ | 1 unit test + suite integration |
| Tests integración | `cookies.test.ts` (~65 it) | `tests/cookies/*` (~31 tests) | 🟡 | Rust menos casos que upstream |

## Crypto

| Capacidad | Upstream | OpenAuth | Estado | Notas |
| --- | --- | --- | --- | --- |
| Password hash (scrypt) | `crypto/password.ts` | `crypto/password.rs` | ✅ | |
| JWT sign/verify | `crypto/jwt.ts` | `crypto/jwt.rs` | ✅ | |
| Secret rotation | `secret-rotation.test.ts` | `crypto/secret_rotation` tests | ✅ | |
| Random / buffer | `random.ts`, `buffer.ts` | `crypto/random.rs`, `buffer.rs` | ✅ | |
| JWE envelope | jose en TS | `crypto/jwe.rs` (feature `jose`) | ✅ | |
| Symmetric secrets | envelope | `crypto/symmetric.rs`, `envelope.rs` | ✅ | |

## DB y almacenamiento

| Capacidad | Upstream | OpenAuth | Estado | Notas |
| --- | --- | --- | --- | --- |
| Tablas auth core | `core/db/schema` | `db/schema/` | ✅ | user, session, account, verification, rateLimit |
| Adapter trait + factory | `core/db/adapter` | `db/adapter/`, `factory.rs` | ✅ | Contract tests extensos |
| Internal adapter CRUD | `internal-adapter.ts` | `session`, `user`, `verification` + adapter | ✅ | |
| Memory adapter | `@better-auth/memory-adapter` | `db/memory.rs` | ✅ | |
| SQL / migraciones | Kysely + `get-migration` | `db/sql/migrations.rs`, `statements.rs` | 🟡 | Dialectos SQL explícitos; ver SQL_ADAPTER_PARITY.md |
| Secondary storage | opciones + internal adapter | `options` + `verification` + rate limit | 🟡 | Paridad funcional; API distinta |
| DB hooks pipeline | `with-hooks.ts` | `db/hooks/pipeline.rs` | ✅ | |
| to-zod / field helpers | `to-zod.ts`, `field*.ts` | schema builder Rust | 🟡 | Sin Zod; tipos compile-time |
| Join adapter | implícito en queries | `db/factory/join_support.rs` | ✅ | Extensión Rust para plugins |

## Options (configuración)

Matriz campo a campo: [07-options-field-matrix.md](./07-options-field-matrix.md).

| Capacidad | Upstream | OpenAuth | Estado | Notas |
| --- | --- | --- | --- | --- |
| `BetterAuthOptions` monolito TS | `types/init-options` | `options/root.rs` + submódulos | 🟡 | Faltan `appName`, `databaseHooks`, `hooks`, `onAPIError`, `logger` |
| session / user / email | tipos core | `options/session.rs`, etc. | ✅ | `tests/options.rs` (8) |
| rateLimit | core + plugin | `options/rate_limit.rs` | ✅ | |
| account linking opts | tipos | `options/account.rs` | 🟡 | OAuth fields gated |
| advanced (skip slashes, …) | sí | `options/advanced.rs` | 🟡 | Revisar campo a campo al portar |
| telemetry.* | core types | en `openauth-telemetry` + snapshot en context | ➖ | Crate aparte |

## Plugin system (solo contrato en core)

| Capacidad | Upstream | OpenAuth | Estado | Notas |
| --- | --- | --- | --- | --- |
| `BetterAuthPlugin` type | `core/types/plugin.ts` | `plugin.rs`, `AuthPlugin` | ✅ | |
| Endpoints / middleware plugin | sí | `plugin/endpoint.rs` | ✅ | |
| Schema / migrations plugin | `core/db/plugin` | `plugin/schema.rs`, `db/migration.rs` | ✅ | |
| Password validators | plugins | `plugin/password.rs` | ✅ | `password_validators.rs` tests |
| Rate limit rules plugin | sí | `plugin/rate_limit.rs` | ✅ | |
| DB hooks | sí | `plugin/db/handler.rs` | ✅ | |
| Implementaciones (admin, org, …) | `better-auth/plugins` | `openauth-plugins` | ➖ | Fuera de alcance |

## Rate limiting

| Capacidad | Upstream | OpenAuth | Estado | Notas |
| --- | --- | --- | --- | --- |
| In-memory store | rate-limiter | `rate_limit.rs` + governor | ✅ | |
| Secondary storage backend | Redis package | `RateLimitStore` trait | 🟡 | `openauth-redis` fuera de core |
| IP / path keys | utils/ip | `utils/ip.rs` + rate_limit | ✅ | |
| disabled_paths bypass | sí | tests dedicados | ✅ | |

## User, session (DB), verification

| Capacidad | Upstream | OpenAuth | Estado | Notas |
| --- | --- | --- | --- | --- |
| Session store | internal adapter | `session.rs` | ✅ | `tests/db/session_store.rs` |
| User store | internal adapter | `user/` | ✅ | `tests/db/user_store.rs` |
| Verification tokens | internal adapter | `verification.rs` | ✅ | secondary storage opcional |
| Additional fields | plugin + routes | `api/additional_fields.rs` | 🟡 | |

## Utils

| Capacidad | Upstream | OpenAuth | Estado | Notas |
| --- | --- | --- | --- | --- |
| Host / SSRF | `core/utils/host` | `utils/host.rs` | ✅ | |
| IP / rate limit keys | `core/utils/ip` | `utils/ip.rs` | ✅ | |
| URL / base path | `better-auth/utils/url` | `utils/url.rs`, `utils/host.rs` | ✅ | `url.test.ts` (66 it) vs tests utils Rust (27) |
| Fetch metadata | `core/utils/fetch-metadata` | `utils/fetch_metadata.rs` | ✅ | |
| Deprecation helper | `deprecate.ts` | — | 🔴 | Bajo impacto servidor |

## Env / errors

| Capacidad | Upstream | OpenAuth | Estado | Notas |
| --- | --- | --- | --- | --- |
| Logger niveles | `core/env/logger` | `env/logger.rs` | ✅ | |
| `isDevelopment` | env-impl | `env.rs` | ✅ | |
| `APIError` / codes | `core/error` | `error.rs` | ✅ | Códigos alineados donde aplica |
| `secret` redaction | tipos | `secret.rs` | ✅ | Rust `Debug` redacted |

## Instrumentación y telemetría

| Capacidad | Upstream | OpenAuth | Estado | Notas |
| --- | --- | --- | --- | --- |
| OpenTelemetry spans en endpoints | `core/instrumentation` | — | 🔴 | No en core |
| Spans en router better-auth | `api/index.ts` | — | 🔴 | |
| Telemetría producto anónima | `@better-auth/telemetry` | `openauth-telemetry` | ➖ | [docs/parity/openauth-telemetry](../openauth-telemetry/README.md) |

## Cliente y frameworks

| Capacidad | Upstream | OpenAuth | Estado | Notas |
| --- | --- | --- | --- | --- |
| `better-auth/client` | sí | — | ➖ | Server-only |
| React / Vue / … | sí | — | ➖ | |
| Next.js / Node handlers | `integrations/*` | App usa `handler()` | ➖ | Por diseño |
