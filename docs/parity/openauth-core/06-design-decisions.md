# Decisiones de diseño y divergencias intencionales

Registro de por qué OpenAuth **no** replica algo de Better Auth 1.6.9 tal cual, o lo hace en otro crate.

## Server-only

| Upstream | Decisión OpenAuth | Razón |
| --- | --- | --- |
| `better-auth/client`, React, Vue, Solid, Lynx | No implementado | Autenticación en servidor; el cliente de la app usa cookies/HTTP propios |
| `BetterAuthClientPlugin`, nanostores | No portado | Tipos solo cliente en `core/types/plugin-client.ts` |
| `Sec-Fetch` en navegador para OIDC | `fetch_metadata` en servidor | Solo donde el servidor hace fetch |

## Split de crates (no es “falta de paridad”, es empaquetado)

| Upstream (en core o better-auth) | OpenAuth | Razón |
| --- | --- | --- |
| `@better-auth/core/oauth2` | `openauth-oauth` + feature `oauth` | Límites de compilación; OAuth opcional |
| `@better-auth/core/social-providers` | `openauth-social-providers` | Misma razón; doc en otra sesión |
| `@better-auth/telemetry` | `openauth-telemetry` | Telemetría opcional y aislada |
| Plugins npm | `openauth-plugins`, SSO, SCIM, Stripe, … | Dominios separados como upstream |

## Merge en un solo crate

| Upstream | OpenAuth | Razón |
| --- | --- | --- |
| `@better-auth/core` + runtime `better-auth` | `openauth-core` | Idioma Rust: un crate con módulos; evita ciclos y duplicar versiones |
| Fachada npm `better-auth` | `openauth` | Mismo patrón: re-exports + builder |

## API y runtime

| Tema | Upstream | OpenAuth | Tipo |
| --- | --- | --- | --- |
| Llamadas directas `auth.api.*` | better-call expone RPC interno | Solo `AuthRouter` + handlers | **Diseño** — apps Rust integran HTTP o llaman servicios internos |
| `betterAuth/minimal` | Sin Kysely en init | No exportado | **Gap** menor — usar core + adapter sin SQL Kysely |
| `better-call` / Zod | Validación runtime TS | Serde + tipos Rust | **Lenguaje** — errores en compile-time donde sea posible |
| OpenAPI en router | `disabled: true` | `openapi_schema()` disponible | **Extensión** Rust |
| Forma exacta JSON de errores | Strings Better Auth | `OpenAuthError` tipado | **Diseño** — misma semántica HTTP/status; ver SERVER_PARITY.md |
| `trustedProviders` función o array | Solo `Vec<String>` estático | **Diseño** — callback dinámico pendiente API pública |
| Account linking OAuth | Política en TS | `auth/oauth/account_linking.rs` | Paridad reciente documentada en SERVER_PARITY.md |

## Infraestructura no portada en core

| Tema | Upstream | OpenAuth | Tipo |
| --- | --- | --- | --- |
| OpenTelemetry `withSpan` | `@better-auth/core/instrumentation` | No en core | **Gap** opcional — distinto de telemetría producto |
| `AsyncLocalStorage` polyfill edge | `async_hooks/pure` | `request_state` sin ALS browser | **N/A** + modelo Rust |
| Deprecation runtime warnings | `utils/deprecate.ts` | — | Bajo valor en Rust lib |
| Adapters Prisma/Drizzle/Kysely | Paquetes JS | SQLx / tokio-postgres / deadpool | **Ecosistema** — traits en core, impl en crates |

## Base de datos y SQL

| Tema | Notas |
| --- | --- |
| Kysely acoplado en full mode | Rust: SQL planificado por dialecto (`SQL_ADAPTER_PARITY.md`) |
| Wildcards en filtros | Escapado explícito vs semántica Kysely |
| Identificadores con punto | Quoting documentado en SQL_ADAPTER_PARITY.md |

## Cookies y sesión

| Tema | Upstream | OpenAuth |
| --- | --- | --- |
| Session refresh | Flags en get-session + internal checks | `disable_refresh`, `defer_refresh`, `needs_refresh` en `auth/session.rs` |
| Endpoint público `freshSessionCheck` | Solo en tests | Sin path dedicado — comportamiento interno |

## Tests y calidad

| Tema | Decisión |
| --- | --- |
| Vitest por archivo pequeño | Rust: menos archivos, tests de integración HTTP más largos |
| Property-based / fuzz | No requerido en upstream; Rust puede añadir donde haya riesgo seguridad |

## Documentos de soporte en el crate

| Archivo | Contenido |
| --- | --- |
| [`SERVER_PARITY.md`](../../../crates/openauth-core/SERVER_PARITY.md) | Linking OAuth implícito, `trusted_providers` |
| [`SQL_ADAPTER_PARITY.md`](../../../crates/openauth-core/SQL_ADAPTER_PARITY.md) | SQL vs Kysely |

## Huecos confirmados en código (no solo “falta documentar”)

Revisión jun 2026 — ver detalle en [08-gaps-audit.md](./08-gaps-audit.md):

| Hueco | Severidad | Notas |
| --- | --- | --- |
| `OpenAuthOptions` sin `app_name` | Media | Hardcoded `"OpenAuth"` |
| Sin `databaseHooks` / `hooks` top-level | Media | Solo vía `AuthPlugin` |
| Sin `onAPIError` | Media | Página `/error` fija; sin `errorURL` global |
| Password hash/verify no configurables en options | Media | Siempre scrypt en builder |
| Sin `DynamicBaseURLConfig` | Media | Multi-dominio preview |
| Sin OTEL en core | Baja | Distinto de telemetría producto |
| Rate limit paths para plugins no core | Baja | `/email-otp/*`, `/forget-password` |

## Cómo clasificar un nuevo hueco

1. **¿Es cliente o adapter JS?** → N/A o crate adapter.
2. **¿Es OAuth/social/plugin?** → Otra carpeta `docs/parity/`.
3. **¿Es limitación de Rust?** → Documentar como **Lenguaje**.
4. **¿Es elección de API más segura/simple?** → **Diseño**.
5. **¿Falta comportamiento observable?** → **Gap** con issue/tests objetivo.
