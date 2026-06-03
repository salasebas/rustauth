# 02 — Mapeo de paquetes y módulos

## 1:1 de paquete

| Upstream | OpenAuth | Notas |
| --- | --- | --- |
| `@better-auth/i18n` | `openauth-i18n` | Crate publicado; sin features Cargo propias |
| `@better-auth/i18n/client` | — | Excluido: server-only |
| Peer `@better-auth/core` + `better-auth` | `openauth-core` | Plugin trait, request/response, cookies, códigos de error |

## Módulo ↔ archivo

| Concepto upstream | Ubicación upstream | Equivalente Rust |
| --- | --- | --- |
| `i18n()` factory | `src/index.ts` | `src/plugin.rs` → `i18n()` |
| `parseAcceptLanguage` | `src/index.ts` (privado) | `src/accept_language.rs` |
| `detectLocale` | `src/index.ts` (privado) | `detect_locale()` en `plugin.rs` |
| Cookie parsing | `better-auth/cookies` `parseCookies` | `openauth_core::cookies::parse_cookies` vía `cookie.rs` |
| After-hook traducción | `createAuthMiddleware` + `isAPIError` | `translate_response()` en `response.rs` |
| `I18nOptions` | `src/types.ts` | `src/types.rs` |
| `TranslationDictionary` tipado | `types.ts` (union plugin error codes) | `IndexMap<String,String>` + trait `TranslationKey` |
| `PACKAGE_VERSION` | `src/version.ts` | `VERSION` / `env!("CARGO_PKG_VERSION")` en plugin metadata |
| `i18nClient` | `src/client.ts` | No portado |

## Dependencias runtime

| Upstream import | Uso | OpenAuth |
| --- | --- | --- |
| `APIError`, `isAPIError` | Reconocer error devuelto | `ApiErrorResponse` + status no success + JSON |
| `createAuthMiddleware` | Hook after | `AuthPlugin::with_on_response` |
| `parseCookies` | Estrategia cookie | `openauth_core::cookies::parse_cookies` |
| `GenericEndpointContext` | Sesión, headers, callback | `AuthContext` + `ApiRequest` |
| `BetterAuthPluginRegistry` augmentation | Tipos plugin | No aplica en Rust |

## Integración en el workspace

| Consumidor | Cómo se usa |
| --- | --- |
| Apps directas | `openauth-i18n::i18n(options)` en `OpenAuthOptions.plugins` |
| Meta-crate | `openauth` feature `i18n` → `pub use openauth_i18n as i18n` |
| Otros crates | **Ninguno** declara dependencia directa salvo `openauth` |

## Documentación y tooling upstream (referencia)

| Path | Relevancia paridad |
| --- | --- |
| `docs/content/docs/plugins/i18n.mdx` | Contrato público (detección, shape de error); alinea con servidor |
| `packages/cli/.../temp-plugins.config.ts` | Genera imports `i18n` + `i18nClient` — solo nota para portar CLI |
| `packages/i18n/CHANGELOG.md` | Historial de releases; sin lógica |

## Tamaño relativo del código

| Métrica | Upstream (servidor) | OpenAuth |
| --- | --- | --- |
| Lógica servidor (sin tests/client) | ~280 LOC TS (`index` + `types` servidor) | ~450 LOC Rust (módulos + validación catálogo) |
| Tests dedicados al paquete | 1 archivo, 15 `it` | 5 archivos, 58 `#[test]` / `#[tokio::test]` |

Rust es algo más grande por: catálogo de locales, errores de config tipados, tests de session/shaping HTTP y unit tests del parser aislados.
