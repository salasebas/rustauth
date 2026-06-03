# 04 — Paridad de comportamiento (tabla maestra)

Leyenda: **✓** alineado · **≈** equivalente con diferencia documentada · **✗** no portado · **+** extra en OpenAuth

## Plugin y ciclo de vida

| Comportamiento | Upstream | OpenAuth | Estado | Por qué si difiere |
| --- | --- | --- | --- | --- |
| Id plugin `i18n` | ✓ | ✓ | ✓ | — |
| Sin endpoints | ✓ | ✓ | ✓ | — |
| Sin DB / migraciones | ✓ | ✓ | ✓ | — |
| Traducciones provistas por la app | ✓ | ✓ | ✓ | — |
| Diccionarios parciales por locale | ✓ | ✓ | ✓ | — |
| Códigos de error arbitrarios (`Record<string,string>`) | ✓ | ✓ | ✓ | — |
| Hook post-ejecución | `hooks.after` matcher `true` | `on_response` (tras `run_after_hooks` en router) | ≈ | TS: `returned` pre-serialización; Rust: body JSON final. **Orden multi-plugin distinto** — [07-deep-audit.md](./07-deep-audit.md) |
| Solo errores, no éxitos | `!isAPIError` early return | `status.is_success()` early return | ≈ | Mismo efecto observable |
| Requiere `code` string | ✓ | ✓ (`code` no vacío) | ✓ | — |
| Sin traducción para code | no-op | no-op | ✓ | — |
| `originalMessage` al traducir | `returned.message` | mensaje previo si `original_message` vacío | ≈ | Rust no sobrescribe `originalMessage` ya presente |
| Preservar status HTTP | ✓ | ✓ | ✓ | — |
| Preservar `code` | ✓ | ✓ | ✓ | — |

## Resolución de locale por defecto (fallback final)

| Comportamiento | Upstream | OpenAuth | Estado |
| --- | --- | --- | --- |
| Tras agotar estrategias → `defaultLocale` resuelto | ✓ | ✓ | ✓ |
| Orden: `defaultLocale` explícito válido → `en` → primera clave | ✓ | ✓ | ✓ |
| `detection` default `["header"]` | ✓ | ✓ | ✓ |
| Estrategias en orden; primera locale soportada gana | ✓ | ✓ | ✓ |
| Locale detectado pero no en `translations` | siguiente estrategia / default | `LocaleCatalog::match_locale` falla → siguiente | ✓ |

## Estrategia `header`

| Comportamiento | Upstream | OpenAuth | Estado | Notas |
| --- | --- | --- | --- | --- |
| Lee `Accept-Language` | ✓ | ✓ | ✓ | |
| Split por `,` | ✓ | ✓ | ✓ | |
| Orden por `q=` descendente | ✓ | ✓ | ✓ | |
| Sin `q=` → 1.0 | ✓ | ✓ | ✓ | |
| `q` inválido | `parseFloat` → NaN (orden impredecible) | trata como `1.0` | ≈ | **Decisión Rust:** comportamiento estable documentado en tests |
| Base tag en parser (`fr-CA`→`fr` en lista) | en `parseAcceptLanguage` | tag completo en parser; base en `LocaleCatalog` | ≈ | Resultado habitual igual; ver región exacta |
| Primer candidato en `translations` | `includes` exacto case-sensitive | `LocaleCatalog` case-insensitive | + | **Mejora Rust** |
| `fr-CA` con solo `fr` en mapa | match `fr` | match `fr` vía base | ✓ | |
| Catálogo con `pt` y `pt-BR` | no distingue (upstream ya redujo a base en header) | prefiere `pt-BR` exacto antes que `pt` | + | **Mejora Rust** (test `accept_language_prefers_exact_region_before_base_locale`) |

## Estrategia `cookie`

| Comportamiento | Upstream | OpenAuth | Estado |
| --- | --- | --- | --- |
| Header `Cookie` | ✓ | ✓ | ✓ |
| Nombre configurable (`localeCookie`) | ✓ | ✓ | ✓ |
| Valor debe existir en traducciones | `includes` exacto | `LocaleCatalog` | ≈ |
| Valores con `=` en cookie | soportado (`parseCookies`) | soportado (`parse_cookies`) | ✓ |
| Cookie ausente / locale no soportado | fall-through | fall-through | ✓ |

## Estrategia `session`

| Comportamiento | Upstream | OpenAuth | Estado |
| --- | --- | --- | --- |
| Lee `session.user[field]` | ✓ | `current_session_user()` + campo JSON | ≈ |
| Solo si string y en traducciones | ✓ | ✓ vía catálogo | ✓ |
| Sin sesión → fall-through | ✓ | ✓ | ✓ |
| Tests dedicados en paquete | **No** (0 tests) | **Sí** (5+ tests) | + |
| Hook custom de sesión | — | `resolve_user_locale` | + | **Decisión Rust:** apps con user model propio |

## Estrategia `callback`

| Comportamiento | Upstream | OpenAuth | Estado |
| --- | --- | --- | --- |
| `getLocale` / `get_locale` | `await opts.getLocale(ctx)` | sync `Fn(AuthContext, ApiRequest)` | ≈ | **Limitación Rust:** hooks de respuesta sync |
| Sin request (issue #7805) | callback puede devolver locale | callback sin headers (test dedicado) | ✓ | |
| Locale no en mapa → fall-through | ✓ | ✓ | ✓ |
| Header custom `X-Custom-Locale` | testeado | testeado | ✓ |

## Validación de configuración

| Comportamiento | Upstream | OpenAuth | Estado |
| --- | --- | --- | --- |
| `translations` vacío | throw al construir | `EmptyTranslations` | ✓ |
| `defaultLocale` no en mapa | ignorado al resolver; `...options` puede reintroducir locale inválido ([07](./07-deep-audit.md)) | `UnknownDefaultLocale` | ≈ | **Decisión Rust:** fail-fast |
| `detection: []` explícito | sin estrategias → solo `defaultLocale` | `[]` → default `[Header]` | ≈ | Edge case raro |
| Locales duplicados case-insensitive (`en`/`EN`) | permitido (comportamiento indefinido) | `DuplicateLocale` | + | **Decisión Rust** |
| `localeCookie` vacío con estrategia cookie | no validado | `EmptyLocaleCookie` | + |
| `userLocaleField` vacío con session | no validado | `EmptyUserLocaleField` | + |

## Traducción de respuesta (capa HTTP)

| Comportamiento | Upstream | OpenAuth | Estado |
| --- | --- | --- | --- |
| Solo `APIError` tipado | ✓ | JSON `application/json` error body | ≈ |
| Ignorar `text/plain` errors | implícito (solo APIError) | explícito en `translate_response` | + |
| HTTP 200 con JSON `{code,message}` | no traduce (no es APIError) | no traduce (success status) | ✓ |
| Quita/recalcula `Content-Length` | implícito al re-serializar | elimina header stale | + |
| Preserva otros headers del error | si APIError los lleva | test `translated_response_preserves_original_headers` | + |

## Cobertura del router (segunda pasada)

| Respuesta | ¿Pasa por `on_response` / i18n? |
| --- | --- |
| Error tras handler + `after` hooks | **Sí** |
| Rate limit, CSRF/origen, middleware plugin, `before` → respond | **No** ([07-deep-audit.md](./07-deep-audit.md) G8) |

## Excluido por diseño (no es gap de implementación)

| Comportamiento upstream | Motivo exclusión |
| --- | --- |
| `i18nClient()` | Client-only; inferencia TS |
| Module augmentation `BetterAuthPluginRegistry` | TS-only |
| Traducción UI / strings de formularios | No implementado en upstream package (solo errores API) |
| `getLocale` async | Pendiente hasta hooks async en core; sync documentado en README |
