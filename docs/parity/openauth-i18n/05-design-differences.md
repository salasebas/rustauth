# 05 — Diferencias de diseño y limitaciones

Documento de decisiones **intencionales** o impuestas por **Rust / server-only**. No son bugs salvo que se indique un gap pendiente.

## Server-only vs cliente TypeScript

| Tema | Upstream | OpenAuth |
| --- | --- | --- |
| `i18nClient()` | Plugin cliente sin lógica; alinea tipos con servidor | No existe crate cliente |
| Traducción en navegador | No; el servidor ya devuelve `message` traducido | Igual |
| Module augmentation | Une error codes de todos los plugins | `TranslationKey` + enums del core (`ApiErrorCode`, `AuthFlowErrorCode`) |

**Por qué:** OpenAuth no publica SDK TS generado desde Rust; las apps consumen JSON HTTP. El cliente solo necesita leer `message` ya traducido.

## Pipeline de error: throw vs mutar respuesta

| Aspecto | Better Auth | OpenAuth |
| --- | --- | --- |
| Punto de enganche | `hooks.after` sobre `ctx.context.returned` | `on_response` en `run_on_response_plugins` |
| Orden vs otros plugins | Orden de registro en cadena `after` | **Después** de todos los `hooks.after` / `async_after` del router |
| Mecanismo | `throw new APIError(status, { … })` | `serde_json` parse → mutate → re-serialize body |
| Reconocimiento error | `isAPIError` (instancia / nombre / `name`) | Status no-2xx + JSON `application/json` + `code` string |

**Por qué:** El core Rust modela errores como respuestas HTTP ya materializadas en el router. El contrato wire (`code`, `message`, `originalMessage`) se mantiene.

**Riesgo a vigilar:** otro plugin con `hooks.after` registrado **después** de i18n en Better Auth puede modificar el error tras la traducción. OpenAuth aplica i18n en `on_response` sobre el body ya pasado por todos los `after` hooks.

**Riesgo a vigilar:** respuestas de error no-JSON no se traducen en Rust (explícito). Upstream tampoco traduce fuera de `APIError`.

## README upstream vs implementación

`packages/i18n/README.md` menciona “UI strings”; **`index.ts` solo traduce errores API**. Confiar en `i18n.mdx` y el código, no en el README del paquete npm.

## Catálogo de locales (`LocaleCatalog`)

OpenAuth centraliza matching:

- Normalización **case-insensitive** (`FR-ca` → locale canónico configurado).
- **Región exacta antes que base** cuando ambas existen (`pt-BR` vs `pt`).
- Rechazo de claves duplicadas tras normalizar.

Upstream usa `Object.keys(translations)` y `includes` **case-sensitive** sin fallback de región en cookie/session (solo el parser de `Accept-Language` reduce a base tag).

**Por qué:** Evitar locales “fantasma”, mejor UX para cookies con casing distinto, y soporte BCP-47 ligero sin traer crate `accept-language` completo.

## Config fail-fast

| Caso | Upstream | OpenAuth |
| --- | --- | --- |
| `defaultLocale` inválido | Ignora al calcular; `...options` puede reintroducir valor inválido (ver [07-deep-audit.md](./07-deep-audit.md)) | Error en `i18n()` |
| `detection: []` | Sin estrategias, solo fallback | Tratado como omitido → `[Header]` |
| Cookie/field name vacío con estrategia activa | Permitido | Error de config |

**Por qué:** Preferir fallar al arrancar el servidor que servir siempre el fallback equivocado en producción.

## `resolve_user_locale` (solo Rust)

Campo extra en `I18nOptions` para estrategia `session` cuando:

- El usuario no expone un campo JSON `locale` plano, o
- La sesión se resuelve fuera de `current_session_user()`.

Upstream solo lee `ctx.context.session.user[field]`.

**Por qué:** En Rust el shape de usuario es más flexible vía adapters; el callback evita forzar un schema de user único.

## Snapshot del diccionario (`Arc`)

OpenAuth congela `translations` al registrar el plugin. Better Auth mantiene la referencia al objeto pasado en opciones; mutaciones posteriores siguen visibles.

**Por qué:** patrón Rust thread-safe para el hook `on_response`. Apps que recargan traducciones en caliente deben reconstruir el plugin o el `AuthContext`.

## Empates en `Accept-Language` (`q` igual)

Better Auth: orden estable del header. OpenAuth: `sort_by` por `q` **sin** desempate por índice — en teoría puede variar entre `de` y `fr` con el mismo `q` ([07-deep-audit.md](./07-deep-audit.md) G9).

## `getLocale` asíncrono

| | Upstream | OpenAuth |
| --- | --- | --- |
| Firma | `Promise<locale \| null> \| locale \| null` | `Fn(...) -> Option<String>` sync |

**Por qué:** `on_response` en `openauth-core` es sincrónico hoy. README del crate documenta la limitación.

**Gap pendiente (opcional):** si el core expone hooks async post-handler, reevaluar paridad con upstream.

## Diccionario tipado de error codes

Upstream construye `TranslationDictionary` como intersección de todos los `$ERROR_CODES` de plugins registrados en TypeScript.

OpenAuth usa `IndexMap<String, String>` y el trait `TranslationKey` para códigos conocidos del core.

**Por qué:** Rust no tiene registry de plugins con metadatos de error en tiempo de compilación equivalente al de Better Auth. Las apps siguen pudiendo insertar strings arbitrarios.

## Parser `Accept-Language`

| Detalle | Upstream | OpenAuth |
| --- | --- | --- |
| Tags en salida del parser | solo base (`en-US`→`en`) | tag literal (`en-US`) luego catálogo |
| `q` no numérico | NaN en sort | `1.0` |

**Por qué:** Separar parsing HTTP de matching al catálogo; tests unitarios más claros.

## Documentación upstream vs implementación

| Afirmación en docs/README | Realidad código |
| --- | --- |
| README package: “UI strings” | Solo errores API en `index.ts` |
| Test “translation is missing” | Sigue traduciendo DE porque la clave existe |

OpenAuth añade `missing_translation_leaves_error_unchanged` para cubrir el caso real.

## Qué no priorizar portar

1. **`i18nClient`** — sin valor en servidor Rust.
2. **Build `tsdown` / `attw` / exports dual** — tooling npm.
3. **Union de error codes de plugins TS** — hasta existir macro/registry Rust similar (baja prioridad).
