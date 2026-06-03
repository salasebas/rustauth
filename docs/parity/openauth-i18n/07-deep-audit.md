# 07 — Auditoría profunda (código + tests, no README)

Revisión línea a línea contra `reference/upstream-src/1.6.9/repository/packages/i18n/` y `crates/openauth-i18n/`. Los README upstream mencionan **“UI strings”** pero **ni `index.ts` ni `i18n.mdx` implementan traducción de UI** — solo mensajes de error API.

## Inventario exhaustivo upstream

| Path | ¿Runtime? | Notas |
| --- | --- | --- |
| `src/index.ts` | Sí | Única lógica servidor |
| `src/types.ts` | Tipos | Union de `$ERROR_CODES` de plugins |
| `src/client.ts` | Cliente | `i18nClient`, sin traducción |
| `src/version.ts` | Metadata | `PACKAGE_VERSION` (no re-exportado en `index.ts`) |
| `src/i18n.test.ts` | Tests | **15** `it()`, **0** archivos de test más |
| `vitest.config.ts` | Tooling | `clearMocks`, `restoreMocks` |
| `tsdown.config.ts` | Build | Entradas `index.ts` + `client.ts` |
| `package.json` | Manifest | Exports `.` y `./client`; peers `core` + `better-auth` |
| `CHANGELOG.md` | Release | Paquete nace en **1.6.0** (#8836) |
| `README.md` | Marketing | **Incorrecto** sobre UI strings |

**Referencias fuera del paquete (no son lógica i18n):**

| Path | Uso |
| --- | --- |
| `docs/content/docs/plugins/i18n.mdx` | Contrato público (228 líneas) |
| `packages/cli/.../temp-plugins.config.ts` | Scaffold `i18n` + `i18nClient` |
| `docs/content/blogs/1-5.mdx` | Anuncio plugin |
| `docs/content/docs/plugins/index.mdx` | Tabla de plugins |

**No hay** tests Vitest en otros paquetes para i18n. **No hay** i18n embebido en `packages/better-auth/src/plugins/`.

## Inventario exhaustivo OpenAuth

| Path | Tests |
| --- | --- |
| `src/lib.rs` | — |
| `src/plugin.rs` | — |
| `src/types.rs` | 2 doctests (`cargo test --doc`) |
| `src/accept_language.rs` | 7 unit |
| `src/cookie.rs` | 3 unit |
| `src/locale.rs` | 4 unit |
| `src/response.rs` | 2 unit |
| `tests/i18n.rs` | 42 integración |
| `tests/common/mod.rs` | helpers (sin tests) |

**Conteo verificado:** `cargo test -p openauth-i18n -- --list` → **60** entradas (= **58** `#[test]`/`#[tokio::test]` + **2** doctests).

**Tests fuera del crate:** `crates/openauth/tests/public_api.rs` (`i18n_feature_reexports_i18n_crate`, feature `i18n`).

## Hallazgo crítico: enganche en el pipeline HTTP

| | Better Auth | OpenAuth |
| --- | --- | --- |
| Mecanismo | `hooks.after` + `createAuthMiddleware` | `AuthPlugin::with_on_response` |
| Momento | Inspecciona `ctx.context.returned` (objeto error **antes** de serializar respuesta HTTP) | Mutación del **body JSON** de `ApiResponse` ya construida |
| Orden en router OpenAuth | N/A | `run_after_hooks` → `run_async_after_hooks` → **`run_on_response_plugins`** |

```text
OpenAuth handle_async (async endpoint):
  … handler …
  → run_after_hooks (todos los plugins, matchers)
  → run_async_after_hooks
  → run_on_response_plugins  ← i18n vive aquí
```

**Implicación:** i18n en Rust corre **después** de todos los `hooks.after` de otros plugins. En Better Auth, i18n compite en la cadena `after` según **orden de registro** de plugins. No es idéntico si otro plugin tiene `after` que altera errores **después** de i18n upstream.

**Equivalencia observable:** para el flujo típico (error API → JSON), el cliente ve el mismo shape. La diferencia importa para composición multi-plugin.

## Hallazgo: bug / pie footgun upstream en `opts`

En `index.ts`, tras calcular `defaultLocale` válido:

```ts
const opts = {
  defaultLocale,
  detection: ["header"],
  localeCookie: "locale",
  userLocaleField: "locale",
  ...options,  // ← puede sobrescribir defaultLocale con valor NO presente en translations
};
```

Si el usuario pasa `defaultLocale: "xx"` inválido, **`opts.defaultLocale` puede quedar en `"xx"`** y `detectLocale` devuelve ese valor al final. La lookup `translations[locale]` falla → **no traduce** (mensaje core inglés).

OpenAuth: `default_locale` inválido → **`I18nConfigError::UnknownDefaultLocale`** al construir el plugin.

## Hallazgo: `detection: []`

| | Upstream | OpenAuth |
| --- | --- | --- |
| `detection: []` | Bucle vacío → cae en `opts.defaultLocale` | `detection.is_empty()` → **`[Header]`** |

Comportamiento distinto si la app pasa array vacío explícitamente (raro).

## Paridad línea a línea: `parseAcceptLanguage` / `parse_accept_language`

| Comportamiento | Upstream `index.ts` | OpenAuth |
| --- | --- | --- |
| Sin header | `[]` | `[]` |
| Split `,` | Sí | Sí |
| `q=` sort descendente | Sí | Sí |
| Sin `q` | `q=1` implícito | `1.0` |
| `q` inválido | `NaN` (orden inestable) | **`1.0`** (testeado) |
| Tag en salida | **Solo base** (`fr-CA`→`fr` en el parser) | **Tag literal** (`fr-CA` queda); base en `LocaleCatalog` |
| Match contra catálogo | `availableLocales.includes(l)` **case-sensitive** | `LocaleCatalog` **case-insensitive** + base + **exacto región antes que base** |

**Docs `i18n.mdx` líneas 88–92:** dicen probar `fr-CA` luego `fr` luego `en`. El **código** upstream solo genera tags base en el parser (`split("-")[0]`), no dos entradas `fr-CA` y `fr` — la documentación upstream es **imprecisa** respecto al código.

## Paridad: estrategias

### `header`

- Upstream: `ctx.headers?.get("Accept-Language")`
- OpenAuth: `request.headers().get("accept-language")` (hyper, case-insensitive)
- **Paridad efectiva:** sí, con mejoras de catálogo en Rust.

### `cookie`

- Upstream: `parseCookies` con `split("; ")` y `split(/=(.*)/s)` ([`cookies/index.ts`](../../../reference/upstream-src/1.6.9/repository/packages/better-auth/src/cookies/index.ts) L359–367)
- OpenAuth: `parse_cookies` con `split("; ")` y `split_once('=')` — **misma semántica** para `=` en el valor (test `cookie_values_containing_equals_are_supported`).

### `session`

| | Upstream | OpenAuth |
| --- | --- | --- |
| Fuente | `ctx.context.session?.user[field]` | `current_session_user()` → JSON field **o** `resolve_user_locale` primero |
| Tipo locale | `typeof === "string"` | `.as_str()` en `serde_json::Value` |
| Tests en paquete | **0** | 5+ integración |

**Gap de test Rust (paridad upstream):** no hay test que use `user_locale_field: "locale"` (default) leyendo `user.locale === "fr"` como en `i18n.mdx`. El test `session_detection_reads_user_locale_field_from_request_state` usa campo **`email`** a propósito, no `locale`.

**Extensión solo Rust:** `resolve_user_locale` no existe upstream.

### `callback`

| | Upstream | OpenAuth |
| --- | --- | --- |
| Async | `await getLocale(ctx)` | Sync `get_locale(ctx, request)` |
| Contexto | `GenericEndpointContext` (headers, session, request opcional) | `AuthContext` + `ApiRequest` |
| Sin request (#7805) | Testeado upstream | `callback_constant_locale_without_headers` |

## Paridad: traducción

| Condición | Upstream | OpenAuth |
| --- | --- | --- |
| Disparador | `isAPIError(returned)` + `typeof code === "string"` | `!status.is_success()` + JSON + `code` string no vacío |
| Sin traducción | `return` (sin throw) | `translate_response` → `Ok(false)` |
| Con traducción | `throw new APIError(status, { code, message, originalMessage })` | Mutar `message`, set `original_message` si ausente |
| `originalMessage` ya presente | N/A en tests | **Preservado** (test explícito; upstream no testea) |
| Éxito 2xx | No toca | No toca (`is_success`) |
| 200 + JSON con `code` | No aplica (no APIError) | **No traduce** (test `arbitrary_json_with_code_and_message_is_not_translated`) |
| `Content-Type` no JSON | Implícito | Requiere `application/json` (test `text/plain`) |
| `Content-Length` stale | — | Eliminado al re-serializar (test) |
| Headers custom en error | Si APIError los lleva | Test `X-Custom-Error` preservado |
| `code` numérico en JSON | Ignorado (`typeof`) | `serde` falla → no traduce (test `non_string_error_code`) |

## Plugin metadata `options`

| | Upstream | OpenAuth |
| --- | --- | --- |
| `plugin.options` | Objeto completo `opts` (incluye **`translations` completos**) | JSON resumido: `defaultLocale`, `detection`, `localeCookie`, `userLocaleField`, `translationLocales` (solo claves) |

No expone el diccionario completo en metadata — **diferencia menor** (introspección / logging).

## Tests upstream: lista canónica (15)

| # | Nombre `it` | ¿Assert `originalMessage`? |
| --- | --- | --- |
| 1 | French Accept-Language | **Sí** |
| 2 | German Accept-Language | No |
| 3 | Unsupported locale → default | No |
| 4 | Quality values | No |
| 5 | `fr-CA` → French message | No |
| 6 | Cookie `lang=fr` | No |
| 7 | “translation is missing” | No — **sigue traduciendo DE** (nombre engañoso) |
| 8 | Default sin header | No |
| 9 | Callback custom header | No |
| 10 | Callback sin request | No |
| 11 | Success getSession | No |
| 12 | First locale sin `en` | No |
| 13 | Explicit `defaultLocale: de` | No |
| 14 | Implicit `en` | No |
| 15 | Empty translations throws | N/A |

**Códigos de error usados en tests upstream:** solo `INVALID_EMAIL_OR_PASSWORD` en flujos reales. Las entradas `USER_NOT_FOUND` / `INVALID_PASSWORD` en el fixture **no se ejercitan** en ningún `it`.

## Gaps reales (accionables)

| ID | Tipo | Descripción | Severidad |
| --- | --- | --- | --- |
| G1 | Test Rust | ~~Falta test session + `user.locale`~~ | **Cerrado** |
| G2 | Paridad | `getLocale` async | Baja (documentado) |
| G3 | Composición | `on_response` vs orden `hooks.after` multi-plugin | Baja (documentar) |
| G4 | Upstream | `...options` sobrescribe `defaultLocale` inválido | Info (no portar bug) |
| G5 | Upstream | `detection: []` vs default `[header]` en Rust | Info |
| G6 | Docs | README package upstream “UI strings” | N/A |
| G7 | PORTING.md | Lista `openauth-i18n` como **“Scaffold”** — **desactualizado** respecto al crate real | Docs repo |
| G8 | Router | ~~`on_response` omitido en salidas tempranas~~ | **Cerrado** — `finalize_response` / `finalize_response_async` en `router.rs` |
| G9 | Parser | ~~`sort_by` inestable~~ | **Cerrado** — desempate por índice de inserción en `accept_language.rs` |
| G1 | Test session `user.locale` | **Cerrado** — `session_detection_reads_default_locale_field` |
| G10 | Config | Snapshot `Arc` vs referencia viva a `translations` | Info |
| G11 | Session | User en request state | **Cerrado** — `ensure_session_user_in_request_state` + `user_output_value` (incl. `user.additional_fields`); test `session_detection_reads_locale_from_session_cookie_hydration` |
| G12 | Wire | `originalMessage` desde campo APIError vs JSON | Baja |
| G13 | Upstream JS | `detection: undefined` rompe loop | Info |
| G14 | Content-Type | JSON estricto en Rust | Baja |
| G15 | Hooks | Orden user-after → plugin-after (BA) vs after → on_response (OA) | Baja |

## Lo que NO falta (falsos alarmas descartados)

- Paquetes extra upstream de i18n: **no existen**.
- Tests Vitest adicionales: **solo** `i18n.test.ts`.
- Rate limit `on_response` antes de plugins: **no-op** en core (`on_response_rate_limit` retorna `Ok(())`).
- `PACKAGE_VERSION` export público: **no** en barrel `index.ts` upstream; Rust `VERSION` en crate root es equivalente opcional.
- Redirect errors / HTML: ninguno de los dos plugins traduce.
- Feature flags en crate i18n: ninguna (correcto).

## Matriz rápida docs oficiales (`i18n.mdx`) vs código

| Afirmación en mdx | Código upstream | OpenAuth |
| --- | --- | --- |
| Solo errores, no éxito | ✓ | ✓ |
| Fallback si falta traducción → inglés core | ✓ (no-op hook) | ✓ |
| `ctx.request` puede ser undefined | ✓ callback | ✓ callback test |
| Session `user.locale` field | ✓ en `index.ts` | ✓ en `plugin.rs`, **test incompleto** (G1) |
| Lista de error codes ejemplo | Documentación | Apps + `TranslationKey` |

## Segunda pasada (auditoría adicional)

### G8 — `on_response` no corre en respuestas cortocircuitadas (OpenAuth)

En `openauth-core` [`router.rs`](../../../crates/openauth-core/src/api/router.rs), `run_on_response_plugins` solo se invoca al final del camino **handler → after hooks**. Muchas salidas hacen `return Ok(response)` **sin** pasar por i18n:

| Salida temprana | Ejemplo de error | ¿Traducible con i18n hoy? |
| --- | --- | --- |
| `run_on_request_plugins` → `Respond` | Plugin responde directo | **No** |
| `validate_request_security` | `INVALID_ORIGIN`, CSRF, etc. | **No** |
| `consume_rate_limit` / `on_request_rate_limit` | `TOO_MANY_REQUESTS` | **No** |
| `run_matching_middlewares` / async | CAPTCHA u otro plugin middleware | **No** |
| `run_endpoint_middlewares` | Middleware por endpoint | **No** |
| `before` / `async_before` → `Respond` | Hook corta antes del handler | **No** |
| `validate_async_endpoint_request` | Validación previa al handler | **No** |
| `api_error(NOT_FOUND)` en rutas deshabilitadas | `NOT_FOUND` | **No** |

**Better Auth:** i18n está en `hooks.after`, que solo corre tras ejecutar el handler en [`to-auth-endpoints.ts`](../../../reference/upstream-src/1.6.9/repository/packages/better-auth/src/api/to-auth-endpoints.ts) (tras asignar `context.returned`). Errores que devuelven `Response` antes del handler tampoco pasan por i18n.

**Conclusión:** paridad similar para “errores de frontera” (rate limit, seguridad, middleware). Para traducir `TOO_MANY_REQUESTS` u `INVALID_ORIGIN`, la app debe asegurar que el error pase por el pipeline con hooks — o aceptar mensajes core sin traducción.

### G9 — Orden estable en empates de `q` (`Accept-Language`)

Upstream usa `Array.prototype.sort` (estable en ES2019+): `de;q=0.8, fr;q=0.8` → prueba `de` antes que `fr`.

OpenAuth usa `entries.sort_by` en [`accept_language.rs`](../../../crates/openauth-i18n/src/accept_language.rs) — **`sort_by` no es estable** en Rust. Con el mismo `q`, el orden entre `de` y `fr` **puede variar** entre ejecuciones si ambos están en el catálogo.

El test `preserves_quality_tie_order` pasa hoy, pero no garantiza estabilidad del lenguaje. **Recomendación:** `sort_by` con índice de inserción como desempate.

### G10 — Diccionario `translations` inmutable tras `i18n()`

Upstream cierra sobre `opts.translations` (referencia al objeto del usuario). Mutar el mapa después de registrar el plugin **afecta** traducciones futuras.

OpenAuth hace `Arc::new(options.translations)` al construir el plugin. Cambios posteriores al `IndexMap` del llamador **no** se ven.

**Tipo:** diferencia de diseño Rust (snapshot) vs JS (referencia viva).

### G11 — Session: `ctx.context.session` vs `current_session_user()`

| | Better Auth | OpenAuth |
| --- | --- | --- |
| Fuente session strategy | `ctx.context.session?.user[field]` | `current_session_user()` en request state |
| Cuándo hay user | Tras middleware de sesión del endpoint (`sessionMiddleware`, etc.) | Tras `current_session()` / `sensitive_session()` en ese request |

No hay middleware global que llene `current_session_user` en **todos** los requests con cookie. Rutas que fallan **antes** de `current_session()` no tendrán session strategy — en BA ocurre lo mismo si el endpoint no montó sesión en el contexto.

`resolve_user_locale` sigue siendo la extensión para cargar locale sin depender de request state.

### G12 — `originalMessage` desde `.message` del error vs body JSON

Upstream: `originalMessage: returned.message` (propiedad del objeto `APIError` de better-call).

OpenAuth: clona `error.message` del JSON deserializado.

Si en algún pipeline `.message` ≠ body serializado, podría divergir. En OpenAuth core, `auth_flow_error_response` mantiene ambos alineados.

### G13 — `detection: undefined` en spread upstream

Si `options` incluye `detection: undefined`, el spread `{ detection: ["header"], ...options }` deja `opts.detection === undefined` y `for (const strategy of opts.detection)` lanza en runtime. OpenAuth no expone este footgun TS/JS.

### G14 — Errores sin `Content-Type: application/json`

`translate_response` exige `application/json`. El core OpenAuth usa `json_response` / `auth_flow_error_response` con content-type correcto en flujos normales. Respuestas de error ad-hoc sin header **no** se traducen (más estricto que upstream que filtra por `isAPIError`).

### G15 — Orden de `after` hooks en Better Auth

En `getHooks()` ([`to-auth-endpoints.ts`](../../../reference/upstream-src/1.6.9/repository/packages/better-auth/src/api/to-auth-endpoints.ts) ~512–549): hooks globales del usuario primero, luego hooks `after` de plugins en **orden de registro**. i18n compite con otros plugins en esa lista.

OpenAuth: todos los `hooks.after` primero, luego **todos** los `on_response` (i18n solo usa esto).

---

## Comandos de verificación usados en esta auditoría

```bash
./scripts/fetch-upstream-better-auth.sh
grep -r "i18n" reference/upstream-src/1.6.9/repository/packages/i18n reference/upstream-src/1.6.9/repository/packages/cli --include="*.ts"
grep -c '^\s*it(' reference/upstream-src/1.6.9/repository/packages/i18n/src/i18n.test.ts
cargo test -p openauth-i18n -- --list
```
