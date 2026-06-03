# 03 — API pública y configuración

## Exports servidor

| Upstream (`@better-auth/i18n`) | OpenAuth (`openauth_i18n`) | Paridad |
| --- | --- | --- |
| `i18n(options)` | `i18n(options) -> Result<AuthPlugin, I18nConfigError>` | Equivalente; Rust valida en build del plugin |
| `I18nOptions` | `I18nOptions` + builders | Equivalente |
| `LocaleDetectionStrategy` | `LocaleDetectionStrategy` enum | Equivalente (`header`…`callback`) |
| `TranslationDictionary` | `TranslationDictionary` (`IndexMap`) | Equivalente semántico |
| `export type * from "./types"` | `pub mod types` + re-exports en root | Equivalente |
| Plugin `id: "i18n"` | `AuthPlugin::new("i18n")` | Igual |
| Plugin `version` | `with_version(CARGO_PKG_VERSION)` | Igual |
| Plugin `options` (resolved) | `with_options(serde_json::…)` metadata | Equivalente (JSON serializable) |
| `i18nClient()` | — | **N/A** client-only |

## `I18nOptions` — campos

| Campo upstream | OpenAuth | Default | Paridad |
| --- | --- | --- | --- |
| `translations` (requerido) | `translations: IndexMap<locale, dict>` | — | Igual; vacío → error |
| `defaultLocale?` | `default_locale: Option<String>` | inferido | Ver [04-behavior-parity.md](./04-behavior-parity.md) si no está en mapa |
| `detection?` | `detection: Vec<LocaleDetectionStrategy>` | `[Header]` | Igual |
| `localeCookie?` | `locale_cookie: String` | `"locale"` | Igual |
| `userLocaleField?` | `user_locale_field: String` | `"locale"` | Igual |
| `getLocale?(ctx)` async/sync | `get_locale: Option<LocaleResolver>` | `None` | **Parcial:** solo sync en Rust |
| — | `resolve_user_locale: Option<LocaleResolver>` | `None` | **Extensión Rust** para session sin acoplar al shape de `user` |

## Resolución de `defaultLocale` al construir

| Paso | Upstream | OpenAuth |
| --- | --- | --- |
| 1 | Si `defaultLocale` está en `translations` | Si `default_locale` matchea catálogo → usar |
| 2 | Si no, y existe `en` | Si no, y catálogo tiene `en` |
| 3 | Si no, primera clave de `translations` | Primera clave en `IndexMap` (orden inserción) |
| 4 | Si `translations` vacío → throw | `I18nConfigError::EmptyTranslations` |
| `defaultLocale` inválido (no en mapa) | Ignorado al resolver; spread `...options` puede dejar locale inválido en `opts` | **`UnknownDefaultLocale`** al construir |

## Helpers solo Rust

| API | Propósito |
| --- | --- |
| `translation_dictionary([(key, msg), …])` | Construir diccionario con `TranslationKey` |
| `TranslationKey` para `ApiErrorCode`, `AuthFlowErrorCode`, `str` | Sustituto pragmático del union tipado de plugins TS |
| `I18nConfigError` | Errores de config explícitos (`DuplicateLocale`, campos vacíos con estrategia activa) |
| `VERSION` | Constante de crate |

## Features Cargo

| Crate | `[features]` |
| --- | --- |
| `openauth-i18n` | *(ninguna)* |
| `openauth` | `i18n = ["dep:openauth-i18n"]` |

## Shape de error traducido (wire JSON)

Ambos documentan y producen:

```json
{
  "code": "INVALID_EMAIL_OR_PASSWORD",
  "message": "<traducido>",
  "originalMessage": "<mensaje original público>"
}
```

En Rust, `ApiErrorResponse.original_message` se serializa como `originalMessage` (`openauth-core`).

## Lo que el plugin **no** exporta

| Superficie | Motivo |
| --- | --- |
| `parse_accept_language` | Interno; cubierto por tests unitarios |
| `LocaleCatalog` | Interno |
| Endpoints / handlers | No existen upstream |
