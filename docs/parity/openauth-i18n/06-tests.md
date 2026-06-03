# 06 — Tests y cobertura

## Conteos

| Suite | Archivos | Tests | Runner |
| --- | --- | --- | --- |
| **Upstream** | `src/i18n.test.ts` | **15** | Vitest + `better-auth/test` |
| **OpenAuth unit** | `src/accept_language.rs`, `cookie.rs`, `locale.rs`, `response.rs` | **16** | `#[test]` |
| **OpenAuth integration** | `tests/i18n.rs` | **45** (34 async + 11 sync) | `#[tokio::test]` / `#[test]` |
| **OpenAuth doctests** | `src/types.rs` | **2** | `translation_dictionary`, `I18nOptions::new` |
| **OpenAuth total** | 5 + doctests | **64** (`cargo nextest run -p openauth-i18n`) | 17 unit + 45 integration + 2 doc |

| Relación | Valor |
| --- | --- |
| Ratio aproximado | **~3.9×** más tests Rust que `it()` upstream |
| Cobertura escenarios upstream | **15/15** tienen equivalente (algunos más estrictos) |

### Upstream: grupos `describe`

| Grupo | Tests `it` |
| --- | --- |
| `locale detection from Accept-Language header` | 5 |
| `locale detection from cookie` | 1 |
| `fallback behavior` | 2 |
| `custom locale detection callback` | 2 |
| `non-error responses` | 1 |
| `defaultLocale validation` | 4 |
| **Total** | **15** |

## Matriz: upstream Vitest → Rust

| # | Upstream `it(...)` | Test OpenAuth | Notas |
| --- | --- | --- | --- |
| 1 | translate to French (`Accept-Language: fr`) | `translates_invalid_sign_in_for_accept_language_fr` | + assert `originalMessage` |
| 2 | translate to German (`de`) | `translates_for_accept_language_de` | |
| 3 | default when locale unsupported (`es`) | `falls_back_to_default_when_locale_not_in_catalog` | |
| 4 | quality values `es,fr,en` | `accept_language_quality_prefers_first_available` | |
| 5 | base locale `fr-CA` | `accept_language_region_maps_to_base_locale` | |
| 6 | cookie `lang=fr` beats header | `cookie_beats_header_when_ordered_first` | |
| 7 | “translation is missing” (DE) | `missing_translation_leaves_error_unchanged` | Upstream test **no** ejercita missing key; Rust sí |
| 8 | default without header/cookie | implícito en varios + `falls_back…` / sign-in sin header | Cubierto por escenarios default |
| 9 | `getLocale` + `X-Custom-Locale` | `callback_custom_header_locale` | |
| 10 | `getLocale` sin request (#7805) | `callback_constant_locale_without_headers` | |
| 11 | successful response unchanged | `successful_sign_in_body_not_modified` | |
| 12 | first locale sin `en` | `default_locale_first_inserted_when_no_en` | |
| 13 | explicit `defaultLocale: de` | `explicit_default_locale_de` | |
| 14 | implicit `en` | `implicit_default_en_when_present` | |
| 15 | empty translations throws | `empty_translations_rejected` | |

## Tests Rust sin equivalente upstream (por categoría)

### Session (5) — upstream **implementa** pero **no testea**

| Test | Qué valida |
| --- | --- |
| `session_resolver_locale_is_used_when_session_detection_is_enabled` | `resolve_user_locale` |
| `session_detection_reads_user_locale_field_from_request_state` | campo `user_locale_field` |
| `session_resolver_falls_through_when_absent_or_unsupported` | fall-through |
| `session_resolver_falls_through_when_it_returns_none` | `None` |
| `session_detection_falls_through_when_no_session_user_is_in_request_state` | sin sesión |
| `session_detection_reads_default_locale_field` | `user.locale` en request state |
| `session_detection_reads_locale_from_session_cookie_hydration` | cookie → DB → `additional_fields.locale` |

### Router / core (4)

| Test | Qué valida |
| --- | --- |
| `translates_not_found_on_early_router_exit` | 404 + i18n |
| `translates_rate_limit_on_early_router_exit` | rate limit + i18n |
| `translates_invalid_origin_on_security_short_circuit` | `INVALID_ORIGIN` + i18n |
| `translates_error_from_on_request_plugin_short_circuit` | `on_request` Respond + i18n |

### Cookie extra (3)

| Test | Qué valida |
| --- | --- |
| `cookie_values_containing_equals_are_supported` | `=` en valor |
| `cookie_strategy_falls_through_when_cookie_missing_or_unsupported` | fall-through |
| `cookie_strategy_falls_through_when_cookie_is_missing` | ausente |

### Accept-Language / catálogo (2)

| Test | Qué valida |
| --- | --- |
| `accept_language_prefers_exact_region_before_base_locale` | `pt-BR` vs `pt` |
| `accept_language_matches_locale_case_insensitively` | casing |

### Callback fall-through (2)

| Test | Qué valida |
| --- | --- |
| `callback_falls_through_when_none_or_unsupported` | |
| `callback_falls_through_when_it_returns_none` | |

### Config / API (6)

| Test | Qué valida |
| --- | --- |
| `unknown_default_locale_rejected` | fail-fast |
| `duplicate_locales_after_normalization_are_rejected` | |
| `empty_locale_cookie_is_rejected_when_cookie_detection_is_enabled` | |
| `empty_user_locale_field_is_rejected_when_session_detection_is_enabled` | |
| `options_builder_methods_configure_public_options` | builders |
| `options_debug_hides_callback_internals` | Debug |
| `detection_strategy_deserialization_rejects_unknown_values` | serde |
| `options_default_user_locale_field_is_locale` | default |
| `plugin_exposes_resolved_serializable_options_metadata` | metadata plugin |

### Response shaping (6)

| Test | Qué valida |
| --- | --- |
| `non_string_error_code_leaves_error_unchanged` | code vacío / inválido |
| `translated_response_preserves_original_headers` | headers |
| `translated_response_removes_stale_content_length` | `Content-Length` |
| `text_plain_response_is_not_translated` | content-type |
| `arbitrary_json_with_code_and_message_is_not_translated` | HTTP 200 JSON |
| `existing_original_message_is_preserved` | no pisar `originalMessage` |

### Tipado (1)

| Test | Qué valida |
| --- | --- |
| `translation_dictionary_accepts_typed_core_error_codes` | `AuthFlowErrorCode` |

### Unit: `accept_language.rs` (7)

Parser aislado: vacío, `q` order, región, empates, espacios, `q` default, `q` inválido.

### Unit: `cookie.rs` (3), `locale.rs` (4), `response.rs` (2)

Ver archivos fuente; no existen como tests separados upstream (lógica embebida en `index.ts`).

## Gaps de cobertura

| Área | Upstream | OpenAuth | Prioridad |
| --- | --- | --- | --- |
| Session `user.locale` (campo default) | código sin tests | **cubierto** (`session_detection_reads_default_locale_field`, hidratación cookie) | — |
| Estrategia `session` en general | código sin tests | 5 tests otros escenarios | — |
| `getLocale` async | soportado, sin test async | no soportado | media si core async |
| Fixture `USER_NOT_FOUND` en upstream | en objeto, **nunca usado** en `it` | N/A | info |
| Errores con headers raros en APIError | parcial | test headers | baja |
| Integración multi-plugin error-code union | tipos TS | manual per app | baja |
| Orden `hooks.after` vs `on_response` | — | no test multi-plugin | baja |

## Tests fuera del crate

| Test | Crate | Notas |
| --- | --- | --- |
| `i18n_feature_reexports_i18n_crate` | `openauth` | feature `i18n` re-export |

## Comando de regresión

```bash
cargo fmt --all --check
cargo clippy -p openauth-i18n --all-targets -- -D warnings
cargo nextest run -p openauth-i18n
```

## Qué no testea el paquete i18n

| Tema | Dónde debería vivir |
| --- | --- |
| Mensajes en inglés del core | `openauth-core` error catalog |
| Traducción de errores de **otros** plugins sin diccionario app | responsabilidad de la app |
| Cliente TS / `i18nClient` | N/A |
| CLI init plugin scaffold | `openauth-cli` (futuro) |
