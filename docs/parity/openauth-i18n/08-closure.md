# 08 — Criterio de cierre (servidor v1.6.9)

Este documento fija **cuándo dejar de ampliar paridad** para `openauth-i18n` y qué queda fuera de alcance de forma deliberada.

## Cerrado para servidor (alto valor / hecho)

| Tema | Estado |
| --- | --- |
| Traducción de errores API (`code` → `message`, `originalMessage`) | Hecho + tests |
| Estrategias `header`, `cookie`, `session`, `callback` | Hecho + tests |
| `Accept-Language` estable (orden de empate) | Hecho |
| Salidas tempranas del router pasan por `finalize_response(_async)` | Hecho en `openauth-core` |
| i18n en 404, rate limit, `on_request` Respond, `INVALID_ORIGIN` | Tests de regresión |
| Sesión en request state para i18n (cookie → usuario) | `ensure_session_user_in_request_state` + `user_output_value` (incluye `user.additional_fields`) |
| Documentación de paridad (`docs/parity/openauth-i18n/`) | Mantenida |

## No portar (sin valor server-only o coste desproporcionado)

| Tema | Motivo |
| --- | --- |
| `i18nClient()` / `@better-auth/i18n/client` | Cliente TS; fuera de alcance Rust server |
| `getLocale` **async** (G2) | Requiere `on_response` async en el pipeline de plugins; coste transversal en core |
| Mutación en vivo del mapa `translations` (G10) | Snapshot en `Arc` al construir el plugin; más simple y seguro |
| Reordenar i18n como `hooks.after` sobre `returned` (G13–G15) | Semántica distinta pero documentada; cambiar rompería orden multi-plugin actual |
| Footguns JS de `opts = { defaults..., ...options }` | Documentados; Rust rechaza `defaultLocale` inválido |

## Seguir solo si hay requisito de producto

- Async `getLocale` + hooks async en core.
- API para recargar traducciones sin reconstruir el plugin.
- Paridad cliente (otro crate / SDK).

## Comando de verificación mínima

```bash
cargo fmt --all --check
cargo clippy -p openauth-core -p openauth-i18n --all-targets -- -D warnings
cargo nextest run -p openauth-i18n
```

Última verificación documentada: **64** tests en `openauth-i18n` (incl. regresiones router/sesión/origen).
