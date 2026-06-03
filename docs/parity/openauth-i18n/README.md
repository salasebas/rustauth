# Paridad: `openauth-i18n` ↔ `@better-auth/i18n`

Documentación de paridad **solo servidor** entre OpenAuth y Better Auth **v1.6.9**.

| Campo | Valor |
| --- | --- |
| Upstream npm | `@better-auth/i18n@1.6.9` |
| Upstream path | `reference/upstream-src/1.6.9/repository/packages/i18n/` |
| Crate Rust | `crates/openauth-i18n` |
| Paridad pin | [`reference/upstream-better-auth/VERSION.md`](../../../reference/upstream-better-auth/VERSION.md) |
| Checklist histórico | [`docs/superpowers/plans/2026-05-12-upstream-i18n-server-checklist.md`](../../superpowers/plans/2026-05-12-upstream-i18n-server-checklist.md) |
| Docs upstream | `docs/content/docs/plugins/i18n.mdx` (en el clone) |

## Relación de paquetes

| Rol | Upstream | OpenAuth |
| --- | --- | --- |
| Plugin servidor | `@better-auth/i18n` → `i18n()` | `openauth-i18n` → `i18n()` |
| Plugin cliente | `@better-auth/i18n/client` → `i18nClient()` | **No portado** (inferencia TS; ver [05-design-differences.md](./05-design-differences.md)) |
| Errores / cookies / hooks | `better-auth/api`, `better-auth/cookies`, `@better-auth/core` | `openauth-core` (`AuthPlugin::on_response`, `parse_cookies`, `ApiErrorResponse`) |
| Re-export en meta-crate | `better-auth` (app import) | `openauth` con feature `i18n` |

**Split/merge:** no hay fusión de paquetes upstream; es **1 paquete npm → 1 crate**. La superficie cliente queda fuera de alcance por decisión server-only.

## Índice

| Documento | Contenido |
| --- | --- |
| [01-overview.md](./01-overview.md) | Resumen ejecutivo, mapa de archivos, alcance |
| [02-package-mapping.md](./02-package-mapping.md) | Archivo ↔ módulo Rust, dependencias |
| [03-public-api.md](./03-public-api.md) | API pública, opciones, tipos |
| [04-behavior-parity.md](./04-behavior-parity.md) | Tabla función por función (detección, traducción, hooks) |
| [05-design-differences.md](./05-design-differences.md) | Diferencias intencionales y limitaciones Rust |
| [06-tests.md](./06-tests.md) | Matriz Vitest ↔ Rust, gaps, comandos |
| [07-deep-audit.md](./07-deep-audit.md) | Auditoría código/tests (README upstream impreciso, pipeline, gaps) |
| [08-closure.md](./08-closure.md) | Criterio de cierre: qué no seguir portando |

## Verificación rápida

```bash
cargo fmt --all --check
cargo clippy -p openauth-i18n --all-targets -- -D warnings
cargo nextest run -p openauth-i18n
```

Última auditoría documentada: **15** tests Vitest upstream (`i18n.test.ts`) vs **64** tests `cargo nextest run -p openauth-i18n`. Ver [07-deep-audit.md](./07-deep-audit.md) y [08-closure.md](./08-closure.md).

## Estado resumido (servidor)

| Área | Paridad | Notas |
| --- | --- | --- |
| Traducción de errores API por `code` | **Alta** | Mismo shape JSON (`code`, `message`, `originalMessage`) |
| Estrategias de detección | **Alta** | `header`, `cookie`, `session`, `callback` en el mismo orden |
| `Accept-Language` + `q=` | **Alta** | Rust documenta mejoras menores en `q` inválido |
| Catálogo de locales | **Mejorada** | Case-insensitive + región exacta antes que base |
| Hook / pipeline | **≈ Equivalente** | Upstream `hooks.after` sobre `returned`; OpenAuth `on_response` **después** de todos los `hooks.after` (ver [07-deep-audit.md](./07-deep-audit.md)) |
| `getLocale` async | **Parcial** | Upstream async; Rust solo sync |
| `i18nClient` | **N/A** | Client-only; no aplica server-only |
| Tests del paquete | **Superset** | 64 tests; incl. cookie de sesión + `additional_fields`, `INVALID_ORIGIN`, `on_request` |
| Router + i18n | **Alineado** | `finalize_response(_async)` aplica `on_response` en salidas tempranas |
| Sesión → locale | **Alta** | Hidratación async con `user_output_value` (campos adicionales en DB) |
