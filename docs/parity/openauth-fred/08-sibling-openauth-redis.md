# 08 — Crate hermano: `openauth-redis` vs `openauth-fred`

Ambos crates apuntan al **mismo upstream** (`@better-auth/redis-storage`) y al **mismo contrato** `openauth-core`. La división es por **driver Redis**, no por funcionalidad de dominio auth.

## Tabla comparativa

| Capacidad | `openauth-redis` | `openauth-fred` |
| --- | --- | --- |
| Cliente | `redis-rs` `ConnectionManager` | `fred::clients::Client` |
| Secondary storage | `RedisSecondaryStorage` | `FredSecondaryStorage` |
| Rate limit store | `RedisRateLimitStore` | `FredRateLimitStore` |
| Script Lua rate limit | Idéntico | Idéntico (`RATE_LIMIT_SCRIPT`) |
| Layout claves `secondary:` / `rate-limit:` | Sí | Sí (test cruce) |
| `ttl = 0` en `set` | **`DEL`** | **`SET`** (como upstream TS) |
| `list_keys` / `clear` | **No** | **Sí** (`SCAN`) |
| Normalización Valkey URL | Sí (privado en lib) | Sí (`normalize_fred_url` público) |
| Validación prefijo vacío en get/set/delete | **No** | **Sí** |
| `scan_count` configurable | N/A | Sí (default 100) |
| Tests totales | 13 | **34** |
| E2E sign-up + Redis | No en crate | Sí |
| Documentación paridad | [openauth-redis](../openauth-redis/README.md) | Este directorio |

## Cuándo elegir cada uno

| Situación | Recomendación |
| --- | --- |
| Stack ya usa `redis-rs` / deadpool-redis | `openauth-redis` |
| Stack ya usa `fred` (alto rendimiento, cluster) | `openauth-fred` |
| Necesitas `list_keys` / `clear` en producción sin añadir código | `openauth-fred` (hoy) |
| Solo rate limit + secondary mínimo | Cualquiera; mismo contrato |
| Migración desde Better Auth con `listKeys` en tests | `openauth-fred` más cercano en utilidades |

## Duplicación de código

| Artefacto | ¿Duplicado? |
| --- | --- |
| Lua `RATE_LIMIT_SCRIPT` | Sí — mantener en sync manualmente |
| Lógica `secondary:` key | Sí — test cruce en fred |
| Módulos `config` / `url` / `error` | Paralelos, no shared crate |

**Posible evolución:** extraer script Lua + prefijos a crate interno `openauth-redis-common` — no existe hoy; duplicación aceptada por simplicidad.

## Upstream solo tiene un paquete

Better Auth no publica variante `redis-rs` vs `fred`. OpenAuth expone **dos crates** por demanda del ecosistema Rust — no por dos paquetes npm distintos.

## Paridad relativa al hermano (no al upstream)

| vs `openauth-redis` | `openauth-fred` |
| --- | --- |
| Secondary CRUD | Equivalente |
| Rate limit Lua | Equivalente |
| Utilidades admin | **Fred ahead** |
| Tests E2E auth | **Fred ahead** |
| Superficie API pública | Fred expone más helpers (`normalize_fred_url`, parse script) |

Paridad entre hermanos: **~100%** en contrato core; **Fred superset** en utilidades y tests.
