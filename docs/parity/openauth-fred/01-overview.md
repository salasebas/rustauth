# 01 — Resumen ejecutivo

## Qué es cada lado

**Upstream (`@better-auth/redis-storage`)** es un adaptador mínimo (~75 líneas en `redis-storage.ts`) que implementa `SecondaryStorage` de `@better-auth/core` sobre un cliente **ioredis** inyectado. Añade `listKeys()` y `clear()` usando Redis `KEYS`. No implementa rate limiting: el core de Better Auth, cuando hay `secondaryStorage`, suele usar `rateLimit.storage = "secondary-storage"` y guarda objetos `RateLimit` como **strings JSON** bajo el mismo prefijo global que sesiones y verificación.

**OpenAuth (`openauth-fred`)** es el mismo rol de adaptador, pero con el cliente Rust **`fred`** (crates.io), organizado en módulos (`config`, `storage`, `store`, `script`, `url`, `error`). Expone:

1. **`FredSecondaryStorage`** — trait `SecondaryStorage` de `openauth-core`, con `list_keys()` y `clear()` basados en `SCAN`.
2. **`FredRateLimitStore`** — trait `RateLimitStore` con script Lua atómico (idéntico al de `openauth-redis`).

Es un crate **opt-in**; el facade `openauth` no lo enlaza por defecto. El ejemplo `examples/full-app` lo usa para backends `fred-redis` y `fred-valkey`.

## Mapa de código

| Upstream | OpenAuth (`openauth-fred`) |
| --- | --- |
| `packages/redis-storage/src/index.ts` | `src/lib.rs` (re-exports) |
| `packages/redis-storage/src/redis-storage.ts` | `src/storage.rs` (`FredSecondaryStorage`) |
| *(no existe)* | `src/store.rs` (`FredRateLimitStore`) |
| *(no existe)* | `src/script.rs` (Lua + parseo) |
| *(no existe)* | `src/url.rs`, `src/config.rs`, `src/error.rs` |
| `e2e/smoke/test/redis.spec.ts` | `tests/fred_rate_limit.rs` (parcial + superset) |

## ¿Tiene sentido documentar paridad de `openauth-fred`?

| Enfoque | ¿Aplica? |
| --- | --- |
| Paridad con `@better-auth/redis-storage` | **Sí** — objetivo principal de este directorio. |
| Paridad con la librería `fred` de crates.io | **No** — es dependencia de transporte; cluster/TLS/sentinel se delegan a `fred` + features del crate. |
| Paridad con `openauth-redis` | **Complementario** — mismo contrato OpenAuth; ver [08-sibling-openauth-redis.md](./08-sibling-openauth-redis.md). |

## Alcance de este análisis

**Incluido**

- API y comportamiento Redis del adaptador (secondary storage + extensiones Fred).
- Diferencias intencionales frente a upstream (`SCAN`, prefijos, validaciones).
- Tests del crate y equivalencia con e2e / tests de consumidores upstream.
- Integración con `openauth` (sign-up, sesiones, rate limit HTTP) **solo donde este crate las prueba**.

**Fuera de alcance**

- SDK cliente, cookies en navegador, React.
- Empaquetado npm (`tsdown`, `publint`, etc.).
- OAuth stateless / Google del smoke upstream (pertenece a `better-auth` / `openauth` core).
- Lógica completa de `internal-adapter`, verificación TTL desde `expiresAt`, API keys — documentada a nivel contrato en [06-consumer-integration.md](./06-consumer-integration.md), implementada en `openauth-core` y plugins.

## Conclusión de paridad

| Dimensión | Valoración |
| --- | --- |
| Secondary storage CRUD + TTL &gt; 0 | **~95%** — difieren prefijo por defecto, namespace `secondary:`, semántica `ttl = 0` |
| `listKeys` / `clear` | **~98%** observable — implementación más segura (`SCAN`, validación prefijo) |
| Rate limit en Redis | **Extensión** — no comparable 1:1 con el paquete npm; superior en atomicidad vs path JSON upstream |
| Tests en el adaptador | Upstream **0**; OpenAuth **33** |
| E2E producto (sesión en Redis) | **Cubierto** en este crate (más que `openauth-redis`) |

**Estimación global servidor:** ~**95%** frente a `@better-auth/redis-storage` literal; ~**98%** frente al contrato OpenAuth (namespaces `secondary:` / `rate-limit:`). Detalle en [09-audit-deep-dive.md](./09-audit-deep-dive.md).

[`crates/openauth-fred/PARITY.md`](../../../crates/openauth-fred/PARITY.md) resume; la auditoría en **09** prevalece si hay discrepancia.

La paridad “de producto” completa (todos los consumidores de secondary storage: API key, SSO, device auth) depende de `openauth-core` y plugins; este crate solo garantiza el contrato Redis/Fred.
