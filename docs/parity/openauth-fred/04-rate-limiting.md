# 04 — Rate limiting y Redis

`FredRateLimitStore` **no existe en** `@better-auth/redis-storage`. Es la misma extensión que `RedisRateLimitStore` en `openauth-redis`, compartiendo `RATE_LIMIT_SCRIPT` en `src/script.rs`.

Ver también [docs/parity/openauth-redis/04-rate-limiting.md](../openauth-redis/04-rate-limiting.md) para el diagrama upstream (KV JSON) vs OpenAuth (Lua).

## Upstream: rate limit vía secondary storage

Cuando `secondaryStorage` está configurado y no se override `rateLimit.storage`, Better Auth usa `"secondary-storage"`:

- **get:** `secondaryStorage.get(key)` → `safeJSONParse<RateLimit>`
- **set:** `secondaryStorage.set(key, JSON.stringify(value), windowSeconds)`
- Clave: `{keyPrefix}{ip|path}` — **mismo prefijo** que sesiones
- Tipo Redis: **string** JSON

Código: `packages/better-auth/src/api/rate-limiter/index.ts`.

## OpenAuth: `FredRateLimitStore`

| Aspecto | Upstream (path secondary) | `FredRateLimitStore` |
| --- | --- | --- |
| Trait | Adaptador interno en rate limiter | `RateLimitStore` (`openauth-core`) |
| Clave Redis | `{prefix}{logicalKey}` | `{prefix}rate-limit:{logicalKey}` |
| Tipo Redis | String JSON | Hash (`count`, `last_request`) |
| Atomicidad | RMW en JS + 2 comandos | Lua `evalsha_with_reload` |
| TTL | `SETEX` = window (s) | `PEXPIRE` en hash (window en ms en script) |
| Config | Automático con secondary storage | Explícito `RateLimitOptions::secondary_storage(store)` |

## Implementación Fred-específica

| Detalle | Ubicación |
| --- | --- |
| Script Lua | `src/script.rs` — idéntico a `openauth-redis` |
| Ejecución | `Script::evalsha_with_reload` (`fred`) |
| Validación | `window > 0`, `max > 0`, overflow ms/i64 |
| Respuesta HTTP | Calculada en Rust: `retry_after`, `remaining`, `reset_after` (`ceil_millis_to_seconds`) |

## ¿Por qué no replicar el JSON en secondary storage?

| Razón | Tipo |
| --- | --- |
| Trait `RateLimitStore` unifica memory / DB / Redis | **Decisión diseño Rust** |
| Lua evita carreras entre workers | **Seguridad / corrección** |
| Separar string (sesiones) y hash (rate limit) | **Decisión diseño** |
| Upstream no define rate limit en paquete redis | **No es gap del port Fred** |

## Compatibilidad operativa

Una misma instancia Redis puede usar:

- `FredSecondaryStorage` para sesiones / verificación
- `FredRateLimitStore` para rate limit

Namespaces distintos (`secondary:` vs `rate-limit:`). **No** mezclar rate limit upstream-style JSON en `FredSecondaryStorage` salvo que se use `LegacyRateLimitStorageAdapter` en core (no cableado a Fred automáticamente).

## Paridad funcional rate limit

| Ítem | Estado |
| --- | --- |
| Límite distribuido multi-proceso | **Sí** (≥ upstream) |
| Misma forma de clave lógica (`ip\|path`) | **Sí** (prefijo distinto en Redis) |
| Almacenamiento JSON compatible con BA | **No** (por diseño) |
| Tests concurrencia | **Sí** en `fred_rate_limit.rs` (`tokio::join!`) |
