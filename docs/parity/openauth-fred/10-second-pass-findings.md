# 10 — Segunda pasada (hallazgos adicionales)

Revisión adicional leyendo `create-context.ts`, `internal-adapter.ts`, `session.rs`, `rate-limiter/index.ts`, tests upstream línea a línea, y comparando wiring con `openauth-core`. Complementa [09-audit-deep-dive.md](./09-audit-deep-dive.md).

## 1. Auto-cableado rate limit + secondary storage (upstream ≠ OpenAuth)

**Upstream** (`packages/better-auth/src/context/create-context.ts` ~329–336):

```typescript
storage:
  options.rateLimit?.storage ||
  (options.secondaryStorage ? "secondary-storage" : "memory"),
```

Si configuras solo `secondaryStorage: redisStorage({ client })`, el rate limit **por defecto** usa el **mismo** KV con JSON (`127.0.0.1|/sign-in/email`, etc.). Lo demuestra `rate-limiter.test.ts` (“custom rate limiting storage”): un solo `Map` mock recibe sesiones **y** entradas de rate limit.

**OpenAuth** (`openauth-core`):

- `OpenAuthOptions.secondary_storage` y `RateLimitOptions.storage` son **independientes**.
- Default rate limit: `RateLimitStorageOption::Memory` (`options/rate_limit.rs`).
- `RateLimitOptions::secondary_storage(store)` exige un `RateLimitStore` concreto (`FredRateLimitStore`); **no** usa el trait `SecondaryStorage`.
- Pasar solo `FredSecondaryStorage` **no** activa rate limit en Redis.

| Configuración | Upstream | OpenAuth + `openauth-fred` |
| --- | --- | --- |
| Solo adaptador Redis en secondary | Sesiones + RL JSON en mismo prefijo plano | Solo sesiones/verificación en `{prefix}secondary:` |
| Rate limit en Redis | Automático (si no override) | Requiere **además** `FredRateLimitStore` en `rate_limit` |
| Un solo cliente Redis | Un `ioredis` compartido | Dos `connect()` → **dos** clientes `fred` salvo `::new` con mismo `Client` |

**Clasificación:** decisión de diseño OpenAuth (traits separados + Lua), no bug del crate Fred. **Gap de migración** si alguien espera “un solo `redisStorage` y listo”.

## 2. `connect_client` no es público — compartir pool

`connect_client` es `pub(crate)` en `store.rs`. Para un solo `fred::Client`:

```rust
let stores = FredOpenAuthStores::connect("redis://127.0.0.1:6379").await?;
let options = stores.apply_to_options(OpenAuthOptions::new().secret("..."));
```

`FredOpenAuthStores::connect` devuelve ambos stores con un solo `fred::Client`. Upstream sigue auto-enlazando rate limit; OpenAuth requiere `apply_to_options` o wiring explícito de `RateLimitOptions::secondary_storage`.

## 3. Dos prefijos distintos en rate limit vs secondary

Upstream: un solo `keyPrefix` en `redisStorage({ keyPrefix })` para sesiones, verificación **y** (vía RL secondary) rate limit.

OpenAuth: `FredRateLimitOptions.key_prefix` y `FredSecondaryStorageOptions.key_prefix` son **independientes**. Valores distintos → namespaces desacoplados (normalmente deseable; distinto a BA si se espera un único prefijo).

## 4. Claves lógicas de sesión (core — afecta tests Fred)

Ver también [openauth-redis/08-logical-keys-and-payloads.md](../openauth-redis/08-logical-keys-and-payloads.md).

| | Upstream | OpenAuth core |
| --- | --- | --- |
| Sesión | Clave = token crudo | `session:{token}` |
| Índice usuario | `active-sessions-{userId}` (JSON con `expiresAt`) | `session:user:{userId}` (JSON array de tokens) |
| Payload sesión | `{ session, user }` | Solo `Session` (usuario vía DB en E2E con `MemoryAdapter`) |
| TTL índice usuario | `furthestSessionTTL` en Redis | `set_user_session_tokens` usa `positive_ttl_seconds` del expiry más lejano |

El test `openauth_email_signup_uses_fred_secondary_storage_for_sessions` valida **OpenAuth**, no el smoke de Better Auth que busca `active-sessions`.

## 5. TTL índice `session:user:` (cerrado en core)

`set_user_session_tokens` ahora pasa TTL derivado del expiry más lejano (`positive_ttl_seconds`, omitiendo ≤0). Los tests Fred/redis de sign-up **no** afirman el valor EXPIRE en Redis (solo flujo list/revoke).

## 6. Core `ttl_seconds` → `Some(0)` y adaptadores

`ttl_seconds()` en `session.rs` devuelve `Some(0)` cuando la sesión ya expiró (`max(0)`).

| Adaptador | `set(..., Some(0))` |
| --- | --- |
| Upstream TS | `SET` (persiste) |
| `FredSecondaryStorage` | `SET` (persiste) — alineado con TS |
| `RedisSecondaryStorage` | `SET` (persiste) — alineado desde gap closure |

Upstream **no escribe** si `getTTLSeconds <= 0` (`if (sessionTTL > 0)` en internal-adapter). OpenAuth **puede** llamar al adaptador con `Some(0)` en edge cases — comportamiento distinto según crate hermano.

## 7. `list_keys`: claves SCAN fuera de namespace se ignoran

En `storage.rs`, bucle SCAN:

```rust
if let Some(unprefixed) = key.strip_prefix(secondary_prefix.as_str()) {
    keys.push(unprefixed.to_owned());
}
```

Claves que coincidan con el patrón pero no empiecen por `secondary_prefix` (corrupción, race, keys ajenas) **se omiten sin error**. Upstream `listKeys` no tiene este filtro (lista todo `prefix*`).

## 8. `list_keys` y `String::replace` upstream

Upstream: `key.replace(keyPrefix, "")` — solo la **primera** ocurrencia. Si el prefijo apareciera dentro de la clave lógica, strip incorrecto. Fred usa `strip_prefix` en el prefijo físico completo `secondary:` — más predecible para el layout OpenAuth.

## 9. `RateLimitOptions::secondary_storage` — nombre engañoso

El método configura un **`RateLimitStore`** (p. ej. `FredRateLimitStore`), no `Arc<dyn SecondaryStorage>`. En upstream el nombre “secondary-storage” para rate limit sí significa reutilizar el KV secondary. Documentar al integrar Fred.

## 10. `LegacyRateLimitStorageAdapter` (core) no usado por Fred

`openauth-core` puede emular el rate limiter JSON get/set sobre `RateLimitStorage` (estilo upstream) vía `LegacyRateLimitStorageAdapter`. **No** está conectado a `FredSecondaryStorage`. Para paridad JSON habría que cablear manualmente un adaptador custom — no existe en el crate.

## 11. CI: `--all-features` sin tests TLS

`.github/workflows/ci.yml` ejecuta:

```bash
cargo nextest run -p openauth-fred --all-features
```

Compila `native-tls` **y** `rustls` a la vez (verificado: `cargo check -p openauth-fred --all-features` OK). **No hay** test que abra `rediss://` con cada feature (a diferencia de `openauth-redis` que tiene `tls_urls_open_as_tls_connections` bajo `cfg(feature)`).

## 12. Tests upstream no mapeados (segunda pasada)

| Archivo | Casos | ¿Fred? |
| --- | --- | --- |
| `rate-limiter.test.ts` con `secondaryStorage` mock + RL default | ~3 bloques (líneas 111, 244, 288) | **No** — RL vía JSON en mismo store |
| `create-context.test.ts` | muchos | **No** — default `storage: secondary-storage` |
| `magic-link-secondary-storage.test.ts` | 6 | **No** |
| `email-verification.test.ts` / `session-api.test.ts` (mencionan secondary) | parcial | **No** en crate fred |
| `listSessions` / `revokeSession` E2E | `secondary-storage.test.ts` | **No** en fred (solo sign-up + sign-out parcial) |

Fred **no** prueba: `list-sessions`, `revoke-other-sessions`, magic link, verificación email genérica (solo reset password).

## 13. `remaining` tras reset de ventana

`fred_rate_limit_store_resets_after_window` espera `second.remaining == 0` con `max: 1` tras permitir de nuevo — coherente con `remaining = max - count` y `count == 1`. No compara headers `X-Retry-After` como upstream `rate-limiter.test.ts`.

## 14. Paquetes upstream relacionados (fuera de scope pero referenciados)

| Paquete | Relación |
| --- | --- |
| `@better-auth/memory-adapter` | Otro backend; no es paridad Fred |
| `packages/redis-storage/dist/*` | Solo artefacto build; fuente es `src/redis-storage.ts` |

## 15. Resumen: qué bajaría o subiría la paridad

| Hallazgo | Impacto en “paridad literal BA” |
| --- | --- |
| Sin auto-RL en secondary | **Baja** (diseño OpenAuth) |
| Dos clientes por defecto | **Media** (operacional) |
| Claves sesión core distintas | **Alta** (datos no portables) |
| Índice `session:user` sin TTL | **Media** |
| `ttl=0` redis-rs vs fred | **Media** entre hermanos |
| `list_keys` scope `secondary:` | **Media** vs `listKeys` upstream |

**Recomendación documental:** enlazar siempre [08-logical-keys-and-payloads.md](../openauth-redis/08-logical-keys-and-payloads.md) desde integración Fred; **no** afirmar paridad 98% con smoke e2e de Better Auth sin esa salvedad.

## Cierre de gaps (2026-06-02)

| Gap | Estado |
| --- | --- |
| `ttl = 0` redis-rs vs fred | **Cerrado** — `openauth-redis` alineado con Fred/upstream |
| `list_keys` / `clear` en redis-rs | **Cerrado** — `SCAN` + `scan_count` |
| Prefijo vacío secondary + rate limit | **Cerrado** — ambos crates |
| Dos clientes Redis | **Cerrado** — `FredOpenAuthStores` / `RedisOpenAuthStores` |
| Prefijo vacío rate limit Fred | **Cerrado** + test |
| Tests integración redis (list/clear/bundle) | **Cerrado** |
| Auto-RL al configurar solo secondary | **Abierto** — requiere cambio en `openauth-core` (diseño) |
| Claves sesión `active-sessions-*` vs `session:user:` | **Abierto** — `openauth-core`, no adaptador |
| OAuth smoke / magic link en crate fred | **Abierto** — otros crates |
