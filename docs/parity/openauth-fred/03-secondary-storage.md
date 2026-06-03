# 03 — Secondary storage (`SecondaryStorage`)

Contrato upstream: `packages/core/src/db/type.ts`.  
Contrato OpenAuth: `openauth-core` → `SecondaryStorage`.

Implementación: `FredSecondaryStorage` en `crates/openauth-fred/src/storage.rs`.

## Métodos del contrato

| Método | Upstream `redisStorage` | `FredSecondaryStorage` | Paridad |
| --- | --- | --- | --- |
| `get(key)` | `GET({prefix}{key})` | `GET` en `{prefix}secondary:{key}` | Alta (namespace distinto) |
| `set(key, value, ttl?)` | Ver TTL | Ver TTL | Media-alta |
| `delete(key)` | `DEL` | `DEL` | Alta |

## Formato de claves

| Aspecto | Upstream | OpenAuth | Motivo |
| --- | --- | --- | --- |
| Prefijo por defecto | `better-auth:` | `openauth:` | Convención proyecto |
| Clave Redis final | `{prefix}{logicalKey}` | `{prefix}secondary:{logicalKey}` | **Decisión OpenAuth:** separar de `rate-limit:` y evitar colisiones |
| Ejemplo sesión | `better-auth:session:token` | `openauth:secondary:session:token` | Migración desde BA requiere reescritura o prefijo custom |

`openauth-redis` usa el **mismo** layout; test de cruce `fred_and_redis_secondary_storage_share_physical_key_layout`.

## TTL en `set` (verificado en código)

| `ttl` | Upstream `redis-storage.ts` | `FredSecondaryStorage` | `RedisSecondaryStorage` |
| --- | --- | --- | --- |
| `None` | `SET` | `SET` sin expire | `SET` |
| `> 0` | `SETEX` | `SET` + `EX` | `set_ex` |
| `0` | `SET` persistente | `SET` persistente | **`DEL`** |
| &gt; `i64::MAX` | N/A | `InvalidConfig` | N/A |

Test Fred: `fred_secondary_storage_supports_strings_ttl_delete_list_and_clear` (`Some(0)` persiste). Test redis-rs: `redis_secondary_storage_supports_get_set_delete_and_ttl_zero` (`Some(0)` borra).

## Utilidades `list_keys` / `clear`

| Aspecto | Upstream | `openauth-fred` | Clasificación |
| --- | --- | --- | --- |
| Enumerar | `KEYS ${prefix}*` | `SCAN` con patrón `{prefix}secondary:*` | **Decisión diseño** (producción) |
| Strip prefix | `key.replace(keyPrefix, "")` | `strip_prefix` en `secondary:` namespace | Comportamiento distinto en claves lógicas |
| Glob en prefijo | Sin escape | Escapa `* ? [ ] \` en patrón SCAN | **Decisión diseño** (seguridad) |
| Prefijo vacío | Permitido (riesgo `KEYS *`) | `InvalidConfig` antes de Redis | **Decisión diseño** |
| `scan_count = 0` | N/A | Rechazado | **Extensión OpenAuth** |
| `clear` sin claves | `del(...[])` (ioredis) | No-op explícito | **Mejora** |

Upstream `listKeys` lista **todo** bajo `keyPrefix` (incluiría entradas de rate limit JSON si comparten prefijo y se usara el adaptador upstream para ambos). Fred `list_keys` solo hace `SCAN` sobre `{prefix}secondary:*` — **no** lista claves `{prefix}rate-limit:*`.

| | Upstream `listKeys` | `FredSecondaryStorage::list_keys` |
| --- | --- | --- |
| Patrón Redis | `KEYS {prefix}*` | `SCAN {prefix}secondary:*` (glob escapado) |
| Claves rate limit en mismo prefijo | Aparecerían en el listado | **Excluidas** por diseño de namespace |
| Strip | `key.replace(keyPrefix, "")` | `strip_prefix` de `{prefix}secondary:` |

## Tipo de valor

| | Upstream | OpenAuth |
| --- | --- | --- |
| `get` en core | `unknown` (permite objeto parseado) | `Option<String>` |
| JSON | Consumidor (`internal-adapter`) | Igual en `openauth-core` |

**No soportado en Rust:** `get` devolviendo JSON ya parseado (tests upstream “pre-parsed storage”). Limitación idiomática + contrato estricto, no de `fred`.

## Configuración del cliente

| Patrón | Upstream | `openauth-fred` |
| --- | --- | --- |
| Conexión | App pasa `ioredis` | `connect(url)` → `Builder::from_config` + `init()` |
| Reutilizar cliente | Misma instancia | `FredSecondaryStorage::new(client, options)` |
| Valkey URL | Usuario usa URL redis | `normalize_fred_url` convierte `valkey://` → `redis://` |
| Cluster / Sentinel | vía ioredis | vía config `fred` (no probado exhaustivamente en crate) |

## Tabla resumen

| Ítem | vs upstream | Acción |
| --- | --- | --- |
| CRUD + TTL positivo | Paridad alta | Documentar namespace en migraciones |
| `list_keys` / `clear` | Paridad alta + mejoras | Mantener `SCAN` |
| Prefijo `openauth:` | Intencional | Configurable vía `key_prefix` |
| `get` solo `String` | Gap documental | Cubierto en core |
