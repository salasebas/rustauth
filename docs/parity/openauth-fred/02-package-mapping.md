# 02 — Mapeo de paquetes y API pública

## Identidad

| | Upstream | OpenAuth |
| --- | --- | --- |
| Nombre publicado | `@better-auth/redis-storage` | `openauth-fred` |
| Versión pin paridad | `1.6.9` | workspace `0.0.6` |
| Cliente Redis | `ioredis` peer `^5.0.0` | `fred` `10.1` (`i-keys`, `i-scripts`, `sha-1`) |
| Líneas implementación adaptador | ~75 TS | ~600 Rust (módulos + validación + tests inline) |

## Por qué existe un crate aparte (no es un paquete upstream extra)

| Motivo | Tipo |
| --- | --- |
| Ecosistema Rust: equipos ya usan `fred` vs `redis-rs` | **Decisión empaquetado** |
| Upstream solo documenta ioredis en el paquete oficial | **Limitación upstream** (un driver en el paquete npm) |
| OpenAuth mantiene **mismo layout de claves** entre `openauth-redis` y `openauth-fred` | **Decisión diseño** |
| Utilidades `list_keys` / `clear` implementadas aquí con `SCAN` | **Decisión diseño** (también portable a `openauth-redis`) |

No hay `@better-auth/fred-storage` en upstream.

## Dependencias

| Concern | Upstream | `openauth-fred` |
| --- | --- | --- |
| Cliente | App crea `new Redis(...)` → `redisStorage({ client })` | `FredSecondaryStorage::connect(url)` o `::new(client, options)` |
| Contrato storage | `@better-auth/core` `SecondaryStorage` | `openauth-core` `SecondaryStorage`, `RateLimitStore` |
| Runtime | Node promises | Tokio + `SecondaryStorageFuture` / `RateLimitFuture` |
| TLS | Config ioredis | Features `native-tls` \| `rustls` → flags `fred` |
| Tests en paquete | 0 | 33 |

## Features Cargo (solo OpenAuth)

| Feature | Efecto |
| --- | --- |
| `default` | Sin TLS en `fred` |
| `native-tls` | `fred/enable-native-tls` |
| `rustls` | `fred/enable-rustls-ring` |

## Módulos Rust ↔ archivos upstream

| Módulo `openauth-fred` | Equivalente upstream / notas |
| --- | --- |
| `lib.rs` | `index.ts` + doc crate |
| `config.rs` | Campos de `RedisStorageConfig` (split en rate limit vs secondary) |
| `storage.rs` | `redis-storage.ts` (`get`/`set`/`delete` + `listKeys`/`clear`) |
| `store.rs` | *(no upstream)* — `FredRateLimitStore` |
| `script.rs` | *(no upstream)* — compartido con `openauth-redis` |
| `url.rs` | *(no upstream)* — `valkey://` / `valkeys://` |
| `error.rs` | Errores → `OpenAuthError::Adapter("fred …")` |

## API pública — tabla comparativa

| Upstream | `openauth-fred` | Paridad | Notas |
| --- | --- | --- | --- |
| `RedisStorageConfig` | `FredSecondaryStorageOptions`, `FredRateLimitOptions` | Parcial | Dos structs; upstream unifica en un config |
| `redisStorage(config)` | `FredSecondaryStorage::connect*` / `::new` | Parcial | No factory TS; URL o cliente Fred existente |
| `config.client` | `fred::clients::Client` | Diseño | `connect_client` en `store.rs` |
| `config.keyPrefix` | `key_prefix` (default `openauth:`) | Parcial | Upstream default `better-auth:` |
| `get` / `set` / `delete` | `SecondaryStorage` trait | Alta | Claves con namespace `secondary:` |
| `listKeys()` | `list_keys()` | Alta | `SCAN` + `scan_count` |
| `clear()` | `clear()` | Alta | vía `list_keys` + `DEL`; no-op si vacío |
| — | `FredRateLimitStore` | **Extensión** | Ver [04-rate-limiting.md](./04-rate-limiting.md) |
| — | `normalize_fred_url` | **Extensión** | Valkey URL aliases |
| — | `parse_rate_limit_script_result`, `RateLimitScriptResult` | **Extensión** | Testabilidad Lua |
| — | `VERSION` | **Extensión** | |

## Re-exports del workspace

| Consumidor | Uso |
| --- | --- |
| `examples/full-app` | Rate limit `fred-redis` / `fred-valkey` |
| `openauth-fred` dev-dep | `openauth`, `openauth-redis` (cruce de claves) |
| `openauth` (facade) | No depende por defecto |
| CI | Matrix `package: openauth-fred` |

## Inventario upstream (referencia)

| Archivo | Contenido |
| --- | --- |
| `src/redis-storage.ts` | Implementación completa |
| `src/index.ts` | Re-export |
| `README.md` | Instalación + link docs |
| `CHANGELOG.md` | Solo bumps deps 1.6.x |

Sin tests, sin rutas HTTP, sin rate limit en el paquete.
