# 05 — Layout de claves, comandos y cliente `fred`

## Namespaces Redis (OpenAuth)

| Uso | Patrón de clave | Comandos principales |
| --- | --- | --- |
| Secondary storage | `{key_prefix}secondary:{logical_key}` | `GET`, `SET` (+ optional `EX`), `DEL` |
| Rate limit | `{key_prefix}rate-limit:{logical_key}` | `EVALSHA` (Lua), `HSET`, `HMGET`, `PEXPIRE` |
| Admin list/clear | SCAN `{prefix}secondary:*` | `SCAN`, `DEL` (batch) |

Upstream secondary storage usa un solo nivel: `{keyPrefix}{logicalKey}` sin segmento `secondary:`.

## Comandos: upstream vs Fred

| Operación | Upstream (`ioredis`) | `openauth-fred` |
| --- | --- | --- |
| Leer valor | `GET` | `GET` |
| Escribir con TTL | `SETEX` | `SET` + `Expiration::EX` |
| Escribir sin TTL | `SET` | `SET` sin expire |
| Borrar | `DEL` | `DEL` |
| Listar | `KEYS` | `SCAN` + `scan_page` |
| Rate limit | *(en core, no en paquete)* | Lua vía `fred::types::scripts::Script` |

## Normalización URL (`normalize_fred_url`)

| Entrada | Salida | Motivo |
| --- | --- | --- |
| `valkey://host:port` | `redis://host:port` | Fred parsea URLs estilo Redis |
| `valkeys://...` | `rediss://...` | TLS alias Valkey |
| `redis://`, `rediss://`, `unix://` | Sin cambio | — |

**Extensión OpenAuth** — upstream delega al usuario ioredis sin alias Valkey en el paquete.

## Features `fred` habilitadas en `Cargo.toml`

| Feature `fred` | Uso en crate |
| --- | --- |
| `i-keys` | `GET` / `SET` / `DEL` / `SCAN` |
| `i-scripts` | Rate limit Lua |
| `sha-1` | `evalsha_with_reload` |
| `enable-native-tls` (opcional) | Feature crate `native-tls` |
| `enable-rustls-ring` (opcional) | Feature crate `rustls` |

`default-features = false` en dependencia `fred` — TLS solo si el usuario activa feature del crate.

## Delegado a `fred` (no probado exhaustivamente aquí)

| Capacidad | Notas |
| --- | --- |
| Redis Cluster | Config URL / builder Fred |
| Sentinel | Idem |
| Connection pooling | `Client` Fred |
| Reconnect | Comportamiento Fred |

El crate verifica conexión en tests de integración contra Redis 6379 y Valkey 6380 (docker-compose), no cada topología.

## Errores

Todos los fallos Redis se mapean a:

`OpenAuthError::Adapter("fred {operation} failed: {detail}")`

Upstream propaga errores de ioredis sin capa uniforme en el adaptador de 75 líneas.
