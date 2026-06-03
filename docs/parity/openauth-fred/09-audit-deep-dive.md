# 09 — Auditoría profunda (código + tests, no README)

Revisión **2026-06-01** leyendo fuentes en:

- `crates/openauth-fred/` (todos los `.rs`, `Cargo.toml`, `CHANGELOG.md`)
- `reference/upstream-src/1.6.9/repository/packages/redis-storage/`
- `e2e/smoke/test/redis.spec.ts`
- Tests upstream relacionados (sin confiar en README del paquete npm)

## Inventario completo del crate Rust

| Archivo | Líneas aprox. | Rol |
| --- | --- | --- |
| `src/lib.rs` | 18 | Re-exports públicos + `VERSION` |
| `src/config.rs` | 28 | `FredRateLimitOptions`, `FredSecondaryStorageOptions` |
| `src/error.rs` | 8 | `fred_error` → `OpenAuthError::Adapter` |
| `src/url.rs` | 12 | `normalize_fred_url` |
| `src/script.rs` | 84 | Lua + `parse_rate_limit_script_result` |
| `src/store.rs` | 135 | `FredRateLimitStore`, `connect_client` |
| `src/storage.rs` | 324 | `FredSecondaryStorage` + 10 unit tests |
| `tests/config.rs` | 141 | 10 tests |
| `tests/fred_rate_limit.rs` | 720 | 14 integration tests |
| `Cargo.toml` | 34 | deps, features, dev-deps |
| `CHANGELOG.md` | 36 | breaking: namespace `secondary:` |
| `README.md` / `PARITY.md` | — | no sustituyen este doc |

**No hay:** `examples/` en el crate, `benches/`, doc-tests, tests de features TLS, tests de cluster/sentinel.

### API pública real (`lib.rs`)

Exporta exactamente: `FredRateLimitOptions`, `FredSecondaryStorageOptions`, `RateLimitScriptResult`, `parse_rate_limit_script_result`, `FredSecondaryStorage`, `FredRateLimitStore`, `normalize_fred_url`, `VERSION`.

**No exporta:** `fred::Client`, `connect_client`, `RATE_LIMIT_SCRIPT`, `fred_error`.

### Constructores `connect_*` (comportamiento real)

En `storage.rs` y `store.rs`:

| Método | Implementación |
| --- | --- |
| `connect` | `connect_with_options(url, default options)` |
| `connect_redis` | **Idéntico a `connect`** |
| `connect_valkey` | **Idéntico a `connect`** (solo importa la URL; `normalize_fred_url` convierte esquemas Valkey) |

El README sugiere Valkey como caso de uso de `connect_valkey`; no hay lógica distinta a Redis.

## Inventario upstream `@better-auth/redis-storage`

| Archivo | Contenido |
| --- | --- |
| `src/redis-storage.ts` | 75 líneas — toda la implementación |
| `src/index.ts` | 1 re-export |
| `package.json` | `vitest` en scripts, **0 archivos `*.test.ts` en el paquete** |
| `README.md` | 15 líneas — instalación + link docs |
| `CHANGELOG.md` | solo bumps de dependencias 1.6.x |

### Comportamiento literal `redis-storage.ts`

```typescript
// Prefijo: `${keyPrefix}${key}` — SIN segmento `secondary:`
// TTL: ttl !== undefined && ttl > 0 → SETEX; else SET
// listKeys: KEYS `${keyPrefix}*` → strip keyPrefix
// clear: KEYS + DEL(...keys)
```

## Matriz de comportamiento (verificado en código)

| Caso | Upstream TS | `FredSecondaryStorage` | `RedisSecondaryStorage` (hermano) |
| --- | --- | --- | --- |
| Clave física | `{prefix}{logical}` | `{prefix}secondary:{logical}` | Igual que Fred |
| Default prefix | `better-auth:` | `openauth:` | `openauth:` |
| `ttl` omitido / `None` | `SET` | `SET` sin expire | `SET` |
| `ttl > 0` | `SETEX` | `SET` + `EX` | `set_ex` |
| `ttl = 0` | `SET` persistente | `SET` persistente (`.filter(>0)`) | **`DEL` la clave** |
| `ttl` no cabe en i64 | N/A | `InvalidConfig` | error adapter redis |
| Prefijo vacío en get/set/delete | Permitido (riesgo) | `InvalidConfig` | **Permitido** (sin validación) |
| `list_keys` alcance | Todo `{prefix}*` | Solo `{prefix}secondary:*` | No existe |
| `list_keys` con RL en mismo prefix | Incluye claves JSON rate limit | **No** incluye `rate-limit:` | N/A |
| Glob en prefijo | Sin escape | Escape en patrón SCAN | N/A |
| Errores Redis | Propagación ioredis | `OpenAuthError::Adapter("fred …")` | `Adapter(string)` |

**Hallazgo crítico:** `ttl = 0` — **Fred alinea con upstream Better Auth**, pero **difiere de `openauth-redis`**. El test `fred_secondary_storage_supports_strings_ttl_delete_list_and_clear` fija el comportamiento Fred (persiste con `Some(0)`). El hermano `redis_secondary_storage_supports_get_set_delete_and_ttl_zero` espera borrado.

**Hallazgo crítico:** validación de prefijo vacío — Fred en los 5 métodos; `openauth-redis` **no** valida en get/set/delete.

## Rate limit (`FredRateLimitStore`)

| Aspecto | Código |
| --- | --- |
| Script Lua | Byte-a-byte igual que `openauth-redis/src/lib.rs` |
| Clave | `{prefix}rate-limit:{logical}` |
| Validación | `window == 0`, `max == 0`, overflow ms, max i64 — **antes** de Redis |
| Prefijo vacío en rate limit | **No validado** (puede escribir en `rate-limit:…` en raíz efectiva) |
| `retry_after` / `reset_after` | `ceil_millis_to_seconds` en `store.rs` |

Upstream no tiene equivalente en el paquete redis; el path `"secondary-storage"` en rate limiter usa JSON string en el **mismo** prefijo plano.

## Divergencias de producto (core, no del driver Fred)

Los tests E2E de sesión en `fred_rate_limit.rs` ejercitan **OpenAuth core**, no Better Auth 1:1:

| Tema | Upstream (`internal-adapter.ts`) | OpenAuth (`session.rs` + tests fred) |
| --- | --- | --- |
| Lista de sesiones por usuario | Clave `active-sessions-{userId}` | Clave `session:user:{user_id}` |
| Smoke e2e busca claves | `!key.startsWith("active-sessions")` | `session:` y `session:user:` |

Paridad del **adaptador Redis** no implica mismas claves lógicas de sesión que Better Auth sin migración de core.

## Tests: lista exhaustiva (`cargo test -p openauth-fred -- --list`)

**Total: 34** funciones de test (0 doc-tests).

### `src/storage.rs` (10)

1. `scan_pattern_escapes_redis_glob_metacharacters`
2. `scan_pattern_leaves_plain_prefixes_readable`
3. `secondary_storage_matches_redis_secondary_namespace_layout`
4. `list_keys_rejects_empty_prefix_before_calling_redis`
5. `list_keys_rejects_zero_scan_count_before_calling_redis`
6. `clear_rejects_empty_prefix_before_calling_redis`
7. `clear_rejects_zero_scan_count_before_calling_redis`
8. `get_rejects_empty_prefix_before_calling_redis`
9. `set_rejects_empty_prefix_before_calling_redis`
10. `delete_rejects_empty_prefix_before_calling_redis`

### `tests/config.rs` (10)

1. `fred_rate_limit_options_default_to_openauth_prefix`
2. `fred_secondary_storage_options_default_to_openauth_prefix`
3. `fred_urls_normalize_valkey_aliases`
4. `fred_urls_leave_redis_and_unix_urls_unchanged`
5. `parses_valid_lua_result`
6. `rejects_malformed_lua_result`
7. `rejects_invalid_permitted_flag_from_lua_result`
8. `rejects_negative_count_from_lua_result`
9. `rejects_zero_rate_limit_window_before_calling_redis`
10. `rejects_zero_rate_limit_max_before_calling_redis`

### `tests/fred_rate_limit.rs` (14)

1. `fred_targets_default_to_docker_compose_redis_and_valkey_when_env_is_unset`
2. `fred_targets_allow_env_overrides`
3. `fred_rate_limit_store_enforces_atomic_max_one`
4. `fred_rate_limit_store_allows_exactly_one_concurrent_request`
5. `fred_rate_limit_store_resets_after_window`
6. `fred_rate_limit_store_resets_at_exact_window_boundary`
7. `openauth_handler_async_uses_fred_rate_limit_store`
8. `openauth_email_signup_uses_fred_secondary_storage_for_sessions`
9. `openauth_email_signup_with_database_sessions_still_writes_fred_secondary_storage`
10. `openauth_password_reset_uses_fred_secondary_storage_for_verification`
11. `fred_secondary_storage_supports_strings_ttl_delete_list_and_clear`
12. `fred_and_redis_secondary_storage_share_physical_key_layout`
13. `fred_secondary_storage_clear_keeps_other_prefixes`
14. `fred_secondary_storage_treats_glob_metacharacters_in_prefix_literally`

## Tests upstream relacionados (conteo real)

| Archivo | Casos aprox. | Redis real | Notas |
| --- | --- | --- | --- |
| `packages/redis-storage` | **0** | — | `npm test` / vitest sin archivos |
| `e2e/smoke/test/redis.spec.ts` | **4** `t.test` | Sí | flushall entre tests |
| `secondary-storage.test.ts` | **4** `it` | No (Map) | string vs object `get` |
| `rate-limiter.test.ts` | **20** `it` (subset secondary) | Mayoría mock | path secondary-storage |
| `internal-adapter.test.ts` | **33** `it` (26 menciones secondary) | Mock | TTL verification, safeJSONParse |
| `magic-link-secondary-storage.test.ts` | **6** `it` | Map mock | issue #8228 |

**No cubierto por `openauth-fred`:**

| Escenario upstream | Severidad |
| --- | --- |
| OAuth stateless + Google + Redis (`redis.spec.ts` #3) | Media — core OAuth |
| Custom Google `authorizationEndpoint` (#4) | Baja — provider |
| Magic link + secondary (`magic-link-secondary-storage.test.ts`) | Media — plugin |
| `get` devuelve objeto ya parseado | Baja — diseño Rust |
| Rate limit vía JSON en mismo KV | N/A — no objetivo |
| `listKeys` incluye claves fuera de `secondary:` | Baja — semántica distinta documentada |
| API key / SSO secondary (cientos de tests) | Media — otros crates |

## Uso real en el workspace (grep código)

| Ubicación | Usa Fred |
| --- | --- |
| `examples/full-app` | **Solo** `FredRateLimitStore` (`FredRedis`, `FredValkey` backends) — **no** `FredSecondaryStorage` |
| `openauth-fred` dev-dep | `openauth`, `openauth-redis` (test cruce) |
| `openauth` facade | No depende |
| CI / release | Sí publica crate |

## Migración / CHANGELOG (no en README)

Versión **unreleased** en `CHANGELOG.md`:

- Claves físicas pasaron de `{prefix}{key}` a `{prefix}secondary:{key}`.
- Datos escritos con layout antiguo **no se leen** tras el cambio.
- Validación de `key_prefix` vacío en get/set/delete (alineado con list/clear).

## Gaps de tests en el crate (no implementados)

| Gap | Riesgo |
| --- | --- |
| Features `native-tls` / `rustls` | Medio |
| `FredRateLimitStore` prefijo vacío | Bajo |
| Overflow window/max en integración | Bajo (solo unit config) |
| Fallo Redis / script `NOSCRIPT` | Bajo |
| `list_keys` con miles de claves (paginación SCAN) | Bajo |
| Compat literal prefijo `better-auth:` sin `secondary:` | Migración |
| Secondary storage en `examples/full-app` | Doc/ejemplo |
| Alinear `ttl=0` con `openauth-redis` | **Inconsistencia hermanos** |

## Paridad revisada (honesta)

| Capa | % | Comentario |
| --- | --- | --- |
| Adaptador vs `redis-storage.ts` (CRUD + TTL&gt;0) | **~90%** | Namespace, prefijo, `list_keys` scope, `ttl=0` vs redis-rs |
| Utilidades list/clear vs upstream | **~85%** observable | SCAN vs KEYS; alcance `secondary:` vs `prefix*` |
| Rate limit vs upstream producto | **Extensión** | Mejor atomicidad; no JSON-compatible |
| Tests adaptador npm vs crate | **Superset** | 0 vs 34 |
| E2E sesión vs smoke | **Parcial** | 2/4 subtests; claves lógicas core distintas |

**Global servidor (adaptador Fred + extensiones): ~95%**, no 98%, si se exige compat literal con upstream + hermano redis-rs en `ttl=0` y prefijo vacío.

## Segunda pasada

Ver [10-second-pass-findings.md](./10-second-pass-findings.md) — auto-RL con secondary, cliente compartido, claves core, índice sin TTL, tests upstream no cubiertos.
