# 07 — Tests: cobertura y matriz upstream ↔ `openauth-fred`

## Conteos (pin 1.6.9)

| Ubicación | Archivos | Casos | Redis/Valkey real |
| --- | --- | --- | --- |
| `packages/redis-storage` | 0 | **0** | — |
| `e2e/smoke/test/redis.spec.ts` | 1 suite | **4** subtests | Sí (`redis://localhost:6379`) |
| `better-auth` `secondary-storage.test.ts` | 1 | ~4 casos (mock Map) | No |
| `better-auth` `internal-adapter.test.ts` (bloques secondary) | 1 | ~22 `it` verification/sessions | Mock |
| `better-auth` `rate-limiter.test.ts` (secondary path) | 1 | Varios mock | No |
| **`openauth-fred` unit** (`src/storage.rs`) | 1 módulo | **10** | No (cliente default) |
| **`openauth-fred` unit** (`tests/config.rs`) | 1 | **9** | No / 2 validación async |
| **`openauth-fred` integration** (`tests/fred_rate_limit.rs`) | 1 | **14** | Sí (Redis 6379 + Valkey 6380) |
| **`openauth-redis`** (hermano) | 2 | **13** | Sí (rate limit; menos E2E auth) |

**Total `openauth-fred`:** **34** funciones de test (`cargo test -p openauth-fred -- --list`).

Lista nombre por nombre en [09-audit-deep-dive.md](./09-audit-deep-dive.md).

Variables de entorno:

| Variable | Efecto |
| --- | --- |
| `OPENAUTH_FRED_REDIS_URL` | Target Redis; si falla y está set → error test |
| `OPENAUTH_FRED_VALKEY_URL` | Target Valkey |
| *(unset)* | Prueba defaults `127.0.0.1:6379` y `6380`; skip si no disponible |

## Detalle por archivo Rust

### `src/storage.rs` (10 tests)

| Test | Qué asegura | Equivalente upstream |
| --- | --- | --- |
| `scan_pattern_escapes_redis_glob_metacharacters` | Escape en SCAN | No |
| `scan_pattern_leaves_plain_prefixes_readable` | Patrón legible | No |
| `secondary_storage_matches_redis_secondary_namespace_layout` | Layout `secondary:` = `openauth-redis` | Parcial (namespace) |
| `list_keys_rejects_empty_prefix_*` | Validación | No (upstream permite) |
| `list_keys_rejects_zero_scan_count_*` | Validación | No |
| `clear_rejects_empty_prefix_*` | Validación | No |
| `clear_rejects_zero_scan_count_*` | Validación | No |
| `get/set/delete_rejects_empty_prefix_*` | Validación | No |

### `tests/config.rs` (10 tests)

| Test | Qué asegura | Equivalente upstream |
| --- | --- | --- |
| `fred_rate_limit_options_default_to_openauth_prefix` | Default prefix | Default `better-auth:` upstream |
| `fred_secondary_storage_options_default_*` | Defaults + `scan_count` | No |
| `fred_urls_normalize_valkey_aliases` | URL Valkey | No |
| `fred_urls_leave_redis_and_unix_urls_unchanged` | Passthrough | No |
| `parses_valid_lua_result` | Parser script | No (sin Lua upstream) |
| `rejects_malformed_lua_result` | Parser | No |
| `rejects_invalid_permitted_flag_*` | Parser | No |
| `rejects_negative_count_*` | Parser | No |
| `rejects_zero_rate_limit_window/max_*` | Config RL | No |

### `tests/fred_rate_limit.rs` (14 tests)

| Test | Qué asegura | Equivalente upstream |
| --- | --- | --- |
| `fred_targets_default_to_docker_compose_*` | URLs CI | No |
| `fred_targets_allow_env_overrides` | Env | No |
| `fred_rate_limit_store_enforces_atomic_max_one` | max=1 secuencial | Parcial (modelo distinto) |
| `fred_rate_limit_store_allows_exactly_one_concurrent_request` | Lua atomicidad | **Mejor** que JSON RMW |
| `fred_rate_limit_store_resets_after_window` | Ventana 1s | Parcial |
| `fred_rate_limit_store_resets_at_exact_window_boundary` | +1000ms | Parcial |
| `openauth_handler_async_uses_fred_rate_limit_store` | HTTP 200 → 429 | Parcial |
| `openauth_email_signup_uses_fred_secondary_storage_for_sessions` | Sign-up + get-session | **≈** smoke test 1 |
| `openauth_email_signup_with_database_sessions_*` | DB + Redis | **≈** smoke test 2 |
| `openauth_password_reset_uses_fred_secondary_storage_*` | Verification key | Parcial |
| `fred_secondary_storage_supports_strings_ttl_delete_list_and_clear` | CRUD admin | **≈** `listKeys` + TTL |
| `fred_and_redis_secondary_storage_share_physical_key_layout` | Interop redis-rs | No upstream |
| `fred_secondary_storage_clear_keeps_other_prefixes` | Aislamiento | Parcial |
| `fred_secondary_storage_treats_glob_metacharacters_in_prefix_literally` | Seguridad prefijo | No |

## Detalle: upstream `redis.spec.ts`

| Subtest | Assert principal | En `openauth-fred` |
| --- | --- | --- |
| Email signup → session en Redis | `listKeys` ×2; filtra `active-sessions-*` | **Sí** — claves OpenAuth `session:` / `session:user:` |
| `storeSessionInDatabase: true` | Session id en Redis | **Sí** |
| Stateless + Google OAuth | JWE + Redis sessions | **No** (core OAuth) |
| Custom Google authorization URL | URL custom | **No** |

## Matriz: qué testea upstream pero no este crate

| Escenario | Severidad | Dónde en OpenAuth |
| --- | --- | --- |
| Magic link + secondary (6 tests upstream) | Media | `openauth` / plugins |
| OAuth smoke Redis | Baja | `openauth` / e2e futuro |
| `get` objeto pre-parseado | Baja | N/A por diseño Rust |
| API key 166 tests secondary | Media | `openauth-api-key` |
| Rate limit JSON en mismo KV | N/A | No objetivo |
| Prefijo `better-auth:` drop-in | Baja | Migración documentada |

## Superset OpenAuth (tests sin equivalente en paquete npm)

- 33 tests en adaptador vs **0** upstream en `redis-storage`.
- Valkey como segundo backend.
- Concurrencia rate limit (`tokio::join!`).
- Cruce `openauth-redis` ↔ `openauth-fred` en mismas claves físicas.
- Validación prefijo vacío / `scan_count`.
- Escape glob en SCAN.
- Password reset verification en integración.

## Comparación con crate hermano `openauth-redis`

| Tipo de test | `openauth-redis` | `openauth-fred` |
| --- | --- | --- |
| Unit URL / Lua / namespace | Sí (5) | Sí (9 config + 10 storage) |
| Rate limit integración | Sí (8) | Sí (6 RL + 8 auth/storage) |
| E2E sign-up + session | **No** | **Sí** |
| `list_keys` / `clear` integración | **No** | **Sí** |
| Interop cross-crate | No | Sí (dev-dep redis) |

**Conclusión:** para paridad **producto** con e2e upstream de sesiones, **`openauth-fred` es el crate de referencia**; `openauth-redis` cubre sobre todo rate limit.

## Cómo ejecutar

```bash
cargo nextest run -p openauth-fred

OPENAUTH_FRED_REDIS_URL=redis://127.0.0.1:6379 \
OPENAUTH_FRED_VALKEY_URL=valkey://127.0.0.1:6380 \
cargo nextest run -p openauth-fred

cargo nextest run -p openauth-redis   # hermano, rate limit
cargo nextest run -p openauth-core    # mocks secondary
```

CI: `.github/workflows/ci.yml` — `package: openauth-fred` con servicios Redis/Valkey.
