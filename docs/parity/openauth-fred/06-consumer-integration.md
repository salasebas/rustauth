# 06 — Integración con consumidores (contrato, no implementación)

`openauth-fred` **solo** implementa `SecondaryStorage` y `RateLimitStore`. La lógica de sesiones, verificación, API keys, SSO, etc. vive en `openauth-core`, `openauth` y plugins — igual que upstream consume `secondaryStorage` desde `better-auth`.

## Auto-cableado rate limit (importante)

Upstream (`create-context.ts`): si existe `secondaryStorage` y no se define `rateLimit.storage`, el default es **`"secondary-storage"`** — el rate limiter reutiliza el **mismo** KV con JSON.

OpenAuth: `secondary_storage` en opciones **no** cambia `rate_limit.storage` (sigue en memory salvo configuración explícita). Para Redis hace falta **`FredRateLimitStore`** además de **`FredSecondaryStorage`**, y normalmente **dos** conexiones `connect()` o un `Client` compartido vía `::new`.

Detalle: [10-second-pass-findings.md](./10-second-pass-findings.md) §1.

## Consumidores upstream (referencia 1.6.9)

| Consumidor | Archivo principal | Claves / comportamiento esperado del adaptador |
| --- | --- | --- |
| Sesiones | `better-auth/src/db/internal-adapter.ts` | `session:{token}`, `session:user:{id}` — ver [08-logical-keys](../openauth-redis/08-logical-keys-and-payloads.md) |
| Rate limit | `better-auth/src/api/rate-limiter/index.ts` | JSON bajo prefijo global (no usa paquete redis directamente) |
| Verificación | `internal-adapter` | `verification:{identifier}` |
| API key | `packages/api-key/src/adapter.ts` | `api-key:*` (storage propio o fallback secondary) |
| OAuth provider | `packages/oauth-provider/src/oauth.ts` | Valida `storeSessionInDatabase` con secondary |
| SSO | `packages/sso` | Domain verification en secondary |
| Device auth | `plugins/device-authorization/routes.ts` | Sesión temporal con TTL |

## Consumidores OpenAuth

| Consumidor | Crate | Requiere de Fred |
| --- | --- | --- |
| Sesiones / list / revoke | `openauth-core` | `get`/`set`/`delete` strings JSON |
| Verificación email / reset | `openauth-core` | TTL segundos, claves `verification:…` |
| Rate limit HTTP | `openauth` + core | `FredRateLimitStore` en `RateLimitOptions` |
| Ejemplo app | `examples/full-app` | `FredRateLimitStore::connect_*` |
| Plugins (API key, SSO, …) | varios | Mismo contrato `SecondaryStorage` si configurado |

## Qué valida este crate de integración

| Escenario | Test |
| --- | --- |
| Sign-up email → sesión en secondary | `openauth_email_signup_uses_fred_secondary_storage_for_sessions` (claves `session:` / `session:user:`, no `active-sessions-{id}` upstream) |
| `storeSessionInDatabase` + secondary | `openauth_email_signup_with_database_sessions_still_writes_fred_secondary_storage` |
| Password reset → `verification:reset-password:{token}` | `openauth_password_reset_uses_fred_secondary_storage_for_verification` |
| Rate limit 429 en handler | `openauth_handler_async_uses_fred_rate_limit_store` |

## Qué no valida este crate (otros crates / fuera de alcance)

| Escenario upstream | Dónde upstream lo prueba | OpenAuth |
| --- | --- | --- |
| OAuth stateless + Google | `e2e/smoke/redis.spec.ts` | `openauth` / providers — **no** en fred |
| API key secondary CRUD | `api-key.test.ts` | `openauth-api-key` + core |
| SSO domain verification | `domain-verification.test.ts` | `openauth-sso` |
| `get` devuelve objeto parseado | `secondary-storage.test.ts` | **No** (solo `String`) |
| Schema sin tabla session | `get-tables.test.ts` | `openauth-core` |

## Compatibilidad de prefijo para migración desde Better Auth

Para leer datos escritos por upstream con `keyPrefix: "better-auth:"` y claves planas:

- Configurar `FredSecondaryStorageOptions { key_prefix: "better-auth:".into(), .. }` **no** alinea el segmento `secondary:` — OpenAuth siempre inserta `secondary:` en la clave física.
- Migración real: re-exportar sesiones o usar prefijo + convención documentada en [03-secondary-storage.md](./03-secondary-storage.md).

## Resumen

| Pregunta | Respuesta |
| --- | --- |
| ¿Fred implementa sesiones? | No — las escribe `openauth-core` vía trait |
| ¿Paridad de internal-adapter? | Depende de core; Fred cumple contrato KV |
| ¿Paridad rate limit producto? | Sí vía `FredRateLimitStore` (modelo distinto a BA JSON) |
