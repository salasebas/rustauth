# Auditoría de huecos (código + tests, jun 2026)

Pasadas **2 y 3** leyendo fuentes y tests, no READMEs. Pin: Better Auth **1.6.9**.  
Tercera pasada añade: códigos de error, delete-user/change-email, utils upstream sin port.

## Rutas HTTP

### In-scope: cobertura de tests

| Path | Registrado | Módulo test | `#` tests async/sync | Profundidad |
| --- | --- | --- | --- | --- |
| `/sign-up/email` | ✅ | `sign_up_email.rs` | 11 | Alta (synthetic user, secondary storage) |
| `/sign-in/email` | ✅ | `sign_in_email.rs` | 4 | Media |
| `/sign-out` | ✅ | `sign_out.rs` | 2 | Baja |
| `/get-session` GET+POST | ✅ | `get_session.rs` | 9 | Alta (defer refresh) |
| `/list-sessions` | ✅ | `list_sessions.rs` | 1 | **Muy baja** |
| `/update-session` | ✅ | `update_session.rs` | 6 | Media |
| `/revoke-session` | ✅ | `revoke_session.rs` | 1 | **Muy baja** |
| `/revoke-sessions` | ✅ | `revoke_sessions.rs` | 1 | **Muy baja** |
| `/revoke-other-sessions` | ✅ | `revoke_other_sessions.rs` | 1 | **Muy baja** |
| `/update-user` | ✅ | `update_user.rs` | 6 | Media |
| `/change-email` | ✅ | `change_email.rs` | 3 | Media |
| `/send-verification-email` | ✅ | `email_verification.rs` | 5 | Media |
| `/verify-email` | ✅ | ↑ | ↑ | |
| `/request-password-reset` | ✅ | `request_password_reset.rs` | 3 | Media |
| `/reset-password/:token` | ✅ | `reset_password.rs` | 4 | Media |
| `/reset-password` | ✅ | ↑ | ↑ | |
| `/change-password` | ✅ | `change_password.rs` | 3 | Media |
| `/set-password` | ✅ | `set_password.rs` | 1 | **Muy baja** |
| `/verify-password` | ✅ | `verify_password.rs` | 1 | **Muy baja** |
| `/delete-user` | ✅ | `delete_user.rs` | 6 | Media (verificación, stale session, hooks) |
| `/delete-user/callback` | ✅ | `delete_user_callback.rs` | 1 | **Muy baja** |
| `/list-accounts` | ✅ | `list_accounts.rs` | 1 | **Muy baja** |
| `/unlink-account` | ✅ | `unlink_account.rs` | 3 | Media |
| `/error` | ✅ | `error_page.rs` | 1 | Baja |
| `/ok` | ✅ `core_endpoints()` | `router.rs` (no route suite) | indirecto | OK probado en router |

**Conclusión rutas:** ningún path in-scope queda sin **algún** test HTTP; muchos tienen **1 solo** `#[tokio::test]` frente a decenas en upstream (`session-api.test.ts` ≈ 56 `it`).

### Rutas en rate limit sin implementar en core

Definidas en `src/rate_limit.rs` (`default_special_rule`):

| Path prefijo | Upstream equivalente | En `core_auth_async_endpoints` |
| --- | --- | --- |
| `/forget-password` | alias histórico | ❌ (usamos `/request-password-reset`) |
| `/email-otp/send-verification-otp` | plugin email-otp | ❌ |
| `/email-otp/request-password-reset` | plugin email-otp | ❌ |

OpenAPI (`api/openapi.rs`) etiqueta `"email-otp"` — **anticipación de plugin**, no rutas core.

### Excluidas (otra sesión)

`/sign-in/social`, `/sign-in/oauth2`, `/callback/:id`, `/link-social`, `/get-access-token`, `/refresh-token`, `/account-info`.

---

## Comportamiento de sesión (sin path dedicado)

| Comportamiento upstream | Implementación Rust | Tests |
| --- | --- | --- |
| `deferSessionRefresh` + GET vs POST `/get-session` | `session.rs` + `auth/session.rs` | ✅ `get_session.rs` |
| `freshAge` + `sensitiveSessionMiddleware` | `api/services/user.rs`, `shared::sensitive_session` | 🟡 context/runtime; **no assert HTTP “fresh”** |
| `should-session-refresh` request state | — | 🔴 No port de `api/state/should-session-refresh.ts` |
| Cookie cache strategies jwt/jwe/compact | `cookies/cache.rs`, session | 🟡 JWT/JWE en `tests/cookies/session.rs`; rutas mayormente Compact |
| Account cookie refresh on session | oauth `account_linking` | ➖ oauth tests only |

---

## Opciones sin paridad o sin tests

Ver [07-options-field-matrix.md](./07-options-field-matrix.md). Resumen **🔴 gap funcional**:

| Gap | Estado (jun 2026) |
| --- | --- |
| `appName` configurable | ✅ `OpenAuthOptions::app_name` |
| `options.databaseHooks` | ✅ `OpenAuthOptions::database_hooks` + plugins |
| `options.hooks` global | ✅ plugin `__openauth_global__` en `context/builder.rs` |
| `onAPIError` | ✅ `api/on_api_error.rs` en `AuthRouter::handle*` |
| `logger` en options | ✅ `OpenAuthOptions::logger` |
| `baseURL` dinámico (`DynamicBaseURLConfig`) | No en `utils/` |
| `trustedProxyHeaders` | No |
| `verification.storeIdentifier` / `disableCleanup` | No en verification store |
| Custom `password.hash` / `verify` en options | `PasswordContext` fija scrypt en builder |
| `emailAndPassword.customSyntheticUser` | Comportamiento vía `on_existing_user_sign_up` + synthetic record |

---

## Módulos upstream sin equivalente Rust en core

| Upstream | OpenAuth | Tipo |
| --- | --- | --- |
| `@better-auth/core/instrumentation` | — | Gap OTEL |
| `@better-auth/core/async_hooks` (ALS) | `context/request_state.rs` | Parcial |
| `better-auth/src/call.ts` (`auth.api.*`) | — | Diseño server-only |
| `better-auth/src/auth/minimal.ts` | — | Gap export |
| `better-auth/src/integrations/*` | — | N/A app |
| `better-auth/src/api/state/oauth.ts` | oauth state crate | ➖ oauth |
| `api/middlewares/authorization.ts` | — | Org/plugin middleware |
| `core/utils/async.ts` (`mapConcurrent`) | Tokio | N/A |
| `core/utils/deprecate.ts` | — | Bajo impacto |

---

## Tests: upstream vs Rust (recuentos verificados)

### Upstream in-scope (`*.test.ts`, excl. plugins/client/social-providers/oauth2)

| Métrica | Valor |
| --- | --- |
| Archivos | **36** |
| `it(` | **≈ 770** |
| `test(` extra | **≈ 14** (`auth/full.test.ts`) |

### `@better-auth/core` (referencia contratos)

| Métrica | Valor |
| --- | --- |
| Archivos `*.test.ts` | **14** |
| `it(` en utils/host+ip+… | **≈ 184** (incl. oauth2 validate-token si se cuenta core — **excluir** de paridad core auth) |

### `openauth-core`

| Métrica | Valor |
| --- | --- |
| Total `#[test]` + `#[tokio::test]` | **501** |
| In-scope (excl. `social_oauth`, `account_tokens`, `auth/oauth`) | **453** |
| Unit en `src/` | **8** |

### Tests upstream **sin** contraparte dedicada en Rust

| Upstream test file | `it(` aprox. | Nota OpenAuth |
| --- | ---: | --- |
| `context/create-context.test.ts` | 115 | Repartido en `context/runtime`, builder, plugins — **mucho menos denso** |
| `cookies/cookies.test.ts` | 54 | `tests/cookies/*` ≈ 31 tests |
| `utils/url.test.ts` | 54 | Parcial en `router` + `host` |
| `crypto/secret-rotation.test.ts` | 38 | 8 tests Rust |
| `api/to-auth-endpoints.test.ts` | 51 | `plugin_router.rs` 24 |
| `api/routes/session-api.test.ts` | 56 | `get_session`+session 22 |
| `core/utils/host.test.ts` | 69 | `utils/host.rs` 9 |
| `core/utils/ip.test.ts` | 24 | `utils/ip.rs` 9 |
| `core/utils/async.test.ts` | 12 | No port |
| `core/utils/fetch-metadata.test.ts` | 3 | Usado en `api/security.rs`; tests en `request_utils` |
| `core/utils/deprecate.test.ts` | 5 | No port |
| `core/instrumentation/*.test.ts` | ~21 | **Gap** |
| `instrumentation.endpoint/db.test.ts` | 15 | **Gap** |
| `integrations/next-js.test.ts` | 5 | N/A |
| `call.test.ts` | 20 | N/A |
| `types/types.test.ts` | 14 | N/A (inferencia TS) |

### Tests Rust **extra** (superset útil)

- `db/adapter_contract.rs`, `adapter_transform.rs`, `sql.rs` (27)
- `db/adapter_factory.rs` (hooks, joins)
- `rate_limit/rate_limiter.rs` (29) — incl. `disabled_paths`, `MissingIpPolicy`
- `api/plugin_router.rs` (24)
- Synthetic sign-up / email enumeration (`sign_up_email.rs`)

---

## Harness de tests de rutas (sesgo importante)

En `tests/api/routes/mod.rs`, **todos** los routers de ruta fuerzan:

```rust
advanced: AdvancedOptions {
    disable_csrf_check: true,
    disable_origin_check: true,
    ...
}
```

**Implicación:** la paridad documentada para rutas **no valida** CSRF ni origin en producción. Hay tests aparte en `utils/trusted_origins.rs` y `api/router.rs` (`fetch_metadata`), pero no integrados con el harness de rutas.

---

## `AuthRouter` vs upstream `router`

| Capacidad | Upstream | OpenAuth |
| --- | --- | --- |
| Plugin `onRequest` antes de rate limit | ✅ orden en `api/index.ts` | ✅ `run_on_request_plugins` |
| Rate limit onRequest/onResponse | ✅ | ✅ |
| `disabledPaths` | ✅ | ✅ |
| `onAPIError.throw` / redirect | ✅ | 🔴 |
| OpenTelemetry spans | ✅ | 🔴 |
| `core_endpoints` `/ok` + async routes | better-call merge | `core_endpoints()` + `with_async_endpoints` |

---

## Tercera pasada — hallazgos nuevos

### Funcionalidad usuario (crítico)

Ver [10-user-lifecycle-gaps.md](./10-user-lifecycle-gaps.md).

| Hueco | Severidad |
| --- | --- |
| `deleteUser.sendDeleteAccountVerification` — email antes de borrar | **Alta** |
| `deleteUser.beforeDelete` / `afterDelete` | Media |
| `changeEmail.sendChangeEmailConfirmation` (email al correo anterior) | Media |
| `SESSION_NOT_FRESH` vs `SESSION_EXPIRED` en delete-user | Media (compat clientes) |

### Códigos de error

Ver [09-error-codes.md](./09-error-codes.md). Resumen: ~30 códigos upstream; Rust cubre **~20** en rutas core; faltan variantes y centralización.

### Utils / pipeline upstream sin port en core

| Upstream (`better-auth/src/utils` o `core`) | OpenAuth |
| --- | --- |
| `utils/async.ts` (`mapConcurrent`) | Tokio nativo — sin tests equivalentes |
| `utils/deprecate.ts` | — |
| `utils/time.ts`, `constants.ts` | `time` crate |
| `utils/hide-metadata.ts`, `plugin-helper.ts` | — |
| `getCurrentAdapter` / `runWithTransaction` ALS | Sin ALS de adapter |
| `attachResponseHeadersToAPIError` (cookies en error) | — |
| `requestOnlySessionMiddleware` | — |
| `verification-token-storage` (hash identifier) | Identifiers plain en Rust |

### Paridad confirmada (antes poco documentada)

| Tema | Evidencia |
| --- | --- |
| `rememberMe` / `dont_remember` cookie | sign-in/up, change_email tests |
| `application/x-www-form-urlencoded` en sign-in/up | `allowed_media_types` en rutas |
| Query `disableRefresh`, `disableCookieCache` en get-session | `session.rs` + tests |
| Cookie `Partitioned` | `options/advanced`, `tests/cookies/cookies.rs` |
| IP / user-agent en sesión | `session_ip_metadata.rs`, `CreateSessionInput` |
| `FAILED_TO_UNLINK_LAST_ACCOUNT` + `allow_unlinking_all` | `unlink_account.rs` tests |
| Additional fields session/user | `update_session.rs`, plugin schema tests |
| Hybrid rate limit | `rate_limiter.rs` |

### `better-auth/src/utils` (17 archivos fuera de tests)

Solo portados en espíritu: `url`, `host`, `ip` (vía core), `fetch-metadata` → `api/security.rs`.  
**No** hay crate equivalente a `get-request-ip.ts` como módulo aparte — lógica en `rate_limit` + `advanced.ip_address`.

---

## Checklist “no olvidar” para próxima iteración

- [ ] Matriz `session-api.test.ts` ↔ cada `#[tokio::test]` en `get_session.rs` / `update_session.rs`
- [ ] `auto_sign_in_after_verification` — test de ruta
- [ ] `disable_sign_up` en `/sign-up/email`
- [ ] Delete-user: `sendDeleteAccountVerification` (implementar o wont-fix documentado)
- [ ] `SESSION_NOT_FRESH` vs `SESSION_EXPIRED`
- [ ] Ampliar tests 1-shot: list_sessions, revoke_*, set_password, delete_user stale session
- [ ] `databaseHooks` / `hooks` / `onAPIError` top-level
- [ ] `app_name`, custom password hash, `verification.storeIdentifier`
- [ ] OTEL vs telemetría producto
