# Ciclo de vida de usuario — huecos funcionales (código)

Comparación directa de `user.changeEmail` y `user.deleteUser` en  
`packages/core/src/types/init-options.ts` vs `crates/openauth-core/src/options/user.rs` y rutas.

## `user.deleteUser`

| Campo / comportamiento upstream | OpenAuth | Estado |
| --- | --- | --- |
| `enabled` | `DeleteUserOptions.enabled` | ✅ |
| `sendDeleteAccountVerification` | `DeleteUserOptions` | ✅ |
| `beforeDelete` | `DeleteUserOptions` | ✅ |
| `afterDelete` | `DeleteUserOptions` | ✅ |
| `deleteTokenExpiresIn` | `delete_token_expires_in` | ✅ |

### Flujo POST `/delete-user` sin password ni token

| Paso | Upstream (`update-user.ts`) | OpenAuth (`delete_user.rs` + `user.rs`) |
| --- | --- | --- |
| Sesión | `sensitiveSessionMiddleware` (sin cookie cache) | `sensitive_session()` — ✅ equivalente |
| Con password | Verifica credential + `INVALID_PASSWORD` | ✅ |
| Con token en body | Redirige a callback interno | ✅ |
| Sin password/token | Si `sendDeleteAccountVerification` → crea token + **email**; si no → borra si sesión fresh | ✅ mismo criterio (`api/services/user.rs`) |

### Flujo GET `/delete-user/callback`

| | Upstream | OpenAuth |
| --- | --- | --- |
| Token en query | ✅ | ✅ |
| Sesión requerida | ✅ sensitive | ✅ `sensitive_session` |
| Hooks before/after | ✅ | ✅ |

### Código de error sesión no fresh

| | Upstream | OpenAuth |
| --- | --- | --- |
| Código | `SESSION_NOT_FRESH` (`freshSessionMiddleware` / delete flow) | `SESSION_EXPIRED` en delete-user |
| HTTP | `FORBIDDEN` en middleware fresh | `BAD_REQUEST` en delete |

Tests upstream: `session-api.test.ts` espera `SESSION_NOT_FRESH`.  
OpenAuth: `tests/api/routes/delete_user.rs` — revisar si cubre stale session (añadir si falta).

---

## `user.changeEmail`

| Campo upstream | OpenAuth | Estado |
| --- | --- | --- |
| `enabled` | `ChangeEmailOptions.enabled` | ✅ |
| `updateEmailWithoutVerification` | ✅ | ✅ tests `change_email.rs` |
| `sendChangeEmailConfirmation` (email al **viejo** correo) | `ChangeEmailOptions` | ✅ |

### Flujo `/change-email`

| Caso | Upstream | OpenAuth |
| --- | --- | --- |
| Email ya usado | Anti-enumeración / verificación | Crea token + `VerificationSent` (similar) |
| User no verificado + `updateEmailWithoutVerification` | ✅ | ✅ |
| Cambio con verificación | Usa hooks de verificación | Usa `send_verification_email` global con identifier `change-email-verification` |
| Confirmación al email **anterior** | `sendChangeEmailConfirmation` opcional | **No** — solo nuevo flujo vía `send_verification_email` |

---

## Middleware de sesión no portados como tipos

| Middleware upstream (`session.ts`) | OpenAuth |
| --- | --- |
| `sessionMiddleware` | Implícito en rutas que exigen sesión |
| `sensitiveSessionMiddleware` | `sensitive_session()` / `disable_cookie_cache` |
| `freshSessionMiddleware` | Solo lógica inline en delete-user (código distinto) |
| `requestOnlySessionMiddleware` | 🔴 No |

---

## Tests relacionados

| Área | Archivo Rust | Cobertura |
| --- | --- | --- |
| change-email | `tests/api/routes/change_email.rs` | 3 tests — buena para unverified/immediate |
| delete-user | `tests/api/routes/delete_user.rs` | 6 tests (verificación, stale session, credential) |
| delete callback | `delete_user_callback.rs` | 1 test |

---

## Acciones sugeridas

1. Extender `DeleteUserOptions` con `send_delete_account_verification`, `before_delete`, `after_delete`, `delete_token_expires_in` o documentar wont-fix.
2. Alinear código `SESSION_NOT_FRESH` donde upstream lo usa para fresh gate.
3. Evaluar `send_change_email_confirmation` para paridad de seguridad (notificar email antiguo).
4. Tests: delete-user con sesión vieja; delete-user con hook de email (si se implementa).
