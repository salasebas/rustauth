# Códigos de error HTTP — `BASE_ERROR_CODES` ↔ OpenAuth

Upstream centraliza mensajes en `@better-auth/core/error/codes.ts` (`BASE_ERROR_CODES`).  
OpenAuth usa **strings sueltas** en rutas + enums locales (`ApiErrorCode`, `AuthFlowErrorCode`).

## Router / seguridad (`ApiErrorCode`)

| Código upstream | OpenAuth `ApiErrorCode` | Paridad |
| --- | --- | --- |
| `INVALID_ORIGIN` | `InvalidOrigin` | ✅ |
| `INVALID_CALLBACK_URL` | `InvalidCallbackUrl` | ✅ |
| `INVALID_REDIRECT_URL` | `InvalidRedirectUrl` | ✅ |
| `INVALID_ERROR_CALLBACK_URL` | `InvalidErrorCallbackUrl` | ✅ |
| `INVALID_NEW_USER_CALLBACK_URL` | `InvalidNewUserCallbackUrl` | ✅ |
| `MISSING_OR_NULL_ORIGIN` | `MissingOrNullOrigin` | ✅ |
| `CROSS_SITE_NAVIGATION_LOGIN_BLOCKED` | `CrossSiteNavigationLoginBlocked` | ✅ |
| — | `NotFound`, `TooManyRequests` | Extra router |

## Rutas core — códigos usados en Rust (grep en `src/api`)

| Código | Upstream `BASE_ERROR_CODES` | Dónde en OpenAuth |
| --- | --- | --- |
| `INVALID_EMAIL_OR_PASSWORD` | ✅ | `auth/email_password`, sign-in tests |
| `USER_ALREADY_EXISTS` | ✅ | sign-up |
| `USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL` | ✅ | ✅ con `another_email_error_on_duplicate` |
| `INVALID_EMAIL` | ✅ | `AuthFlowErrorCode` |
| `INVALID_PASSWORD` / `INVALID_PASSWORD_LENGTH` | ✅ / parcial | `INVALID_PASSWORD`, `INVALID_PASSWORD_LENGTH`, `PASSWORD_TOO_SHORT/LONG` |
| `EMAIL_NOT_VERIFIED` | ✅ | `AuthFlowErrorCode` |
| `FAILED_TO_CREATE_SESSION` | ✅ | `AuthFlowErrorCode` |
| `VERIFICATION_EMAIL_NOT_ENABLED` | ✅ | email_verification, change_email |
| `EMAIL_ALREADY_VERIFIED` | ✅ | email_verification |
| `EMAIL_CAN_NOT_BE_UPDATED` | ✅ | update_user |
| `CREDENTIAL_ACCOUNT_NOT_FOUND` | ✅ | password routes |
| `PASSWORD_ALREADY_SET` | ✅ | set_password |
| `FAILED_TO_UNLINK_LAST_ACCOUNT` | ✅ | unlink_account (+ test) |
| `METHOD_NOT_ALLOWED` | ✅ (`METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED` upstream) | get-session POST sin defer |
| `BODY_MUST_BE_AN_OBJECT` | ✅ | update-session |
| `UNAUTHORIZED` | (implícito) | `shared::unauthorized()` |
| `NOT_FOUND` | — | varias rutas |
| `INVALID_TOKEN` | ✅ | password reset, delete callback |
| `SESSION_NOT_FRESH` | ✅ | 🔴 **No** — delete-user usa `SESSION_EXPIRED` |
| `SESSION_EXPIRED` | ✅ (distinto mensaje) | delete-user cuando sesión no fresh |
| `FIELD_NOT_ALLOWED` | ✅ | ✅ update-session campos no input |
| `EMAIL_MISMATCH` | ✅ | 🔴 no grep en core in-scope |
| `ACCOUNT_NOT_FOUND` | ✅ | parcial en account oauth |
| `USER_ALREADY_HAS_PASSWORD` | ✅ | 🔴 no encontrado (set_password usa `PASSWORD_ALREADY_SET`) |

## Códigos upstream sin uso claro en rutas core Rust

| Código | Notas |
| --- | --- |
| `USER_NOT_FOUND` | email_verification route |
| `FAILED_TO_CREATE_USER` | adapter errors genéricos |
| `FAILED_TO_UPDATE_USER` | — |
| `FAILED_TO_GET_SESSION` | — |
| `SOCIAL_*`, `PROVIDER_*`, `ID_TOKEN_*` | oauth / social |
| `LINKED_ACCOUNT_ALREADY_EXISTS` | oauth linking |
| `FAILED_TO_CREATE_VERIFICATION` | — |
| `ASYNC_VALIDATION_NOT_SUPPORTED` | N/A Rust |
| `VALIDATION_ERROR`, `MISSING_FIELD` | body schema distinto |
| `CALLBACK_URL_REQUIRED` | validación URL en social |

## Plugin error codes

| Upstream | OpenAuth |
| --- | --- |
| Plugins registran códigos en registry TS | `AuthPlugin::with_error_code`, merge en `context.plugin_error_codes` |
| Tests | `plugin_router` parcial; sin matriz 1:1 |

## Errores con cookies en respuesta (gap de pipeline)

Upstream `createAuthEndpoint` adjunta `Set-Cookie` acumulados al lanzar `APIError` (`kAPIErrorHeaderSymbol` en `@better-auth/core/api`).  
OpenAuth **no** documenta ni replica ese merge en el router — las rutas devuelven JSON/redirect sin ese contrato explícito.

## Recomendación de paridad

1. Unificar enum Rust `BaseErrorCode` alineado a `BASE_ERROR_CODES` para rutas core.
2. Alinear `SESSION_NOT_FRESH` vs `SESSION_EXPIRED` en delete-user / change-password si aplica fresh gate.
3. Añadir `USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL` si upstream lo distingue en sign-up anti-enumeración.
