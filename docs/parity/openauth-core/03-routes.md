# Rutas HTTP — paridad de endpoints

Rutas relativas a `basePath` (por defecto upstream `/api/auth`). OpenAuth usa el mismo sufijo en `AuthEndpoint::path`.

**Leyenda:** ✅ implementado in-scope · ⛔ excluido (OAuth/social) · ⚠️ diferencia de comportamiento

## Endpoints in-scope

| Path | Métodos | Upstream | OpenAuth | Tests Rust (archivo) | Tests upstream |
| --- | --- | --- | --- | --- | --- |
| `/ok` | GET | `ok.ts` | `api/router.rs` + `core_endpoints()` | `api/router.rs` | indirecto (no en `routes/mod.rs`) |
| `/error` | * | `error.ts` | `routes/error.rs` | `routes/error_page.rs` (1) | `error.test.ts` (3) |
| `/sign-up/email` | POST | `sign-up.ts` | `routes/sign_up.rs` | `sign_up_email.rs` (11) | `sign-up.test.ts` (34) |
| `/sign-in/email` | POST | `sign-in.ts` | `routes/sign_in.rs` | `sign_in_email.rs` (4) | `sign-in.test.ts` (18) |
| `/sign-out` | POST | `sign-out.ts` | `routes/sign_out.rs` | `sign_out.rs` (2) | `sign-out.test.ts` (2) |
| `/get-session` | GET, POST | `session.ts` | `routes/session.rs` | `get_session.rs` (9) | `session-api.test.ts` (66) |
| `/list-sessions` | * | `session.ts` | `routes/session.rs` | `list_sessions.rs` (1) | en session-api |
| `/update-session` | * | `update-session.ts` | `routes/session.rs` | `update_session.rs` (6) | en session-api |
| `/revoke-session` | * | `session.ts` | `routes/session.rs` | `revoke_session.rs` (1) | en session-api |
| `/revoke-sessions` | * | `session.ts` | `routes/session.rs` | `revoke_sessions.rs` (1) | en session-api |
| `/revoke-other-sessions` | * | `session.ts` | `routes/session.rs` | `revoke_other_sessions.rs` (1) | en session-api |
| `/send-verification-email` | POST | `email-verification.ts` | `routes/email_verification.rs` | `email_verification.rs` (5) | `email-verification.test.ts` (19) |
| `/verify-email` | GET | `email-verification.ts` | `routes/email_verification.rs` | ↑ | ↑ |
| `/request-password-reset` | POST | `password.ts` | `routes/password.rs` | `request_password_reset.rs` (3) | `password.test.ts` (20) |
| `/reset-password/:token` | GET | `password.ts` | `routes/password.rs` | `reset_password.rs` (4) | ↑ |
| `/reset-password` | POST | `password.ts` | `routes/password.rs` | ↑ | ↑ |
| `/verify-password` | POST | `password.ts` | `routes/password.rs` | `verify_password.rs` (1) | ↑ |
| `/change-password` | POST | `update-user.ts` | `routes/password.rs` | `change_password.rs` (3) | `update-user.test.ts` |
| `/set-password` | POST | `update-user.ts` (path virtual en better-call) | `routes/password.rs` (`/set-password`) | `set_password.rs` (1) | en update-user |
| `/update-user` | POST | `update-user.ts` | `routes/update_user.rs` | `update_user.rs` (6) | `update-user.test.ts` (25) |
| `/change-email` | POST | `update-user.ts` | `routes/change_email.rs` | `change_email.rs` (3) | ↑ |
| `/delete-user` | POST | `update-user.ts` | `routes/delete_user.rs` | `delete_user.rs` (4) | ↑ |
| `/delete-user/callback` | GET | `update-user.ts` | `routes/delete_user.rs` | `delete_user_callback.rs` (1) | ↑ |
| `/list-accounts` | GET | `account.ts` | `routes/account.rs` | `list_accounts.rs` (1) | `account.test.ts` (24) |
| `/unlink-account` | POST | `account.ts` | `routes/account.rs` | `unlink_account.rs` (3) | ↑ |

## Endpoints excluidos (documentados, no auditados aquí)

| Path | Upstream | OpenAuth | Motivo exclusión |
| --- | --- | --- | --- |
| `/sign-in/social` | `sign-in.ts` | `routes/social.rs` | Sesión paralela OAuth/social |
| `/sign-in/oauth2` | — | `routes/social.rs` | Extensión / generic OAuth |
| `/callback/:id` | `callback.ts` | `routes/social.rs` | Callback proveedor |
| `/link-social` | `account.ts` | `routes/social.rs` | |
| `/get-access-token` | `account.ts` | `routes/account.rs` | Tokens cuenta OAuth |
| `/refresh-token` | `account.ts` | `routes/account.rs` | |
| `/account-info` | `account.ts` | `routes/account.rs` | |

Registro en código:

```31:74:crates/openauth-core/src/api/routes/mod.rs
pub fn core_auth_async_endpoints(adapter: Arc<dyn DbAdapter>) -> Vec<AsyncAuthEndpoint> {
    vec![
        sign_up::sign_up_email_endpoint(Arc::clone(&adapter)),
        sign_in::sign_in_email_endpoint(Arc::clone(&adapter)),
        #[cfg(feature = "oauth")]
        social::sign_in_social_endpoint(Arc::clone(&adapter)),
        // ... oauth-gated endpoints ...
        sign_out::sign_out_endpoint(adapter),
    ]
}
```

Upstream `baseEndpoints` equivalente (`api/index.ts` ~230–260) incluye las rutas OAuth en el mismo objeto.

## Comportamiento transversal de rutas

| Tema | Upstream | OpenAuth | Tipo diferencia |
| --- | --- | --- | --- |
| `disabledPaths` | `api/index.ts` onRequest | `api/router.rs` | ✅ Paridad |
| Origin / CSRF | `originCheckMiddleware` | trusted origins + router | ✅ Alta |
| Rate limit por path | `api/rate-limiter` | `rate_limit.rs` | ✅ Alta |
| OpenAPI | Deshabilitado en router | `AuthRouter::openapi_schema()` | ⚠️ Rust más explícito |
| Plugin endpoints merge | `getEndpoints()` | `AuthRouter` + plugins | ✅ |
| Respuestas error JSON | `APIError` shapes | `OpenAuthError` | ⚠️ Diseño: mismas reglas de seguridad, strings no idénticos |

## Huecos de endpoint conocidos

| Tema | Upstream | OpenAuth |
| --- | --- | --- |
| Endpoint interno refresh “fresh session” | Usado en tests `session-api.test.ts` (`freshSessionCheck`) | Lógica en `auth/session.rs` (`needs_refresh`, `defer_refresh`) sin path público dedicado |
| `auth.api.signInEmail()` (llamada directa) | Soportado vía better-call | No — solo HTTP/async handler |

## Cobertura de tests por ruta (resumen)

Rust concentra muchos escenarios en pocos archivos grandes (`sign_up_email.rs`, `get_session.rs`); upstream concentra sesión en `session-api.test.ts` (**66** `it`). La paridad **funcional** no implica el mismo número de casos por archivo.

Ver matriz completa en [05-tests.md](./05-tests.md).
