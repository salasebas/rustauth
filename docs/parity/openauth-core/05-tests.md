# Tests — conteos y matriz de cobertura

Comparación aproximada con Better Auth **v1.6.9** (jun 2026). Conteos upstream: archivos `*.test.ts` bajo `packages/core/src` y `packages/better-auth/src`, excluyendo `plugins/`, `client/`, `social-providers/`, `oauth2/`.

## Totales

| Ámbito | Archivos test | Casos `it(` / `test(` aprox. | Notas |
| --- | ---: | ---: | --- |
| `@better-auth/core` | 14 | **184** | Seguridad IP/host, adapter ID, instrumentation |
| `better-auth` server-ish | 36 | **770** | Rutas, cookies, DB, context, rate limit |
| **Upstream in-scope total** | **50** | **~770** `it(` + **~14** `test(` | Recuento en archivos, jun 2026 |
| **`openauth-core` Rust** | 78 (76 `tests/` + 2 `src/`) | **501** (`266` sync + `235` async) | |
| **`openauth-core` sin oauth/social** | — | **453** | Excl. `social_oauth`, `account_tokens`, `auth/oauth` |
| **`openauth` facade** | 2 | ~40+ (estimado en `public_api.rs`) | Producto E2E, no duplicar como core |

### Comando de verificación Rust

```bash
# Total crate
cargo nextest run -p openauth-core

# Aproximar alcance de este doc
cargo nextest run -p openauth-core -- --skip social_oauth --skip account_tokens --skip oauth
```

## Distribución Rust por suite

| Suite (`tests/`) | Archivos `.rs` | `#[test]` + `#[tokio::test]` (suma por archivo) | Enfoque |
| --- | ---: | ---: | --- |
| `api/` (incl. routes) | ~35 | ~180 | Router, body, plugins, **rutas HTTP** |
| `db/` | ~12 | ~120 | Adapter contract, SQL, stores |
| `cookies/` | 3 | ~31 | Parse, session cookie, store |
| `crypto/` | 7 | ~39 | password, jwt, jwe, rotation |
| `auth/` | 2 (+oauth excl.) | ~14 in-scope | email_password, session |
| `context/` | 2 | ~25 | runtime, request_state |
| `rate_limit/` | 1 | ~29 | limiter + disabled_paths |
| `utils/` | 3 | ~27 | host, ip, trusted_origins |
| `env/` | 1 | ~4 | logger |
| `options.rs` | 1 | 8 | builder options |
| Unit en `src/` | 2 | 8 | dialect SQL, cookie cache |

## Matriz upstream ↔ Rust (áreas, no 1:1 por `it`)

| Área upstream (archivo destacado) | ~`it(` upstream | OpenAuth tests | Cobertura relativa |
| --- | ---: | ---: | --- |
| `core/utils/ip.test.ts` | 24 | `utils/ip.rs` (9) | 🟡 Rust menos granular |
| `core/utils/host.test.ts` | 66 | `utils/host.rs` (9) | 🟡 |
| `core/db/adapter/get-id-field.test.ts` | 20 | `db/id_policy.rs` (10) | 🟡 |
| `core/instrumentation/*.test.ts` | ~21 | — | 🔴 gap |
| `cookies/cookies.test.ts` | ~65 | `cookies/*` (~31) | 🟡 |
| `context/create-context.test.ts` | ~145 | `context/*` (~25) | 🟡 upstream muy denso |
| `db/internal-adapter.test.ts` | ~37 | `db/*` stores + adapter | ✅ repartido |
| `crypto/secret-rotation.test.ts` | ~46 | `crypto/secret_rotation` (8) | 🟡 |
| `api/routes/session-api.test.ts` | ~66 | `get_session`+session routes (~22) | 🟡 |
| `api/routes/sign-up.test.ts` | ~34 | `sign_up_email.rs` (11) | 🟡 |
| `api/routes/account.test.ts` | ~24 | `list_accounts`+`unlink` (4) | 🟡 in-scope only |
| `api/to-auth-endpoints.test.ts` | ~63 | `plugin_router.rs` (24) | 🟡 |
| `api/rate-limiter/rate-limiter.test.ts` | ~26 | `rate_limit/rate_limiter.rs` (29) | ✅ |
| `api/middlewares/origin-check.test.ts` | ~36 | `trusted_origins`+router | 🟡 |
| `utils/url.test.ts` | ~66 | host+router parcial | 🟡 |

## Rutas HTTP — detalle in-scope

| Ruta / tema | Archivo Rust | Tests | Archivo upstream | ~`it(` |
| --- | --- | ---: | --- | ---: |
| sign-up email | `sign_up_email.rs` | 11 | `sign-up.test.ts` | 34 |
| sign-in email | `sign_in_email.rs` | 4 | `sign-in.test.ts` | 18 |
| get-session | `get_session.rs` | 9 | `session-api.test.ts` | 66 |
| update-session | `update_session.rs` | 6 | ↑ | |
| session IP metadata | `session_ip_metadata.rs` | 4 | ↑ | |
| sign-out | `sign_out.rs` | 2 | `sign-out.test.ts` | 2 |
| email verification | `email_verification.rs` | 5 | `email-verification.test.ts` | 19 |
| password flows | varios | 12 | `password.test.ts` | 20 |
| update-user / email / delete | varios | 12 | `update-user.test.ts` | 25 |
| list/unlink account | 4 | `account.test.ts` | 24 (incl. oauth cases) |
| set/verify password | 2 | en update-user/password | |
| plugin + openapi | `plugin_router`, `openapi` | 25 | `index.test`, conflicts | |

## Tests excluidos de este doc (pero en el crate)

| Archivo | Tests | Motivo |
| --- | ---: | --- |
| `tests/api/routes/social_oauth.rs` | 20 async | OAuth/social |
| `tests/api/routes/account_tokens.rs` | 9 async | Tokens cuenta OAuth |
| `tests/auth/oauth.rs` | 19 async + 2 sync | Módulo `auth/oauth` |
| `tests/package_reexports.rs` | 1 | Re-exports con features default |

## Qué testea OpenAuth de más (superset server)

- Contrato **`DbAdapter`** exhaustivo (`adapter_contract`, `adapter_factory`, `adapter_transform`).
- **SQL dialect** y migraciones multi-backend (`db/sql.rs` — 27 tests).
- **Plugin router** conflictos y hooks sin Vitest equivalente 1:1.
- **OpenAPI** generation smoke (`routes/openapi.rs`).
- **Rate limit** con `disabled_paths` sin tocar storage.

## Qué testea upstream de más (huecos Rust)

- **OpenTelemetry** instrumentation (core + endpoint/db tests en better-auth).
- **Cliente** session refresh, proxy, query (toda la carpeta `client/`).
- **Plugins** (mayoría de los 80 archivos test del paquete).
- **OAuth2** `link-account`, utils (carpeta `oauth2/`).
- **Integraciones** Next.js (`integrations/next-js.test.ts`).
- Casos **Zod / Standard Schema** en tipos (`types/types.test.ts`).

## Fachada `openauth` (referencia cruzada)

| Archivo | Propósito |
| --- | --- |
| `tests/public_api.rs` | Migraciones SQLx/SQLite/Postgres, hooks, rate limit secundario, builders async con telemetry |
| `tests/feature_flags.rs` | Aislamiento de features `sqlx-postgres`, `oidc` vs `saml` |

No sustituyen tests de `openauth-core`; validan el **producto empaquetado**.

## Harness de rutas (sesgo)

`tests/api/routes/mod.rs` construye el router con `disable_csrf_check: true` y `disable_origin_check: true` para **todos** los tests de rutas. CSRF/origin se prueban en `tests/api/router.rs` y `tests/utils/trusted_origins.rs`, pero **no** junto con flujos sign-in/session.

## Rutas con test “thin” (1 caso)

`list_sessions`, `list_accounts`, `revoke_session`, `revoke_sessions`, `revoke_other_sessions`, `set_password`, `verify_password`, `delete_user_callback`, `error_page` — ver tabla en [08-gaps-audit.md](./08-gaps-audit.md).

## Interpretación

- **Menos tests Rust que `it(` Vitest** no implica menor paridad si cada test Rust es más amplio; varios archivos upstream tienen **un solo** `it` equivalente (p. ej. `sign-out.test.ts`: 1).
- Las mayores brechas de **cantidad** están en **`create-context.test.ts`** (~115 `it`), **`cookies.test.ts`** (~54), **`session-api.test.ts`** (~56).
- Prioridad: ampliar revoke/list/set_password; `auto_sign_in_after_verification`; `fresh_age` en HTTP; matriz en [08-gaps-audit.md](./08-gaps-audit.md).
