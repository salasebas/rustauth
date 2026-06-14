# RustAuth Backend Reference

Ejemplo **solo backend** (sin vistas ni UI) que muestra cómo montar RustAuth con
arquitectura modular, Deadpool Postgres, todos los plugins oficiales activos y
rutas de introspección para explorar la API pública.

A diferencia de [`full-app`](../full-app/), este ejemplo se centra en la lógica
que necesita quien integra RustAuth en su propia aplicación: configuración,
plugins, persistencia, montaje en Axum y consumo de endpoints.

## Estructura del código

```
src/
├── config.rs          # Variables de entorno (secret, base URL, Postgres, origins)
├── auth/
│   ├── options.rs     # RustAuthOptions: sesiones, email/password, rate limit, hooks
│   ├── plugins.rs     # Todos los plugins con APIs `_with` representativas
│   ├── social_providers.rs  # Patrones distintos de setup OAuth social
│   ├── schema.rs      # Schema DB derivado de plugins antes de conectar Postgres
│   └── factory.rs     # AuthStack: ensambla RustAuth (migraciones vía CLI)
├── database/
│   └── postgres.rs    # DeadpoolPostgresAdapter
├── server/
│   ├── router.rs      # Axum: /api/auth + rutas de referencia
│   └── introspection.rs
├── catalog/           # Agrupa endpoints por dominio (core, admin, oauth, …)
└── client/            # Builders HTTP y flujos de ejemplo (sign-up/sign-in)
```

## Plugins habilitados

| Plugin | Notas |
|--------|-------|
| additional-fields | Campo demo `locale` en `user` |
| admin, anonymous, api-key, bearer | — |
| custom-session, device-authorization | — |
| email-otp, magic-link | Callbacks stub (log) |
| have-i-been-pwned | Desactivado (`enabled: false`) |
| jwt, last-login-method, multi-session | — |
| oauth-provider | OAuth 2.1 + MCP metadata, registro dinámico de clientes |
| oauth-proxy, one-tap, one-time-token, open-api | — |
| organization, passkey, phone-number | — |
| captcha, generic-oauth, scim, siwe, sso, stripe, two-factor, username | Stripe/SIWE con valores de desarrollo |

**`access`** es una librería de roles/statements (sin rutas HTTP) — ver `/reference/access`.

## OAuth: social vs generic-oauth (como upstream)

| Flujo | Rutas | Body clave |
|-------|-------|------------|
| **Social catalog** (`social_providers`) | `POST /sign-in/social`, `GET/POST /callback/:id`, `POST /link-social` | `provider` |
| **Generic OAuth** (plugin `generic-oauth`) | `POST /sign-in/oauth2`, `GET /oauth2/callback/:providerId`, `POST /oauth2/link` | `providerId` |

Ambos pueden estar activos a la vez: rutas distintas, sin conflicto.

## Arranque rápido

### Con Postgres (recomendado)

```bash
# Desde la raíz del repo
docker compose -f examples/backend-reference/docker-compose.yml up -d

cd examples/backend-reference
rustauth db migrate --yes

# Or from the repo root (same workflow CI uses on pull requests):
# ./scripts/ensure-example-migrations.sh

DATABASE_URL=postgres://user:password@127.0.0.1:5432/rustauth \
RUST_ENV=development \
cargo run -p rustauth-example-backend-reference
```

`rustauth.toml` en este directorio declara `deadpool-postgres`, los plugins
habilitados y el directorio de migraciones. El servidor **no** aplica migraciones
en runtime; usa `rustauth db migrate` (o tu pipeline de despliegue) antes de
arrancar.

Los tests `tests/plugin_toml_parity.rs` y `tests/cli_schema_parity.rs` exigen
que `[plugins].enabled` coincida con `ENABLED_PLUGIN_IDS` en Rust y que el CLI
pueda planificar el mismo esquema que la app (salvo columnas de
`additional-fields`, que requieren alineación manual). Tras cambiar plugins,
ejecuta `rustauth doctor` y recompila el CLI con los `--features` necesarios.

### Variables de entorno

| Variable | Default | Descripción |
|----------|---------|-------------|
| `RUSTAUTH_SECRET` | dev secret de 32+ chars | Secreto de firma de cookies/tokens |
| `RUSTAUTH_HOST` | `127.0.0.1` | Bind address |
| `RUSTAUTH_PORT` | `3000` | Puerto HTTP |
| `RUSTAUTH_AUTH_BASE_PATH` | `/api/auth` | Prefijo de montaje de la API de auth |
| `RUSTAUTH_BASE_URL` | `http://{host}:{port}{auth_base_path}` | URL pública del auth |
| `DATABASE_URL` | `postgres://user:password@127.0.0.1:5432/rustauth` | Postgres |
| `RUSTAUTH_TRUSTED_ORIGINS` | `http://127.0.0.1:3000` | Orígenes CORS (coma-separados) |
| `RUST_ENV` | `development` (implícito en tests) | `production` endurece cookies/CSRF y oculta rutas `/reference/*`; `development` o `test` permiten defaults de desarrollo |

## Rutas de introspección (sin UI)

Estas rutas son **del ejemplo**, no de RustAuth core. Sirven para inspeccionar
lo que tu app expone:

| Método | Ruta | Contenido |
|--------|------|-----------|
| GET | `/health` | Estado y versión |
| GET | `/reference/runtime` | Config efectiva, plugins, recuento de endpoints |
| GET | `/reference/endpoints` | Lista plana de todos los endpoints |
| GET | `/reference/groups` | Endpoints agrupados por dominio |
| GET | `/reference/openapi.json` | Esquema OpenAPI completo |
| GET | `/reference/plugins` | IDs de plugins y notas |
| GET | `/reference/access` | Ejemplo RBAC (`rustauth_plugins::access`) |
| GET | `/reference/social-patterns` | Patrones distintos de configuración social OAuth |

Copia variables desde [`.env.example`](.env.example).

## Integraciones opcionales

| Capacidad | Crate / feature | Cómo empezar |
|-----------|-----------------|--------------|
| CLI scaffold | `rustauth-cli` | `cargo run -p rustauth-cli -- init` |
| Telemetría | `rustauth/telemetry` | `cargo run -p rustauth-example-backend-reference --features telemetry` + `RUSTAUTH_TELEMETRY=1` |
| i18n | `rustauth/i18n` | `--features i18n` registra el plugin i18n en `auth/plugins.rs` |
| Access control | `rustauth_plugins::access` | `/reference/access` + `auth/access.rs` |

La API pública de auth vive bajo **`/api/auth`** (sign-up, sign-in, passkey,
OAuth, SCIM, organizaciones, etc.).

## Social providers

El módulo `auth/social_providers.rs` registra **un ejemplo por API pública
distinta**:

- **Catálogo estándar** — `providers::github(SocialProviderConfig::new(...))` y similares
- **Builder** — `SocialProviderConfig::builder()` (Spotify)
- **Cognito** — segundo argumento `CognitoPoolConfig`
- **Opciones avanzadas** — Google (`hd`, `access_type`), Apple (`audience`), Microsoft (`tenant_id`), Salesforce (`environment`), WeChat (`lang`), PayPal, Discord, Facebook, GitLab, Dropbox, Zoom, Reddit, Roblox, Twitch, Paybin, …

Credenciales: `{PROVIDER}_CLIENT_ID` / `{PROVIDER}_CLIENT_SECRET` (stubs en dev).
TikTok también acepta `{PROVIDER}_CLIENT_KEY`.

## Montaje Axum con `Arc<RustAuth>`

```rust
use rustauth_axum::{RustAuthAxumExt, RustAuthAxumOptions};

let auth = stack.auth; // Arc<RustAuth>
let auth_routes = auth.mount_routes(RustAuthAxumOptions::default())?;
// `auth` sigue disponible para AppState e introspección
```

## Consumir la API desde tu backend

El módulo `client` muestra el patrón sin acoplarte a un framework HTTP:

```rust
use rustauth_example_backend_reference::client::{
    absolute_uri, register_and_sign_in, sign_up_email, SignUpEmailBody,
};
use rustauth_example_backend_reference::AppConfig;

let config = AppConfig::from_env()?;

// In-process (útil en tests o workers):
let cookie = register_and_sign_in(&auth, &config, "Ada", "ada@example.com", "secret123").await?;

// O construir requests HTTP crudos para reqwest/axum:
let request = sign_up_email(
    &config,
    SignUpEmailBody {
        name: "Ada",
        email: "ada@example.com",
        password: "secret123",
        remember_me: Some(true),
    },
)?;

// URL absoluta para clientes HTTP externos:
let url = absolute_uri(&config, "/get-session");
let _session = reqwest::Client::new().get(url).send().await?;
```

Equivalente con `curl`:

```bash
# Registro
curl -s -X POST http://127.0.0.1:3000/api/auth/sign-up/email \
  -H 'Content-Type: application/json' \
  -d '{"name":"Ada","email":"ada@example.com","password":"password123456"}' \
  -c cookies.txt

# Sesión actual
curl -s http://127.0.0.1:3000/api/auth/get-session -b cookies.txt

# Catálogo agrupado
curl -s http://127.0.0.1:3000/reference/groups | jq .
```

## Integrar en tu propia app

```rust
use rustauth_example_backend_reference::{AppConfig, AuthStack};
use rustauth_example_backend_reference::server::build_router;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stack = AuthStack::from_config(AppConfig::from_env()?).await?;
    let app = build_router(stack)?;

    // Monta `app` en tu router existente o sirve directamente:
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}
```

Copia los módulos `auth/`, `database/` y `config.rs` a tu crate y adapta
plugins/opciones a tu producto.

## Tests

Los tests de humo usan `AuthStack::in_memory()` (sin Docker):

```bash
cargo test -p rustauth-example-backend-reference
```

## Relación con `full-app`

| | `backend-reference` | `full-app` |
|--|---------------------|------------|
| UI / vistas | No | Sí (explorador, DB viewer) |
| Enfoque | Integración backend | Demo interactiva |
| Base de datos | Postgres (Deadpool) | Memory, SQLite, SQLx, Deadpool, MySQL |
| Plugins | Todos (mismos stubs) | Todos (mismos stubs) |
| Catálogo API | JSON agrupado | UI + JSON |
