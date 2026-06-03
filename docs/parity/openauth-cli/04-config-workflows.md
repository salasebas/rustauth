# Configuración y flujos de trabajo

## Modelo de configuración

| | Upstream | OpenAuth |
| --- | --- | --- |
| Archivo principal | `auth.ts`, `better-auth.ts`, rutas en `config-paths.ts` | `openauth.toml` (default `{cwd}/openauth.toml`) |
| Formato | TypeScript ejecutable (`BetterAuthOptions`) | TOML declarativo |
| Carga | `jiti` + `c12` + resolución `tsconfig` paths | `serde` + `toml_edit` para mutaciones |
| Plugins | Objeto/opciones en TS | `[plugins].enabled = ["organization", …]` |
| Base URL / path | Campos en options | `[project] base_url`, `base_path` |
| DB | Función adapter o Kysely en TS | `[database] adapter`, `provider`, `url_env`, `migrations_dir` |
| Secret | `BETTER_AUTH_SECRET` (convención docs) | `OPENAUTH_SECRET` (`[security].secret_env`) |

### Por qué TOML y no `auth.rs` ejecutable

| Razón | Tipo |
| --- | --- |
| OpenAuth es **servidor Rust**; la config de app vive en código Rust (`OpenAuth::builder()`), no en un DSL TS | Decisión de diseño |
| Evitar ejecutar código del usuario en el CLI (seguridad, determinismo CI) | Decisión de diseño |
| `openauth.toml` es contrato estable para **solo** herramientas (migraciones, doctor, plugins list) | Decisión de diseño |
| No hay equivalente a `jiti` en el ecosistema Rust para “importar auth.ts” | Limitación práctica |

## Flujo recomendado OpenAuth

```text
openauth secret --env-line          # opcional, sin config
openauth init [-y]                  # openauth.toml + .env.example
openauth doctor                     # warnings
openauth doctor --production        # gate pre-deploy
openauth db status [--check]        # CI: pendiente?
openauth db generate [-y]           # *.sql
openauth db migrate [-y]            # apply
```

## Flujo upstream (Better Auth + Node)

```text
npx auth@latest secret
npx auth@latest init                # auth.ts, client, deps, .env
npx auth@latest generate [-y]       # prisma/drizzle/kysely file
npx auth@latest migrate [-y]        # solo si adapter.id === "kysely"
# prisma/drizzle: migrate via herramienta ORM, no auth migrate
```

## `init` — qué crea cada uno

| Artefacto | Upstream | OpenAuth |
| --- | --- | --- |
| Server auth config | `auth.ts` generado | `openauth.toml` |
| Client config | `auth-client.ts` / similar | **No** |
| `package.json` deps | Instala `better-auth`, adapters, plugins | **No** |
| `.env` | Crea/merge con secret hash | **No** — solo `.env.example` placeholders |
| Snippet integración | Imports framework-specific | Snippet **Axum** en stdout si framework=axum |
| Detección | `framework.test.ts`, package.json | `cargo_metadata`, deps `openauth-axum`, etc. |
| Social providers | Multiselect + env vars | **No** en CLI v1 |
| Cloudflare / SvelteKit env | `add-cloudflare-modules.ts`, etc. | **N/A** |

## `generate` — artefactos

### Upstream

1. Resuelve adapter (real o mock con `--adapter` + `--dialect`).
2. `generateSchema({ adapter, options })` → generador Prisma/Drizzle/Kysely o `adapter.createSchema`.
3. Escribe **código TypeScript/Prisma** en ruta convencional del ORM.
4. Telemetría según outcome.

### Paridad SQL con Kysely upstream

El generador Kysely de Better Auth **también escribe SQL** (no solo tipos TS):

```text
./better-auth_migrations/<ISO-timestamp>.sql
```

OpenAuth escribe bajo `migrations_dir` (default `migrations/openauth/`) con metadatos en cabecera SQL (`schema_hash`, `plan_hash`, `config_base_path`). Mismo concepto, distinta ruta y naming.

### OpenAuth

1. Carga `CliConfig`; exige `database.provider` para plan real.
2. `target_schema` + `apply_configured_plugins` → `DbSchema`.
3. `plan_with_base` / diff contra estado DB o `--from-empty`.
4. Escribe **SQL** timestamped bajo `migrations_dir` (default `migrations/openauth`).
5. `publish_generate*` con outcome.

| Caso | Upstream | OpenAuth |
| --- | --- | --- |
| Schema al día | `no_changes`, exit 0 | Plan sin statements / mensaje equivalente |
| Archivo existe | prompt overwrite/append | `DuplicateMigration` si mismo `plan_hash` (salvo `--force`) |
| Sin DB URL | N/A en generate (mock posible) | generate puede planear; migrate requiere env |

## `migrate` — quién aplica qué

| Adapter configurado | Upstream `migrate` | OpenAuth `db migrate` |
| --- | --- | --- |
| Kysely built-in | Aplica migraciones Better Auth | — |
| Prisma | Mensaje → usar Prisma migrate | Error `UnsupportedAdapter` |
| Drizzle | Mensaje → usar Drizzle kit | Error `UnsupportedAdapter` |
| sqlx (OpenAuth) | — | Aplica vía `openauth-sqlx` |
| Mongo / otros | Error / telemetry | No soportado en CLI v1 |

## `get-config` (upstream) vs carga TOML (Rust)

Upstream `get-config.test.ts` (**21** casos) cubre:

- Alias TypeScript, `tsconfig` paths, monorepos
- SvelteKit, Cloudflare, múltiples rutas `auth.ts`
- Errores si no hay config

OpenAuth cubre parsing en `tests/config.rs` (**3** casos) + integración init/commands. **Hueco documentado:** no hay tests de rutas `--config` personalizadas exhaustivas (sí un caso en `commands.rs`).

## Comandos sin config (ambos)

| Comando | OpenAuth sin `openauth.toml` | Upstream sin `auth.ts` |
| --- | --- | --- |
| `secret` | Sí | Sí |
| `schema print` | Sí (schema base) | No existe |
| `plugins list` | Sí | No existe |
| `doctor` | Sí (defaults + warnings) | No existe |
| `info` | Sí (defaults) | Falla parcialmente sin config |
| `generate` / `migrate` | Error config requerida | Error “No configuration file found” |

## Variables de entorno

| Variable típica | Upstream | OpenAuth |
| --- | --- | --- |
| Secret | `BETTER_AUTH_SECRET` | `OPENAUTH_SECRET` (configurable vía TOML) |
| DB | `DATABASE_URL` | `DATABASE_URL` (default `url_env`) |
| Telemetría | vars `@better-auth/telemetry` | vars `openauth-telemetry` (ver doc telemetry) |

Ambos cargan `.env` al inicio del proceso CLI sin sobrescribir variables ya definidas (upstream: `dotenv/config`; Rust: `env.rs`).
