# Mapeo de paquetes y superficie publicada

## Identidad publicada

| | Upstream | OpenAuth |
| --- | --- | --- |
| Nombre npm/cargo | `auth` | `openauth-cli` |
| Versión pin | `1.6.9` (monorepo) | `0.0.6` (workspace, ver `Cargo.toml` raíz) |
| Bins | `auth`, `better-auth` → `dist/index.mjs` | `openauth`, `open-auth`, `better-auth`, `betterauth` + 4× `cargo-*` |
| Entry CLI | `packages/cli/src/index.ts` | `src/app.rs` + `src/bin/*.rs` |
| Framework CLI | Commander 12 | Clap 4 + `clap_complete` |
| Runtime async | Node async/await | Tokio (`block_on` en `app.rs`) |

## Dependencias: quién hace el trabajo

| Capacidad | Upstream depende de | OpenAuth depende de |
| --- | --- | --- |
| Opciones auth / schema core | `better-auth`, `@better-auth/core` | `openauth-core` |
| Aplicar migraciones | `better-auth/db/migration` + Kysely adapter | `openauth-sqlx` (`SqliteAdapter`, `PostgresAdapter`, `MySqlAdapter`) |
| Plugins en schema | Plugins en `BetterAuthOptions` (runtime TS) | `openauth-plugins` + IDs en TOML |
| Telemetría | `@better-auth/telemetry` | `openauth-telemetry` |
| Cargar config app | `c12`, `jiti`, `get-tsconfig`, Babel (init) | `toml_edit` + serde (`openauth.toml`) |
| Inspección proyecto | `package.json`, `detectPackageManager` | `cargo_metadata`, `workspace.rs` |
| ORM codegen | `@mrleebo/prisma-ast`, generadores drizzle/kysely/prisma | **No** — SQL desde core |
| UX terminal | chalk, prompts, yocto-spinner, @clack/prompts | `inquire`, stdout simple |
| Env | `dotenv` al inicio | `env.rs`: `.env` / `.env.local` sin pisar vars existentes |

### Crate `openauth` en `Cargo.toml`

`openauth` está declarado como dependencia pero **no se importa** en el código del CLI (los snippets en `plugins.rs` mencionan `openauth::plugins::…` como texto para el usuario). Decisión pendiente: quitar dep o usarlo para versión/snippet real.

## API programática (solo upstream)

Upstream exporta subpath npm:

```text
auth/api → generateSchema, generatePrismaSchema, generateDrizzleSchema, generateKyselySchema, adapters, tipos
```

Archivo: `packages/cli/src/api.ts` → build `dist/api.mjs`.

**OpenAuth:** no hay equivalente `openauth-cli` como librería; toda la superficie es **binario**. La lógica reutilizable vive en `openauth-core` / `openauth-sqlx`.

## Archivos fuente comparables

| Concern | Upstream | OpenAuth |
| --- | --- | --- |
| Bootstrap CLI | `src/index.ts` | `src/app.rs` |
| Init | `src/commands/init/**` (~1.7k líneas TS) | `src/commands/init.rs` + `config.rs` |
| Generate | `src/commands/generate.ts` + `src/generators/*` | `src/commands/db.rs` + `src/db.rs` |
| Migrate | `src/commands/migrate.ts` | `src/commands/db.rs` + `src/db.rs` |
| Secret | `src/commands/secret.ts` | `src/secret.rs` + `src/commands/secret.rs` |
| Info | `src/commands/info.ts` | `src/commands/info.rs` (reusa `diagnostics::doctor`) |
| Config discovery | `src/utils/get-config.ts`, `config-paths.ts` | `src/paths.rs`, `src/config.rs` |
| Package manager | `check-package-managers.ts`, `install-dependencies.ts` | **No** (Cargo-only) |
| Doctor / readiness | *(no comando)* | `src/diagnostics.rs`, `src/commands/doctor.rs` |
| Plugins CLI | Solo vía `init` (flags dinámicos por plugin) | `src/plugins.rs`, `src/commands/plugins.rs` |
| Schema inspect | *(no comando)* | `src/schema.rs`, `src/commands/schema.rs` |
| Telemetry wiring | inline en generate/migrate | `src/telemetry.rs` |

## Integración workspace Rust

| Crate | Uso en CLI |
| --- | --- |
| `openauth-core` | `DbSchema`, planes de migración, dialectos, `OpenAuthOptions` para telemetry |
| `openauth-sqlx` | Plan + apply contra DB real |
| `openauth-plugins` | `PLUGIN_IDS`, instanciar plugins para schema |
| `openauth-telemetry` | `cli_generate`, `cli_migrate` |

Ningún otro miembro del workspace depende de `openauth-cli` (hoja del grafo).

## Legacy `@better-auth/cli`

No está en el monorepo 1.6.9. Los comandos `login` y `logout` del CLI moderno ejecutan:

```text
npx @better-auth/cli@latest login|logout
```

OpenAuth no implementa ni delega esto — **decisión: sin infra cloud equivalente**.
