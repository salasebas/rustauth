# Inventario de fuentes (auditoría código + tests)

Inventario derivado de **lectura directa** de `packages/cli/` (upstream v1.6.9) y `crates/openauth-cli/`, no de READMEs.

## Upstream — árbol `packages/cli/`

| Ruta | Rol |
| --- | --- |
| `src/index.ts` | Commander root `better-auth`, registra 11 comandos, `dotenv/config` |
| `src/api.ts` | Re-export programático: `generateSchema`, generadores ORM, tipos |
| `src/commands/init/index.ts` | `initAction` (~1.6k líneas): wizard completo |
| `src/commands/init/generate-auth.ts` | Codegen servidor `auth.ts` |
| `src/commands/init/generate-auth-client.ts` | Codegen cliente |
| `src/commands/init/configs/*.ts` | Frameworks (12), DB adapters (Prisma/Drizzle/Kysely/Mongo), 34 social providers, ~31 plugins init |
| `src/commands/init/utility/*.ts` | env, imports, framework detect, plugin codegen, prompts |
| `src/commands/generate.ts` | `generateAction` + mock adapter `--adapter`/`--dialect` |
| `src/commands/migrate.ts` | `migrateAction` exportado; solo Kysely; telemetry unsupported |
| `src/commands/secret.ts` | Solo imprime hex 32 bytes + hint `.env` |
| `src/commands/info.ts` | JSON: system, node, packageManager, frameworks, databases, betterAuth |
| `src/commands/ai.ts` | Agent Auth (~780 líneas), sin flags CLI |
| `src/commands/mcp.ts` | MCP Cursor/Claude/OpenCode/manual |
| `src/commands/upgrade.ts` | Semver + install npm |
| `src/commands/login.ts` | Delega `npx @better-auth/cli@latest` |
| `src/generators/{prisma,drizzle,kysely,index}.ts` | Salida ORM; **Kysely también emite SQL** |
| `src/utils/get-config.ts` | jiti + c12 + tsconfig paths + Cloudflare/SvelteKit shims |
| `src/utils/config-paths.ts` | Decenas de rutas `auth.ts` / `auth-client.ts` |
| `src/utils/{install-dependencies,check-package-managers,...}.ts` | npm ecosystem |

### Hallazgo: Kysely `generate` también produce SQL

```14:17:reference/upstream-src/1.6.9/repository/packages/cli/src/generators/kysely.ts
		fileName:
			file ||
			`./better-auth_migrations/${new Date()
				.toISOString()
				.replace(/:/g, "-")}.sql`,
```

OpenAuth usa por defecto `migrations/openauth/` y nombres `YYYYMMDDhhmmss_{provider}_{hash}.sql` con cabecera `-- plan_hash:` / `-- schema_hash:`.

**Paridad parcial real:** ambos pueden emitir SQL; upstream además mantiene tipos Kysely en TS y carpetas distintas.

## OpenAuth — árbol `crates/openauth-cli/`

| Ruta | Visibilidad | Rol |
| --- | --- | --- |
| `src/app.rs` | `pub` | Clap, dispatch, `AppContext`, `AppError::SilentExit` |
| `src/config.rs` | `pub` | TOML + `add/remove_plugin_to_document` |
| `src/db.rs` | `pub` | plan/migrate/write SQL, sqlite path normalize |
| `src/schema.rs` | `pub` | `target_schema`, dialectos |
| `src/diagnostics.rs` | `pub` | `doctor()`, códigos de finding |
| `src/secret.rs` | `pub` | generate + assess |
| `src/plugins.rs` | `pub` | `official_plugins`, `schema_plugin` (11 plugins), snippets (8) |
| `src/workspace.rs` | `pub` | `cargo_metadata`, detect axum/sqlx/… |
| `src/telemetry.rs` | `pub(crate)` | eventos CLI |
| `src/commands/*.rs` | handlers | init, doctor, info, secret, db, schema, plugins, completions |
| `src/{env,paths,prompt,output}.rs` | `pub(crate)` | `.env` sin override, rutas, inquire |

**API librería Rust:** varios módulos son `pub` (`config`, `db`, `diagnostics`, …) pero el producto publicado es **binario**; no hay equivalente npm `auth/api`.

## Plugins: tres niveles en OpenAuth + init upstream

| Nivel | Cantidad | Dónde |
| --- | --- | --- |
| `plugins list` | **27** IDs | `openauth_plugins::PLUGIN_IDS` |
| Schema en migraciones | **11** con tablas | `schema_plugin()` en `plugins.rs` |
| Snippet Rust impreso en `plugins add` | **8** | `rust_snippet()` |
| Init upstream `temp-plugins` | **30** plugins, **81** flags CLI | `temp-plugins.config.ts` |

Plugins con schema CLI: `admin`, `anonymous`, `api-key`, `device-authorization`, `jwt`, `mcp`, `organization`, `phone-number`, `siwe`, `two-factor`, `username`.

**Solo en init upstream:** `passkey`, `oidc`, `scim`, `sso`, `stripe`, `i18n`.  
**Solo en `PLUGIN_IDS` Rust:** `access`, `additional-fields`.  
Detalle: [08-edge-cases.md](./08-edge-cases.md#plugins-init-vs-plugins-list).

## Frameworks / DB (init)

| | Upstream `init` | OpenAuth `init` |
| --- | --- | --- |
| Frameworks | 12 (Next, Nuxt, SvelteKit, Astro, Hono, …) + route handlers | Default `axum`; detecta axum/actix/rocket/poem/warp vía Cargo |
| DB adapters | 20+ variantes Prisma/Drizzle/Kysely/Mongo | `sqlx` + provider sqlite/postgres/mysql |
| Social OAuth | 34 proveedores en wizard | No |
| Instalar deps | Sí | No |

## Códigos `doctor` (OpenAuth)

| Código | Severidad típica |
| --- | --- |
| `config.loaded` / `config.missing` | info / warn |
| `workspace.root` / `workspace.metadata` | info / warn |
| `framework.detected` | info |
| `database.adapter_mismatch` | error |
| `database.adapter_provider_mismatch` | warn |
| `database.multiple_adapters` | warn |
| `security.secret` | info–error |
| `security.base_url_https` | error (production) |
| `security.localhost` | warn (production) |
| `database.migrations_unsupported` | warn |
| `database.url` | warn/error |
| `database.schema_type_mismatch` | error |
| `database.pending_schema` | warn |
| `database.schema` | info |
| `database.connection` | error |

Upstream no tiene comando `doctor`; parte de esto se solapa con lectura manual de `info` + runtime errors.

## Telemetría — outcomes en código

| Evento | Upstream (`generate.ts` / `migrate.ts`) | OpenAuth (`commands/db.rs`) |
| --- | --- | --- |
| `cli_generate` | `no_changes`, `generated`, `overwritten`, `appended`, `aborted` | `no_changes`, `generated`, `unsupported_adapter`, `unsupported_database` |
| `cli_migrate` | `no_changes`, `aborted`, `migrated`, `unsupported_adapter` | `no_changes`, `dry_run`, `aborted`, `migrated`, `unsupported_adapter`, `unsupported_database` |

**Solo Rust:** `dry_run`, `unsupported_database` en generate. **Solo upstream:** `overwritten`, `appended` (confirmación archivo ORM).

## Exportaciones upstream usadas en tests

| Símbolo | Archivo | Uso en tests |
| --- | --- | --- |
| `migrateAction` | `migrate.ts` | `test/migrate.test.ts` — migra + `signUpEmail` / INSERT plugin |
| `getConfig` | `get-config.ts` | Mock en migrate; 21 casos resolución TS |
| `initAction` | `init/index.ts` | `test/init.test.ts` (memfs) |
| `generateSchema` | `generators` | `test/generate.test.ts` (53 casos) |

OpenAuth no exporta `run_from` para tests; usa **`assert_cmd`** contra bins compilados + tests unitarios de `openauth_cli::secret` / `config`.

## Snapshots upstream (`test/__snapshots__/`)

**29** archivos de texto, casi todos **esquemas Drizzle/Prisma** (enum, uuid, passkey, plural, etc.). No hay snapshots de SQL Kysely en esa carpeta (el SQL Kysely se valida vía contenido en tests de generate).

## Comportamiento sin tests automatizados

### Upstream CLI

| Superficie | Tests |
| --- | --- |
| `secret` comando | **Ninguno** |
| `ai`, `mcp`, `upgrade`, `login`, `logout` | **Ninguno** |
| Binario E2E real | `info.test.ts` (7) ejecuta `node dist` vía `cliPath` |
| `generate`/`migrate` E2E bin | Mayormente unit con mocks |

### OpenAuth CLI

| Superficie | Tests |
| --- | --- |
| `migrate --dry-run` | **No** |
| `generate --force` | **No** |
| `doctor --strict` | **No** |
| `UnsafeMigration` (warnings en plan) | **No** |
| `plugins remove` | **No** |
| `schema print --format json` | **No** |
| `completions` | **No** |
| `init --force` overwrite | **No** (solo refuse sin `--force`) |
| `info` modo humano | **No** (solo `--json` redaction) |
| Postgres/MySQL | 2× `#[ignore]` Docker |
