# Tests — matriz upstream ↔ Rust (auditoría archivos)

Fecha: **2026-06-01**. Conteos desde archivos `*.test.ts` y `crates/openauth-cli/tests/*.rs`.

## Resumen numérico

| Métrica | Upstream | OpenAuth |
| --- | --- | --- |
| Archivos test | 14 | 7 |
| `it(` nombrados | 192 | — |
| `testWithTmpDir(` | 92 | — |
| **Total aprox. casos** | **284** | **51** `#[test]` (`tests/regression_gaps.rs` +12) |
| Snapshots en repo | 29 (ORM) | 0 (predicates inline) |
| Tests binario real | `info.test.ts` (7) | Todos `assert_cmd` |
| Tests librería sin bin | Muchos (generateSchema, utilities) | `secret.rs` (2), `config.rs` (3) |

## Upstream — cada archivo y qué prueba

### `test/generate.test.ts` (53 `it`)

Prisma, Drizzle, Kysely: ids numéricos/uuid, enums, MongoDB, `usePlural`, relaciones duplicadas, `--adapter`/`--dialect` sin config, `createSchema` custom, overwrite/append. **No ejecuta el binario `generate`** en la mayoría de casos — llama `generateSchema` directamente.

### `test/generate-all-db.test.ts` (12 `it`)

Drizzle multi-DB + variaciones passkey plugin.

### `test/get-config.test.ts` (21 `it`)

Alias tsconfig, paths relativos, js config, referencias tsconfig, SvelteKit, Cloudflare, errores de alias inválido. **Superficie crítica upstream sin análogo Rust** (no hay `auth.ts`).

### `test/migrate.test.ts` (2 `it`)

| Test | Qué demuestra |
| --- | --- |
| migrate base | `migrateAction` + Kysely in-memory → `auth.api.signUpEmail` funciona |
| migrate + plugin | Tabla custom plugin insertable |

OpenAuth `db.rs` tests migran schema pero **no** invocan API HTTP de registro.

### `test/info.test.ts` (7 `it`) — **E2E binario**

Ejecuta `node ${cliPath} info --json` con proyecto temporal:

1. Sin auth config → system/node/packageManager, `betterAuth.config` null  
2. Sanitiza `secret`, `socialProviders.*`  
3. Detecta frameworks en package.json  
4. Detecta clientes DB en package.json  
5. `--config` ruta custom  
6. Sanitiza plugins en config  
7. Sin package.json → graceful  

Rust: un test `info_json_redacts_sensitive_values` (estructura `DiagnosticReport`, no el JSON de upstream).

### `test/init.test.ts` (17 `testWithTmpDir`)

Existing auth file, cancel, missing package.json, Prisma setup, MongoDB, múltiples env files, package managers.

### `test/install-dependencies.test.ts` (18 tmp)

npm/pnpm/yarn/bun, cwd, errores.

### `test/check-package-managers.test.ts` (9 tmp)

Lockfiles yarn/bun, fallback npm.

### `src/commands/init/utility/plugin.test.ts` (66 `it`)

Codegen de plugins en `auth.ts` / argumentos anidados — **el bloque más grande del paquete**.

### `src/commands/init/utility/framework.test.ts` (35 tmp)

Orden de detección de frameworks.

### `src/commands/init/utility/database.test.ts` (11 `it`)

Strings de adapter Prisma/Drizzle/Kysely/Mongo.

### `src/commands/init/utility/env.test.ts` (6 `it` + 13 tmp)

Missing env vars, comentarios, múltiples archivos.

### `src/commands/init/utility/imports.test.ts` (10 `it`)

Generación de imports TS.

### `src/commands/init/utility/auth-config.test.ts` (4 `it`)

Fragmentos database + appName + baseURL + plugins.

## OpenAuth — cada test por nombre

### `tests/commands.rs` (11)

| Test | Cobertura |
| --- | --- |
| `init_creates_config_and_env_example` | init flags, plugins en TOML, `.env.example` |
| `commands_accept_global_config_path` | `--config config/auth.toml` + schema print |
| `init_refuses_to_overwrite_existing_config` | sin `--force` |
| `cargo_openauth_wrapper_*` | 4 wrappers cargo |
| `better_auth_alias_*` / `open_auth_*` / `compact_betterauth_*` | 8 bins |
| `plugins_list_json_exposes_enriched_contract` | JSON metadata plugins |
| `generate_emits_debug_telemetry_when_enabled` | stderr `cli_generate` + plugins en payload |

### `tests/db.rs` (11 + 2 ignored)

| Test | Cobertura |
| --- | --- |
| `sqlite_status_migrate_and_second_status_are_consistent` | E2E status→migrate→status `--check` |
| `generate_does_not_duplicate_same_plan_hash` | DuplicateMigration |
| `generate_output_treats_sql_path_as_file` | `--output *.sql` |
| `db_status_loads_project_env_file` | `.env` |
| `sqlite_relative_database_url_resolves_against_project_cwd` | sqlite relativo + cwd |
| `schema_print_includes_api_key_plugin_schema` | plugin en schema (duplica parcialmente schema_snapshots) |
| `non_sql_adapter_does_not_attempt_sql_migration_checks` | adapter `memory` + doctor |
| `output_dir_flag_writes_generated_migration_to_directory` | `--output-dir` |
| `postgres_*` / `mysql_*` | **ignored** Docker |
| `adding_schema_plugin_updates_config_and_reports_database_impact` | plugins add |

### `tests/schema_snapshots.rs` (4)

DDL base sqlite/postgres/mysql + plugins api-key/organization.

### `tests/secret.rs` (4)

API `generate_secret`/`assess_secret` + CLI `--env-line` + `--check-env`.

### `tests/config.rs` (3)

Parse TOML, preserve unknown keys, default render.

### `tests/doctor.rs` (2)

`doctor --production` sin secret; `info --json` redacción.

### `tests/quick_start.rs` (3)

Config-free commands (OPE-51); doctor sin hard error; init→`config.loaded`.

## Matriz: área funcional → quién la prueba

| Área | Upstream | OpenAuth | Nota |
| --- | --- | --- | --- |
| ORM schema codegen | 53+12 tests | schema_snapshots (SQL) | Distinto artefacto |
| TS config resolution | 21 tests | 1 test `--config` | Gap esperado (TOML) |
| Init wizard | 17+66+… | 2 init tests | Gap esperado |
| Migrate + auth API | 2 tests signUp | migrate schema only | Rust no prueba HTTP auth |
| Info JSON shape | 7 E2E | 1 partial | JSON distinto por diseño |
| Secret strength | 0 | 4 | Rust superset |
| DB E2E sqlx | vía Kysely/better-sqlite3 | 11 sqlite + 2 docker ignore | Rust más explícito en CLI |
| Telemetry payload | mocks en generate | 1 debug stderr test | Ambos incompletos |
| Package managers | 27 tests | 0 | N/A Cargo |
| Plugin CLI add/remove | en init tests | add sí, remove no | |
| Aliases binarios | 0 | 8 tests | Rust superset |

## Huecos de test documentados (OpenAuth)

Comportamiento implementado en `src/` **sin** test de integración:

- `migrate --dry-run` + telemetry `dry_run`
- `generate --force` tras duplicate hash
- `doctor --strict` (exit 1 con warnings)
- `DbCliError::UnsafeMigration` cuando hay warnings
- `plugins remove` + mensaje “no destructive migrations”
- `schema print --format json`
- `completions`
- `init --force` overwrite confirmado
- `secret --check` éxito / warning path
- unsupported_adapter telemetry en **migrate** (solo generate testeado)
- Salida humana de `info` (no JSON)

## Huecos upstream (referencia)

- Comando `secret` sin tests
- Comandos cloud/AI/MCP/upgrade sin tests
- SQL file naming Kysely vs snapshots ORM

## Comandos de verificación

```bash
# Rust — lista tests
cargo nextest run -p openauth-cli -- --list-tests

# Upstream — desde packages/cli
cd reference/upstream-src/1.6.9/repository/packages/cli && npm test
```
