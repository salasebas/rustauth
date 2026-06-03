# Comandos — matriz de paridad

Leyenda **Estado**: `Paridad` ≈ mismo rol; `Parcial` mismo nombre/distinto comportamiento; `Extra` solo Rust; `N/A` solo upstream o no aplica server-only.

## Top-level

| Comando upstream | Comando OpenAuth | Estado | Notas |
| --- | --- | --- | --- |
| `init` | `init` | Parcial | Ver [04-config-workflows.md](./04-config-workflows.md) |
| `generate` | `generate` → `db generate` | Parcial | Mismo verbo; salida ORM vs `.sql` |
| `migrate` | `migrate` → `db migrate` | Parcial | Kysely built-in vs sqlx |
| `secret` | `secret` | Parcial | Rust más capacidades |
| `info` | `info` | Parcial | Stack distinto |
| `ai` | — | N/A | Agent Auth setup (TS) |
| `mcp` | — | N/A | Config editores / MCP remoto |
| `upgrade` | — | N/A | Actualiza deps npm `better-auth*` |
| `login` | — | N/A | Infra cloud legacy CLI |
| `logout` | — | N/A | Idem |
| — | `doctor` | Extra | Diagnóstico producción + exit codes |
| — | `db status` | Extra | Plan + `--check` para CI |
| — | `schema print` | Extra | DDL sin conectar DB |
| — | `plugins list\|add\|remove` | Extra | Edición TOML de plugins |
| — | `completions <shell>` | Extra | clap_complete |

## Flags globales

| Flag | Upstream | OpenAuth | Paridad |
| --- | --- | --- | --- |
| `--cwd` | Sí (`-c` en varios comandos) | Sí (`-c` / `--cwd`, default `.`) | Paridad |
| `--config` | Ruta a `auth.ts` | Ruta a `openauth.toml` | Parcial (archivo distinto) |
| `--yes` / `-y` | generate, migrate, init, upgrade | generate, migrate, init, plugins | Parcial |
| `--y` (deprecated) | Sí | No | Upstream only |
| `--json` / `--copy` | `info` (`-j`, `-C`) | `info` (`-j`, `-C` clipboard) | Parcial |
| `--package-manager` | `init` | No | N/A (Cargo) |
| `--production` | No (doctor no existe) | `doctor --production` | Extra |
| `--strict` | No | `doctor --strict` | Extra |

## `secret`

| Aspecto | Upstream | OpenAuth |
| --- | --- | --- |
| Entropía | Comando: `randomBytes(32)` hex; **`init` usa `generateSecretHash()` = 16 bytes hex** | `generate_secret(bytes)` → **URL-safe base64** (mín. 32 bytes efectivos en assess) |
| Salida | Comando: bloque `.env`; **init escribe `.env` real** con `BETTER_AUTH_SECRET` + `BETTER_AUTH_URL` | stdout; `--env-line`; init **`.env.example` + `.env`**; `--seed-secrets` en `.env` nuevo |
| Validación | No en comando `secret` | `--check` / `--check-env`; `--production` (default) / `--dev` |
| Default bytes | 32 (comando) / 16 (`init`) | `--bytes` (default 32) |

**Por qué:** Rust prefiere secretos URL-safe y assessment explícito para `doctor`/CI; no copiamos el formato hex de Better Auth para evitar confusión con `OPENAUTH_SECRET`.

## `generate`

| Aspecto | Upstream | OpenAuth |
| --- | --- | --- |
| Requiere config | `auth.ts` ejecutable | `openauth.toml` |
| Salida | `schema.prisma`, `schema.ts` (Drizzle), tipos Kysely, etc. | `migrations/openauth/<timestamp>_<hash>.sql` (por defecto) |
| `--output` | Archivo ORM | Archivo `.sql` o directorio |
| `--adapter` / `--dialect` | Mock adapter sin config (tests/CI) | No — adapter/provider desde TOML |
| `--from-empty` | No | Sí — plan desde esquema vacío |
| `--force` / `-y` | Confirm overwrite ORM / auto-yes | `--force` duplicado hash; `-y` salta confirmación pre-escritura |
| Sin cambios | Mensaje + telemetry `no_changes` | Plan vacío / sin statements (comportamiento análogo) |
| Telemetría outcomes | `no_changes`, `generated`, `overwritten`, `appended`, `aborted` | `no_changes`, `generated`, `overwritten`, `aborted` |

## `migrate`

| Aspecto | Upstream | OpenAuth |
| --- | --- | --- |
| Adaptador soportado | Solo `kysely` (built-in) | Solo `sqlx` |
| Prisma / Drizzle | Error amigable + `unsupported_adapter` telemetry, exit 0 | Mensaje guiado + telemetría, **exit 0** |
| Confirmación | prompts | `inquire` + `-y` |
| `--dry-run` | No | Sí |
| Aplica | SQL vía `getMigrations` | Statements vía adapters sqlx |

## `init`

| Aspecto | Upstream | OpenAuth |
| --- | --- | --- |
| Genera `auth.ts` | Sí (Babel, plugins, social, DB ORM) | No |
| Genera auth **client** | Sí (`generate-auth-client.ts`) | No — **client-only / TS** |
| Instala deps | `install-dependencies.ts` | No — usuario añade crates |
| Plugins | Flags dinámicos + multiselect | `--plugins` comma-separated → TOML |
| Frameworks | Next, Nuxt, SvelteKit, etc. | Detecta Axum/actix/… vía `cargo_metadata`; default `axum` |
| Env | Crea/actualiza `.env` | Actualiza `.env.example` solo |
| `--force` | Varias confirmaciones | Sobrescribe `openauth.toml` |

## `info`

| Upstream muestra | OpenAuth muestra |
| --- | --- |
| Node, npm/pnpm/yarn/bun, OS, RAM, CPUs | `rustc`, `cargo`, versión crate CLI |
| Frameworks desde `package.json` | Framework desde TOML + detección workspace |
| Config Better Auth (sanitizada) | `doctor` report / JSON redactado |
| `--copy` al portapapeles | No |

## `doctor` (solo OpenAuth)

| Flag | Efecto |
| --- | --- |
| `--production` | Exige secret fuerte, URL DB, etc. |
| `--json` | `DiagnosticReport` |
| `--strict` | exit 1 si hay warnings |
| *(sin flag)* | exit 1 solo en ERROR |

Findings típicos: `config.missing`, `deps.missing_openauth_sqlx`, `security.weak_secret`, `database.url_missing`.

## `db` (solo OpenAuth)

| Subcomando | Descripción |
| --- | --- |
| `status` | Resumen del plan; `--json`; `--check` exit 1 si hay trabajo pendiente |
| `generate` | Igual que top-level `generate` |
| `migrate` | Igual que top-level `migrate` |

## `schema print` (solo OpenAuth)

| Flag | Valores |
| --- | --- |
| `--format` | `sql` (default), `json` |
| `--dialect` | `sqlite`, `postgres`, `mysql`, … |

No requiere `openauth.toml` para inspección base (plugins opcionales si config cargada).

## `plugins` (solo OpenAuth)

| Subcomando | Upstream equivalente |
| --- | --- |
| `list` | Parcialmente documentación / init multiselect |
| `add` / `remove` | Parte de flujo `init` (edición `auth.ts`), no comandos dedicados |

Preserva claves TOML desconocidas (`toml_edit`) — importante para usuarios que extienden el archivo.

## Telemetría (comandos que publican)

| Evento | Upstream | OpenAuth |
| --- | --- | --- |
| `cli_generate` | Sí | Sí (`publish_generate*`) |
| `cli_migrate` | Sí | Sí (`publish_migrate*`) |
| Payload `outcome` | Ver tabla abajo | Ver tabla abajo |

Config snapshot: `get_telemetry_auth_config` en ambos lados (ver doc telemetry).

### Valores `outcome` (desde código fuente)

| `outcome` | `cli_generate` upstream | `cli_generate` Rust | `cli_migrate` upstream | `cli_migrate` Rust |
| --- | --- | --- | --- | --- |
| `no_changes` | Sí | Sí | Sí | Sí |
| `generated` | Sí | Sí | — | — |
| `overwritten` | Sí | — | — | — |
| `appended` | Sí | — | — | — |
| `aborted` | Sí | — | Sí | Sí |
| `migrated` | — | — | Sí | Sí |
| `unsupported_adapter` | — | Sí | Sí (Prisma/Drizzle) | Sí |
| `unsupported_database` | — | Sí | — | Sí |
| `dry_run` | — | — | — | Sí |

Rust publica `unsupported_*` antes de retornar error; upstream Prisma/Drizzle en migrate publican `unsupported_adapter` y salen con **exit 0** (mensaje al usuario) — comportamiento distinto.
