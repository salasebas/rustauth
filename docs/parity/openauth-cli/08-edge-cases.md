# Casos límite, exit codes y diferencias sutiles

Hallazgos de una **tercera pasada** leyendo implementaciones completas (`migrate.ts`, `init/index.ts`, `info.ts`, `env.ts`, `index.ts`) — no inferidos de README.

## Exit codes y flujos “silenciosos” (upstream)

| Situación | Upstream | OpenAuth |
| --- | --- | --- |
| `generate` / `migrate` sin config | `console.error` + **`return`** (sin `process.exit`) → suele ser **exit 0** | `AppError::Message` → **exit 1** |
| `migrate` cancelado por usuario | `process.exit(0)` | `Ok(())` → **exit 0** |
| `generate` cancelado / abortado | `process.exit(1)` | confirmación + `SilentExit(1)` + telemetría `aborted` |
| `migrate` Prisma / Drizzle | mensaje + telemetry + **`process.exit(0)`** | mensaje + telemetry + **`SilentExit(0)`** (alineado) |
| `migrate` otro adapter no Kysely | exit **1** | exit **1** |
| `doctor` / `db status --check` con trabajo pendiente | N/A | `SilentExit { code: 1 }` |
| SIGINT / SIGTERM | `process.exit(0)` en `index.ts` | Sin handler dedicado (comportamiento proceso Rust) |

**Implicación CI:** un pipeline que espere exit ≠ 0 cuando falta `auth.ts` en upstream **no** lo obtendrá con `npx auth migrate` / `generate`; con `openauth` sí.

## Secretos: tres generadores distintos en upstream

| Origen | Bytes aleatorios | Formato | Variable env |
| --- | --- | --- | --- |
| Comando `secret` | 32 | hex (64 caracteres) | Mensaje sugiere `BETTER_AUTH_SECRET=` |
| `init` → `generateSecretHash()` | **16** | hex (32 caracteres) | Escribe `.env` real |
| OpenAuth `secret` | `--bytes` (default 32) | URL-safe base64 | `OPENAUTH_SECRET` / `--env-line` |

```27:29:reference/upstream-src/1.6.9/repository/packages/cli/src/utils/helper.ts
export const generateSecretHash = () => {
	return Crypto.randomBytes(16).toString("hex");
};
```

OpenAuth `secret --check` / `--check-env` usan modo producción por defecto; **`--dev`** desactiva el modo estricto (equivalente a comprobar secretos de desarrollo).

## Variables de entorno al arranque

| | Upstream | OpenAuth |
| --- | --- | --- |
| Carga automática | `import "dotenv/config"` → típicamente **solo `.env`** | `env.rs`: **`.env` y `.env.local`**, sin pisar vars ya definidas |
| Init escribe | **`.env`** nuevo (`createEnvFile`) o actualiza `.env*` existentes (excepto `.env.example`) | **`.env.example`** + **`.env`** si no existe; merge de keys en ambos; **`--seed-secrets`** escribe secreto real solo en `.env` nuevo |
| Vars en init | `BETTER_AUTH_SECRET`, **`BETTER_AUTH_URL`** | `OPENAUTH_SECRET` (nombre configurable), `DATABASE_URL` placeholder |
| Detección provider en init | vía wizard DB | `init` puede inferir provider desde `DATABASE_URL` en entorno |

## `init`: schema generation embebido (upstream)

Durante el wizard, si el ORM es Drizzle o Prisma, `init` **genera schema en el mismo flujo** (no solo deja preparado `generate`):

- Drizzle → `auth-schema.ts` junto al `auth.ts` generado  
- Prisma → `prisma/schema.prisma`  
- Usa `createMinimalConfig` + mock adapter + `generateDrizzleSchema` / `generatePrismaSchema`

OpenAuth `init` **no** genera SQL ni DDL; TOML + env + snippet Axum (sin Prisma/Drizzle embebido).

## Rutas por defecto de artefactos (`generate`)

| Adapter | Archivo por defecto (upstream) |
| --- | --- |
| Prisma | `./prisma/schema.prisma` |
| Drizzle | `./auth-schema.ts` |
| Kysely | `./better-auth_migrations/<ISO-timestamp>.sql` |

OpenAuth: `{migrations_dir}/{timestamp}_{provider}_{hash}.sql` con cabecera SQL documentada.

## `generate` ORM: overwrite / append

`SchemaGeneratorResult` incluye `overwrite` y `append`. Prisma/Drizzle devuelven `overwrite: true` si el archivo ya existía y cambió. El CLI pregunta overwrite vs append y telemetría distingue `overwritten` / `appended`.

OpenAuth: deduplicación por **`plan_hash`** en comentarios SQL; `--force` para ignorar; **no** append.

## `info`: sanitización extra (upstream)

Además de redactar claves sensibles, `sanitizeBetterAuthConfig`:

- Callbacks `sendResetPassword` / `sendVerificationEmail` → `"[Function]"`  
- Plugins que son funciones → `"[Plugin Function]"`  
- Plugins objeto → `{ name, config }` redactado  

Rust `info` reutiliza `DiagnosticReport` (findings + `RedactedConfig`); **no** expone `system`/`node`/`packageManager` ni versión de `better-auth` desde npm.

**`info --copy`**: implementado (pbcopy / xclip / xsel / clip). JSON sigue siendo forma OpenAuth (`InfoReport`), no el dump sanitizado de `better-auth`.

## Carga de config TS: errores especiales (upstream)

`get-config.ts` maneja explícitamente:

- Import **`server-only`** → mensaje para quitarlo temporalmente  
- Alias **tsconfig** (incl. referencias, wildcards — ver changelog 1.6.3)  
- Shims **Cloudflare** / **SvelteKit** (`add-cloudflare-modules.ts`, `add-svelte-kit-env-modules.ts`)

OpenAuth: parse TOML estático; sin `server-only` ni resolución TS.

## Plugins: init vs `plugins list`

| Conjunto | Cantidad | Notas |
| --- | --- | --- |
| `temp-plugins.config` (init) | **30** plugins | **81** flags CLI dinámicos (`--two-factor-issuer`, …) |
| `PLUGIN_IDS` (`plugins list`) | **27** | kebab-case servidor OpenAuth |
| `schema_plugin()` en CLI | **11** | Migraciones SQL |
| `rust_snippet()` | **8** | Texto tras `plugins add` |

### En init upstream pero **no** en `PLUGIN_IDS` Rust

`passkey`, `oidc`, `scim`, `sso`, `stripe`, `i18n` (nombres camelCase en TS).

### En `PLUGIN_IDS` pero **no** en init `temp-plugins`

`access`, `additional-fields` (IDs upstream distintos / solo servidor Rust).

### Convención de nombres

| Upstream init | OpenAuth CLI |
| --- | --- |
| `twoFactor`, `apiKey` | `two-factor`, `api-key` |

## Comandos / infra adicionales (confirmado en código)

| Comando | Detalle no obvio |
| --- | --- |
| `upgrade` | Solo paquetes `better-auth` o `@better-auth/*`; consulta registry npm; `installDependencies` con PM detectado |
| `login` / `logout` | `spawn` shell `npx @better-auth/cli@latest …` — paquete legacy fuera del monorepo |
| `mcp` | URL remota fija `https://mcp.better-auth.com/mcp` |
| `ai` | Sin subcomandos; setup Agent Auth interactivo largo |

## OpenAuth: comportamientos sin test (reconfirmado)

- `plugins add` **lee** `openauth.toml` existente (falla si no hay `init` previo)  
- `migrate` con warnings en plan → `DbCliError::UnsafeMigration` (no apply)  
- `generate` con `--output` sin `.sql` → warning y trata como directorio  
- `sqlite` relativo resuelve contra `--cwd` (testeado); upstream Kysely depende de `process.cwd()` en paths Prisma/Drizzle  

## Build / test harness upstream

| Pieza | Uso |
| --- | --- |
| `tsdown.config.ts` | Dos builds: `index.ts` (CLI), `api.ts` (tipos + generadores exportados) |
| `vitest` | `clearMocks` + `restoreMocks` |
| `test/utils.ts` | Resuelve `cliPath` → `dist/index.mjs` para E2E `info` |
| `test/test-utils.ts` | `memfs` + `testWithTmpDir` para init/install/PM |

OpenAuth: filesystem real (`tempfile`), bins via `assert_cmd::cargo_bin`.
