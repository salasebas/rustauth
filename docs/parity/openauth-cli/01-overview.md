# Visión general — `openauth-cli`

## Qué es cada CLI

| | Upstream (`packages/cli`) | OpenAuth (`openauth-cli`) |
| --- | --- | --- |
| **Propósito** | Herramienta Node para proyectos **Better Auth + TS**: scaffold, generar esquemas ORM, migrar con Kysely integrado, utilidades de ecosistema | Herramienta **Rust/Cargo** para proyectos **OpenAuth**: `openauth.toml`, SQL migrations vía sqlx, diagnóstico de workspace Cargo |
| **Config** | Ejecuta / importa `auth.ts` (`BetterAuthOptions`) | Lee `openauth.toml` (no ejecuta código de app) |
| **Generate** | Archivos Prisma / Drizzle / Kysely (+ `createSchema` custom) | Archivos **`.sql`** (plan de migración OpenAuth) |
| **Migrate** | Solo adaptador **Kysely** built-in | Solo adaptador **`sqlx`** (sqlite, postgres, mysql) |
| **Init** | Wizard grande: auth server + **auth client**, deps npm, env, frameworks web | Escribe TOML + `.env.example` + snippet Axum opcional |
| **Tests del paquete** | ~284 Vitest (carga de config + codegen TS dominante) | 38 integración `assert_cmd` + API `secret` |

## Mapa de código (alto nivel)

```text
Upstream packages/cli/
  src/index.ts              → Commander, 11 comandos top-level
  src/commands/             → init, generate, migrate, secret, info, ai, mcp, upgrade, login, logout
  src/generators/           → prisma | drizzle | kysely
  src/utils/get-config.ts   → jiti + c12 + auth.ts
  test/*.test.ts            → mayoría de cobertura

OpenAuth crates/openauth-cli/
  src/app.rs                → Clap + dispatch Tokio
  src/commands/             → init, doctor, info, secret, db, schema, plugins, completions
  src/config.rs             → openauth.toml
  src/db.rs                 → plan/migrate → openauth-sqlx
  src/schema.rs             → DDL desde openauth-core
  src/diagnostics.rs        → doctor (no existe en upstream CLI)
  tests/*.rs                → binarios reales, SQLite (+ Docker PG/MySQL opcional)
```

## Estado resumido de paridad

| Área | Paridad funcional | Nota |
| --- | --- | --- |
| `secret` | **Media** | Ambos generan secreto; upstream solo hex + mensaje `.env`; Rust URL-safe base64, `--check`, `--check-env`, `--env-line` |
| `init` | **Baja** (mismo nombre, distinto alcance) | Upstream = producto completo TS; Rust = config mínima servidor |
| `generate` | **Media-baja** | ORM (Prisma/Drizzle) + SQL Kysely en `better-auth_migrations/` vs SQL OpenAuth en `migrations/openauth/`; telemetría con outcomes distintos |
| `migrate` | **Media-baja** | Ambos aplican migraciones en DB “nativa”; ORM vs sqlx; upstream rechaza Prisma/Drizzle con mensaje + telemetry |
| `info` | **Media** | Upstream: Node/OS/npm/frameworks; Rust: rustc/cargo/workspace OpenAuth |
| `login` / `logout` | **N/A** | Infra Better Auth (delega `@better-auth/cli`) — sin equivalente Rust |
| `ai`, `mcp`, `upgrade` | **N/A** | TS / IDE / npm — fuera de alcance server-only |
| `doctor` | **Extra Rust** | No hay comando upstream homónimo |
| `db status`, `schema print`, `plugins` | **Extra Rust** | Workflow explícito servidor + TOML |
| `completions` | **Extra Rust** | clap_complete |
| Binarios alias + `cargo-*` | **Parcial** | Rust: 8 bins; upstream: 2 (`auth`, `better-auth`) |
| API `auth/api` | **N/A upstream en Rust** | Generadores ORM exportados solo en npm |
| Tests del paquete CLI | **Diferente forma** | Upstream mucho más tests de **codegen TS**; Rust más **E2E CLI + SQL snapshots** |

## Comandos: solo upstream

| Comando | Motivo de no paridad en Rust |
| --- | --- |
| `ai` | Setup Agent Auth / MCP / skills — ecosistema TS y paquetes `@auth/agent-cli` |
| `mcp` | Escribe config MCP en Cursor/Claude/OpenCode |
| `upgrade` | `semver` + `package.json` + install npm/pnpm/yarn/bun |
| `login` / `logout` | Cloud Better Auth Infrastructure vía `npx @better-auth/cli@latest` |

## Comandos: solo OpenAuth

| Comando | Motivo |
| --- | --- |
| `doctor` | Readiness producción (secret, adapter, URL, deps Cargo) sin ejecutar `auth.ts` |
| `db status` | Plan pendiente + exit code `--check` (CI) |
| `schema print` | Inspeccionar DDL objetivo (sql/json) sin DB |
| `plugins list|add|remove` | Gestionar `plugins.enabled` en TOML preservando claves desconocidas |
| `completions` | Shell completions nativas Clap |
| Top-level `generate` / `migrate` | Alias de `db generate` / `db migrate` (ergonomía Better Auth) |

## Conclusión ejecutiva

El crate **`openauth-cli`** no pretende ser un port del wizard TypeScript de Better Auth. Comparte **nombres y flujo mental** (`init` → `generate` → `migrate`, `secret`, `info`, telemetría) pero el **artefacto de generate** y el **modelo de configuración** son fundamentalmente distintos por diseño (**servidor Rust + sqlx + TOML** vs **monorepo Node + ORM + auth.ts**).

La paridad útil para mantenedores está en: **migraciones SQL reales**, **eventos de telemetría**, **flags globales `--cwd` / `--config`**, y **aliases de binario** `better-auth` / `cargo-better-auth`.
