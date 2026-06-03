# Diferencias de diseño y límites

Tabla de referencia: **por qué** OpenAuth diverge del CLI upstream, clasificado para mantenimiento de paridad.

## Clasificación

| Código | Significado |
| --- | --- |
| **D** | Decisión de diseño OpenAuth (servidor Rust, sin magia TS) |
| **T** | Limitación ecosistema TypeScript / Node (upstream-only) |
| **C** | Cliente / frontend / DX IDE — fuera de alcance server-only |
| **I** | Infra / producto Better Auth commercial |
| **P** | Paridad parcial planificada o en progreso |

## Tabla principal

| Tema | Upstream | OpenAuth | Código | Explicación |
| --- | --- | --- | --- | --- |
| Config ejecutable | `auth.ts` | `openauth.toml` | **D** | CLI no ejecuta código de aplicación |
| Generate output | Prisma/Drizzle/Kysely TS | SQL migrations | **D** | Stack Rust usa sqlx; ORM TS no aplica |
| Migrate target | Kysely only | sqlx only | **D** | Alineado con adaptador “nativo” de cada stack |
| SQL migration files | Kysely `generate` → `better-auth_migrations/*.sql` | `db generate` → `migrations/openauth/*.sql` | **P** | Mismo tipo de artefacto; carpetas y headers distintos |
| Prisma migrate unsupported exit code | exit 0 + mensaje | error CLI | **P** | UX distinta al rechazar adapter |
| Init scope | Full stack scaffold | Config + env example | **D** + **C** | Sin auth client ni framework web codegen |
| `auth/api` export | Sí | No | **D** | Consumidores Rust usan crates, no npm API |
| Binarios | 2 | 8 (+ cargo subcommands) | **D** | Familiaridad Better Auth + integración `cargo install` |
| Secret encoding | hex | URL-safe base64 | **D** | Idiomático para cookies/API keys Rust docs |
| `doctor` | — | Sí | **D** | Reemplaza parte de “info + validación manual” en Rust |
| `db status` | — | Sí | **D** | CI-friendly; upstream infiere en generate |
| `schema print` | — | Sí | **D** | Debug DDL sin DB (útil en crates/plugins) |
| `plugins` CLI | En init | Comandos dedicados | **D** | TOML editable sin regenerar TS |
| `completions` | — | Sí | **D** | Estándar en CLIs Rust/clap |
| `ai` Agent Auth | Sí | — | **T** + **C** | Paquetes `@auth/agent-cli`, protocolo web |
| `mcp` editor setup | Sí | — | **C** | Configura Cursor/Claude/OpenCode |
| `upgrade` npm | Sí | — | **T** | Versiones en `Cargo.toml`, no `package.json` |
| `login` / `logout` | Sí | — | **I** | Better Auth Infrastructure cloud |
| Package managers | npm/pnpm/yarn/bun | Cargo | **T** | Detección vía `cargo_metadata` |
| Babel / Prettier codegen | Sí | — | **T** | Init TS no portado |
| Prisma AST | Sí | — | **T** | Sin Prisma en servidor Rust |
| Framework matrix | Next, Nuxt, … | Axum-first + detect | **D** + **P** | Más frameworks Rust pueden añadirse sin paridad 1:1 con Next |
| Social providers en init | Sí | No | **P** | Configuración en código Rust del usuario |
| `--adapter` mock en generate | Sí | No | **P** | Útil para tests upstream; Rust usa snapshots `schema print` |
| `info --copy` | Sí | No | **P** | Baja prioridad terminal |
| Telemetría outcomes | Granular ORM | Menos variantes | **P** | Misma familia de eventos; strings no idénticos |
| Legacy `@better-auth/cli` | Delegación | — | **I** | Sin producto equivalente |
| Dependencia `openauth` en CLI | N/A | Declarada sin uso | **P** | Limpieza pendiente en Cargo.toml |

## Server-only: qué ignorar al medir paridad

No se consideran “huecos” de implementación:

- Generación de **auth client** TypeScript / React / Vue
- Instalación de paquetes npm y scripts `package.json`
- Integración SvelteKit / Cloudflare Workers modules
- Comandos **MCP** y **AI** orientados a editores
- **Upgrade** semántico de versiones npm
- Cualquier flujo que requiera **Node** en runtime del proyecto del usuario

## Qué sí es paridad objetivo

| Área | Objetivo |
| --- | --- |
| Flujo `init` → `generate` → `migrate` | Misma historia de usuario para operador servidor |
| Eventos `cli_generate` / `cli_migrate` | Payload compatible con telemetry (ver `openauth-telemetry`) |
| Flags `--cwd`, `--config`, `-y` | Ergonomía CLI |
| Aliases `better-auth` | Migración mental desde docs Better Auth |
| Secret generation | Entropía ≥256 bits; documentar mapping env var |
| Mensajes adapter no soportado en migrate | Claridad Prisma/Drizzle vs sqlx (mensajes distintos pero rol igual) |

## Riesgos de confusión para usuarios

| Expectativa Better Auth | Realidad OpenAuth |
| --- | --- |
| `npx auth generate` crea `schema.prisma` | Crea `.sql` en `migrations/openauth/` |
| `npx auth migrate` con Prisma | Usar `openauth db generate` + `openauth db migrate` con adapter `sqlx` |
| Editar plugins en `auth.ts` | `openauth plugins add` o editar TOML |
| `BETTER_AUTH_SECRET` | `OPENAUTH_SECRET` (nombre distinto por diseño) |

Documentar esto en README del crate y en guías de migración desde Better Auth (fuera de este doc).

## Posibles extensiones futuras (no compromiso)

| Extensión | Tipo |
| --- | --- |
| `openauth upgrade` vía `cargo edit` / aviso crates.io | **P** |
| Más adapters CLI (`tokio-postgres` deadpool) | **P** |
| Mock `--adapter` para CI sin DB | **P** |
| Alinear strings telemetry outcome con upstream | **P** |
| Quitar o usar dep `openauth` en CLI | Mantenimiento |
