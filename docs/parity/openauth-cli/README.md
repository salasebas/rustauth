# Paridad: `openauth-cli` ↔ `packages/cli` (npm `auth`)

Documentación de paridad entre el crate Rust **`openauth-cli`** y el CLI upstream de Better Auth **v1.6.9**.

| Campo | Valor |
| --- | --- |
| Upstream npm | [`auth@1.6.9`](https://www.npmjs.com/package/auth) (bins: `auth`, `better-auth`) |
| Upstream path | `reference/upstream-src/1.6.9/repository/packages/cli/` |
| Crate Rust | `crates/openauth-cli` |
| Paridad pin | [`reference/upstream-better-auth/VERSION.md`](../../../reference/upstream-better-auth/VERSION.md) |
| Alcance | **Solo servidor / toolchain Rust** — sin codegen de cliente TS, sin ecosistema Node como producto |

## Relación de paquetes

| Rol | Upstream | OpenAuth |
| --- | --- | --- |
| CLI publicado | `auth` (`packages/cli`) | `openauth-cli` (crates.io) |
| Config runtime (TS) | `auth.ts` / `better-auth.ts` vía `get-config` + `c12` + `jiti` | `openauth.toml` (TOML estático) |
| Esquema / migraciones DB | `better-auth` + generadores Prisma/Drizzle/Kysely | `openauth-core` + `openauth-sqlx` → **SQL** |
| Telemetría CLI | `@better-auth/telemetry` en `generate` / `migrate` | `openauth-telemetry` (mismos eventos `cli_generate`, `cli_migrate`) |
| Plugins en schema | Opciones en `BetterAuthOptions` (init escribe TS) | `openauth-plugins` + lista en TOML |
| API programática | `auth/api` → `generateSchema`, generadores ORM | **No exportada** — solo binarios |

No hay split/merge de paquetes respecto al CLI upstream: **1 paquete npm ↔ 1 crate**. La complejidad repartida en Rust vive en **`openauth-core`**, **`openauth-sqlx`**, **`openauth-plugins`**, **`openauth-telemetry`** (documentados aparte).

## Índice

| Documento | Contenido |
| --- | --- |
| [01-overview.md](./01-overview.md) | Resumen ejecutivo, mapa de fuentes, estado global |
| [02-package-mapping.md](./02-package-mapping.md) | Binarios, dependencias, API exportada, integraciones workspace |
| [03-commands.md](./03-commands.md) | Tabla comando a comando (upstream ↔ Rust) |
| [04-config-workflows.md](./04-config-workflows.md) | Config, init, generate, migrate, secret, info |
| [05-design-differences.md](./05-design-differences.md) | Decisiones intencionales y límites (TS-only, client, infra) |
| [06-tests.md](./06-tests.md) | Matriz Vitest ↔ `assert_cmd`, huecos y superset |
| [07-source-inventory.md](./07-source-inventory.md) | Inventario archivo a archivo, telemetría, plugins, snapshots |
| [08-edge-cases.md](./08-edge-cases.md) | Exit codes, secretos, env, init+schema embebido, plugins diff |
| [09-parity-closure.md](./09-parity-closure.md) | Qué se cerró y qué queda fuera de alcance |

## Verificación rápida

```bash
cargo fmt -p openauth-cli --check
cargo clippy -p openauth-cli --all-targets -- -D warnings
cargo nextest run -p openauth-cli
```

Conteos documentados (2026-06-02): upstream **~284** casos Vitest; Rust **52** `#[test]` de integración (`tests/regression_gaps.rs` cubre huecos de paridad).

## Lectura recomendada cruzada

- Telemetría CLI: [`docs/parity/openauth-telemetry/`](../openauth-telemetry/README.md)
- Adaptador SQL / migraciones: [`docs/parity/openauth-sqlx/`](../openauth-sqlx/README.md)
