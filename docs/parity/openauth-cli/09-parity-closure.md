# Cierre de paridad CLI (servidor)

Estado tras cerrar huecos de comportamiento y tests en **`openauth-cli`** frente a Better Auth **`packages/cli` v1.6.9**. No es paridad línea a línea con Node; es **equivalencia operativa** para equipos Rust/sqlx.

## Cubierto en esta ronda

| Área | Comportamiento |
| --- | --- |
| Adapters no sqlx | Mensaje guiado + telemetría `unsupported_adapter`; Prisma/Drizzle → **exit 0** (como upstream) |
| `db generate` | Plan impreso, confirmación (auto-`yes` sin TTY), `--force`, telemetría `aborted` / `overwritten` |
| `db migrate` | `ensure_safe_to_apply`, `--dry-run`, confirmación, telemetría |
| `init` | `.env.example` + `.env` (sin pisar `.env` existente); `--seed-secrets` opcional |
| `secret` | `--production` (default) / `--dev` |
| `info` | `--json`, `--copy` (pbcopy/xclip/clip) |
| Global | `-c` / `--cwd` |
| Plugins | `add`/`remove` cargan config; lista 27 IDs oficiales |
| Tests | `regression_gaps.rs` + suite existente (~50 tests) |

## Diferencias aceptadas (sin valor en seguir)

| Tema | Motivo |
| --- | --- |
| Comandos `ai`, `mcp`, `upgrade`, `login`, `logout` | Producto TS / npm, no toolchain Rust |
| Init wizard completo (npm, auth client, social, Prisma/Drizzle en wizard) | Runtime TS; Rust solo TOML + env |
| `generate`/`migrate` sin config → exit 0 (upstream) | Rust falla con exit 1 — **más seguro en CI** |
| `info` JSON con forma `better-auth` / `system` / `node` | Reporte `DiagnosticReport` + detección workspace |
| Plugins `passkey`, `scim`, `sso`, `stripe`, `i18n` en `plugins list` | Crates/ecosistema aparte; no todos en `PLUGIN_IDS` |
| Confirm sin TTY | Auto-confirma (ergonomía CI); upstream exige `-y` explícito |
| Secret init upstream 16 bytes hex vs Rust 32 bytes base64 | Política OpenAuth documentada en `08-edge-cases.md` |

## Verificación

```bash
cargo nextest run -p openauth-cli
```

## Conclusión

**Parar aquí** para el CLI servidor: lo restante es cliente TS, crates opcionales, o cosmética sin beneficio para usuarios Rust. Reabrir solo si sube la versión pin de Better Auth y cambian contratos de `generate`/`migrate`/telemetría.
