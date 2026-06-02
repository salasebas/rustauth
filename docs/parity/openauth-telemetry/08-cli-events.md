# 08 — CLI events (`cli_generate` / `cli_migrate`)

The telemetry package does **not** define these events; it only accepts `publish` with `type` and `payload`. Producers are `packages/cli` (upstream) and `openauth-cli` (OpenAuth).

## Common payload shape

```json
{
  "type": "cli_generate | cli_migrate",
  "anonymousId": "<project id>",
  "payload": {
    "outcome": "<string>",
    "config": { /* get_telemetry_auth_config */ },
    "adapter": "optional",
    "database": "optional",
    "forced": true
  }
}
```

`adapter` / `database` in extras come from `TelemetryContext` or the `extra` map on adapter errors.

---

## `cli_generate`

| Outcome | Upstream (`generate.ts`) | OpenAuth (`commands/db.rs`, `db_support.rs`) | Parity |
| --- | --- | --- | --- |
| `no_changes` | Schema already up to date | Empty plan | Yes |
| `generated` | Successful new write | SQL migration generated (no `--force`) | Yes (different artifact: SQL vs TS/Prisma) |
| `overwritten` | `schema.overwrite` + confirm | `--force` + extra `forced: true` | Partial (same name, different trigger) |
| `appended` | Append to existing file | **Not emitted** | **Gap** — OpenAuth has no TS schema append mode |
| `aborted` | User cancels confirm | User cancels confirm | Yes |

### Upstream generate telemetry context

First `no_changes` includes `adapter` and `database` from the Kysely/adapter setup; OpenAuth always sets `adapter` + `database` from `openauth.toml` in `telemetry_context`.

---

## `cli_migrate`

| Outcome | Upstream (`migrate.ts`) | OpenAuth | Parity |
| --- | --- | --- | --- |
| `no_changes` | No pending migrations | Empty plan | Yes |
| `migrated` | Successful apply (kysely adapter) | `db::migrate_with_base` OK | Yes (OpenAuth applies its own SQL) |
| `aborted` | User cancel | User cancel | Yes |
| `unsupported_adapter` | Unsupported / non-kysely adapter | `map_db_error` | Yes |
| `dry_run` | — | `--dry-run` flag | **OpenAuth only** |
| `unsupported_database` | — | `DbCliError::UnsupportedProvider` | **OpenAuth only** |

### Exit code + telemetry (OpenAuth)

| Case | Exit code | Telemetry |
| --- | --- | --- |
| Unsupported adapter but documented success (e.g. prisma guidance) | 0 | `unsupported_adapter` |
| Unsupported adapter error | non-zero | `unsupported_adapter` |
| Unsupported provider | non-zero | `unsupported_database` |

Upstream uses `unsupported_adapter` only; OpenAuth splits invalid provider.

---

## CLI enablement

Same as server: requires `OPENAUTH_TELEMETRY_ENDPOINT` or `custom_track` so `create_telemetry` is not a hard noop; plus `OPENAUTH_TELEMETRY` / `telemetry.enabled` and not being in test env (unless `skip_test_check`).

Tests:

- `openauth-cli/tests/commands.rs` — smoke `cli_generate` + `generated`
- `openauth-cli/tests/regression_gaps.rs` — `unsupported_adapter`, `dry_run` behavior

Broader CLI parity: [`../openauth-cli/README.md`](../openauth-cli/README.md).
