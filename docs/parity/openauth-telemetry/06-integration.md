# 06 — OpenAuth workspace integration

## `openauth` crate (feature `telemetry`)

| Piece | Location | Behavior |
| --- | --- | --- |
| Feature | `crates/openauth/Cargo.toml` | `telemetry = ["dep:openauth-telemetry", "openauth-telemetry/oauth"]` |
| Re-exports | `crates/openauth/src/lib.rs` | `create_telemetry`, `get_telemetry_auth_config`, types |
| Builder | `OpenAuthBuilder::telemetry_context` | Passes `TelemetryContext` |
| Async build | `build_async` → `attach_telemetry` | `create_telemetry` + stores publisher on context |
| Runtime API | `OpenAuth::publish_telemetry` | Delegates to `AuthContext` |

### Sync vs async (documented operational gap)

| API | Telemetry |
| --- | --- |
| `OpenAuthBuilder::build()` | **noop** publisher on context |
| `build_async()` / async root init | Real publisher when sink + enabled |

**Classification:** **Rust decision** — explicit async constructor; upstream TS is always async in `createTelemetry`.

### Integration test

`crates/openauth/tests/public_api.rs`: `openauth_async_builder_wires_context_telemetry_publisher` (requires feature `telemetry`).

## `openauth-core`

| Piece | Role |
| --- | --- |
| `TelemetryOptions` | `enabled`, `debug` on `OpenAuthOptions` |
| `AuthContext::publish_telemetry` | Trait object noop by default |
| No dependency on `openauth-telemetry` | Avoids crate cycle |

Upstream equivalent: types in `@better-auth/core`, implementation in telemetry package.

## `openauth-cli`

| File | Role |
| --- | --- |
| `src/telemetry.rs` | `publish_generate*`, `publish_migrate*`, minimal `OpenAuthOptions` + `TelemetryContext` |
| `src/commands/db.rs` | generate/migrate outcomes |
| `src/commands/db_support.rs` | `unsupported_adapter` / `unsupported_database` telemetry |
| `src/app.rs` | `dry_run` flag → `dry_run` outcome |

### CLI payload

```json
{
  "outcome": "<string>",
  "config": { /* get_telemetry_auth_config */ },
  "...": "optional extras (adapter, etc.)"
}
```

| Context field | CLI source |
| --- | --- |
| `database` | `config.database.provider` |
| `adapter` | `config.database.adapter` |

### Feature dependencies

`openauth-cli` depends on `openauth-telemetry` with **default** features (`http`), **without** `oauth` — CLI snapshot has no social providers unless added later.

Tests:

- `crates/openauth-cli/tests/commands.rs` — smoke `cli_generate` on stderr when telemetry enabled
- `crates/openauth-cli/tests/regression_gaps.rs` — `unsupported_adapter`, `dry_run`

Full outcome table: [08-cli-events.md](./08-cli-events.md).

## Upstream equivalent integration

| Consumer | Usage |
| --- | --- |
| `packages/better-auth` | Re-export telemetry API |
| `packages/cli` | `createTelemetry` + `publish` for generate/migrate |
| Better Auth server init | Creates telemetry at startup (TS pattern) |

Neither project exposes HTTP telemetry endpoints.

## OpenTelemetry / tracing

| System | Package |
| --- | --- |
| Product telemetry (this doc) | `@better-auth/telemetry` / `openauth-telemetry` |
| OTel traces | core instrumentation / future OpenAuth |

Do not merge requirements.
