# 02 — Public API and types

## Exported surface

| Upstream (`@better-auth/telemetry`) | OpenAuth (`openauth-telemetry`) | Parity |
| --- | --- | --- |
| `createTelemetry(options, context?)` | `create_telemetry(options, context)` | Yes (async in Rust) |
| `getTelemetryAuthConfig(options, context?)` | `get_telemetry_auth_config(options, context)` | Yes (sync) |
| `TelemetryEvent` (type) | `TelemetryEvent` (struct) | Yes |
| Return `{ publish(event) }` | `TelemetryPublisher` + `publish` | Yes (explicit type) |
| — | `VERSION` | Extra (crate version) |
| — | `TelemetryHttpTransport`, `TelemetryHttpError` | Extra (HTTP injection) |
| — | `TelemetryTestHooks` | Extra (tests only) |
| — | `DetectionInfo`, `RuntimeInfo`, `CustomTrackFn` | Equivalent to upstream internal types |

### Re-exports at the root crate

| Consumer | Upstream | OpenAuth |
| --- | --- | --- |
| Main package | `better-auth` re-exports all three APIs | `openauth` with feature `telemetry` re-exports helpers + types |
| CLI | Import from `@better-auth/telemetry` | `openauth_telemetry` directly |

## `TelemetryEvent`

| Upstream field (JSON) | Rust (`serde`) | Notes |
| --- | --- | --- |
| `type` | `event_type` → serializes as `type` | |
| `anonymousId?` | `anonymous_id` | `publish` **overwrites** with project id |
| `payload` | `payload: serde_json::Value` | Free-form object |

## `TelemetryContext`

| Field | Upstream | OpenAuth | Parity |
| --- | --- | --- | --- |
| `customTrack` | `async (event) => void` | `Option<CustomTrackFn>` | Yes |
| `database` | `string?` | `Option<String>` | Yes |
| `adapter` | `string?` | `Option<String>` | Yes |
| `skipTestCheck` | `boolean?` | `skip_test_check: bool` | Yes |
| — | — | `http_transport: Option<Arc<dyn TelemetryHttpTransport>>` | Extra |
| — | — | `test_hooks: Option<TelemetryTestHooks>` | Extra |

## Cargo features (`openauth-telemetry`)

| Feature | Default | Effect |
| --- | --- | --- |
| `http` | yes | `reqwest` for JSON POST |
| `oauth` | no | Snapshot includes `socialProviders` from OAuth traits |

The `openauth` crate enables `telemetry = ["openauth-telemetry", "openauth-telemetry/oauth"]`.

## Environment variables

| Upstream (`@better-auth/core` ENV) | OpenAuth | Functional parity |
| --- | --- | --- |
| `BETTER_AUTH_TELEMETRY` | `OPENAUTH_TELEMETRY` | Partial (see [03](./03-publisher-enablement.md)) |
| `BETTER_AUTH_TELEMETRY_DEBUG` | `OPENAUTH_TELEMETRY_DEBUG` | Yes |
| `BETTER_AUTH_TELEMETRY_ENDPOINT` | `OPENAUTH_TELEMETRY_ENDPOINT` | Yes |
| `BETTER_AUTH_TELEMETRY_ID` | — | **Not consumed** upstream or OpenAuth in 1.6.9 |

Runtime environment detection:

| Concept | Upstream | OpenAuth |
| --- | --- | --- |
| Production | `NODE_ENV=production` | `RUST_ENV=production` |
| Test | `isTest()` (Vitest / `NODE_ENV=test`) | `RUST_ENV=test` or `TEST` |
| CI | `isCI()` in core/telemetry | Same `CI`, `BUILD_*`, etc. in `env.rs` |

## Non-goals (API not ported)

| Upstream surface | Reason |
| --- | --- |
| Conditional `node` vs default export | Single Rust artifact; runtime detection |
| Peer `@better-fetch/fetch` | `reqwest` + trait |
| Async `package.json` reads on edge | No equivalent on pure Rust server |
| Core `logger` on HTTP errors | HTTP errors ignored (`let _ =`); custom track in spawn |

## Rust extensions (documented as **non-upstream**)

Deliberate for operations and tests; safe if unused in production:

1. **`TelemetryHttpTransport`** — mocks in tests (`CountingTransport`, `CapturingTransport`).
2. **`TelemetryTestHooks`** — pins runtime, DB, framework, `systemInfo`, `anonymousId`.
3. **`TelemetryPublisher::noop()`** — explicit constructor (upstream returns object with noop `publish`).
