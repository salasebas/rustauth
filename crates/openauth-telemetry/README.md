# openauth-telemetry

Opt-in telemetry helpers for OpenAuth-RS.

## What It Is

`openauth-telemetry` builds Better Auth-shaped telemetry payloads for Rust
hosts. It does not send anything by default. A deployment must provide
`OPENAUTH_TELEMETRY_ENDPOINT` or a custom track function before events leave
the process.

## What It Provides

- Telemetry publisher construction from `OpenAuthOptions`.
- Anonymous project ID resolution.
- Runtime and environment detection hooks.
- Optional HTTP transport through the default `http` feature.
- Test hooks for deterministic telemetry assertions.

## Quick Start

```rust
use openauth::{OpenAuthOptions, TelemetryOptions};
use openauth_telemetry::{create_telemetry, TelemetryContext, TelemetryEvent};
use serde_json::json;

let options = OpenAuthOptions::new()
    .base_url("https://app.example.com/api/auth")
    .telemetry(TelemetryOptions::new().enabled(true));

let publisher = create_telemetry(&options, TelemetryContext::default()).await;
publisher
    .publish(TelemetryEvent {
        event_type: "custom".to_owned(),
        anonymous_id: None,
        payload: json!({ "source": "app" }),
    })
    .await;
```

Without an endpoint or custom sink this remains a no-op, even when telemetry is
enabled in options.

## Environment

- `OPENAUTH_TELEMETRY`: master switch (see precedence below).
- `OPENAUTH_TELEMETRY_DEBUG`: print JSON instead of POSTing.
- `OPENAUTH_TELEMETRY_ENDPOINT`: collector URL.

### Enablement precedence

`OPENAUTH_TELEMETRY` takes precedence over `TelemetryOptions::enabled`:

- `OPENAUTH_TELEMETRY=false` (or `0`) is a hard opt-out: telemetry stays off
  even when application code calls `TelemetryOptions::enabled(true)`.
- `OPENAUTH_TELEMETRY=true` (or `1`) enables telemetry on its own, regardless
  of the options value.
- When the variable is unset, `TelemetryOptions` decides (disabled by default).

Telemetry is additionally suppressed under tests unless
`TelemetryContext::skip_test_check` is set, and remains a no-op until an
endpoint or custom sink exists (see above).

## Status

Experimental beta. Payload shape, detection behavior, environment variables,
and transport hooks may change before stable release.

## Upstream parity (Better Auth 1.6.9)

Upstream package: `@better-auth/telemetry` (one npm package → one Rust crate). Re-exported
from `openauth` with feature `telemetry`; CLI events from `openauth-cli`. Server-only,
opt-in anonymous usage analytics.

### Status

| Area | Server parity | Notes |
| --- | --- | --- |
| Publisher / enablement / noop | High | `OPENAUTH_TELEMETRY` hard opt-out; noop without endpoint or `custom_track` |
| `init` event shape | High | Runtime `rust`, package manager `cargo` by design |
| Config snapshot | Medium–high | Better Auth-shaped JSON; some branches fixed until `openauth-core` grows |
| Host detectors | Medium | Deploy vendors aligned; `cpuModel` / `memory` null without sysinfo |
| JS detectors (Next, Prisma, npm) | N/A | Cargo / Rust equivalents |
| Package tests | Superset | 6 upstream Vitest → 33 Rust (34 with `--features oauth`) |

Verify: `cargo test -p openauth-telemetry` (add `--features oauth` for OAuth snapshot branches).

### Intentional differences

- Environment variables use the `OPENAUTH_TELEMETRY*` prefix instead of Better Auth names.
- Runtime detection reports `rust` and package manager `cargo` instead of Node/npm.
- `cpuModel` and `memory` remain null unless a host adds sysinfo-backed detectors.
- Telemetry stays a no-op without `OPENAUTH_TELEMETRY_ENDPOINT` or a custom track function.

### Open gaps/risks

- Config snapshot branches may lag until `openauth-core` exposes matching option surfaces.
- JavaScript framework detectors (Next.js, Prisma, npm lockfiles) have no Rust equivalent.
- OAuth-related snapshot branches require `--features oauth` in crate tests.

### Upstream lookup

1. Read the pin in [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md).
2. Open `reference/upstream-src/<version>/repository/packages/telemetry/` (run `./scripts/fetch-upstream-better-auth.sh` if missing).
3. Map Rust modules in `crates/openauth-telemetry/src/` to upstream `.ts` by exported event types, detectors, and `telemetry.test.ts`.
4. Add a failing Rust integration test before changing behavior; match payload shape and enablement semantics—not TypeScript types.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
