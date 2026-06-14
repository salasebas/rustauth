# rustauth-telemetry

Opt-in telemetry helpers for RustAuth.

## What It Is

`rustauth-telemetry` builds Better Auth-shaped telemetry payloads for Rust
hosts. It does not send anything by default. A deployment must provide
`RUSTAUTH_TELEMETRY_ENDPOINT` or a custom track function before events leave
the process.

## What It Provides

- Telemetry publisher construction from `RustAuthOptions`.
- Anonymous project ID resolution.
- Runtime and environment detection hooks.
- Optional HTTP transport through the `http` feature (`default = []`).
- OAuth/social-provider config snapshots when the `oauth` feature is enabled.
- Test hooks (`TelemetryTestHooks`, `get_telemetry_auth_config`) for integration
  tests; they are `#[doc(hidden)]` on the public API surface.

## Feature Flags

No default features. Enable what you need:

- `http`: JSON POST transport through `reqwest`.
- `oauth`: serializes configured social providers into the `socialProviders`
  branch of [`get_telemetry_auth_config`](https://docs.rs/rustauth-telemetry/latest/rustauth_telemetry/fn.get_telemetry_auth_config.html).
  Without this feature, `socialProviders` is always `[]` even when
  `RustAuthOptions` carries social providers.

```toml
rustauth-telemetry = { version = "0.1.0", default-features = false, features = ["http", "oauth"] }
```

The umbrella [`rustauth`](../rustauth/README.md) `telemetry` feature enables
`rustauth-telemetry/http` and `rustauth-telemetry/oauth` for you.

## Quick Start

```rust
use rustauth::telemetry::{create_telemetry, TelemetryContext, TelemetryEvent};
use rustauth::{RustAuthOptions, TelemetryOptions};
use serde_json::json;

let options = RustAuthOptions::new()
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

When telemetry is enabled and a sink exists, [`create_telemetry`](https://docs.rs/rustauth-telemetry/latest/rustauth_telemetry/fn.create_telemetry.html)
immediately publishes an `init` event (asynchronously, without blocking
construction). The payload includes a Better Auth-shaped `config` snapshot plus
runtime, database, framework, environment, `systemInfo`, and `packageManager`
detection fields. Later [`TelemetryPublisher::publish`](https://docs.rs/rustauth-telemetry/latest/rustauth_telemetry/struct.TelemetryPublisher.html)
calls emit additional event types you choose (for example `cli_generate` from
the CLI).

## Environment

The [`rustauth-cli`](../rustauth-cli/README.md#telemetry) binary reuses these
variables for `generate` / `migrate` telemetry. Each opted-in run emits `init`
first, then `cli_generate` or `cli_migrate`.

- `RUSTAUTH_TELEMETRY`: master switch (see precedence below).
- `RUSTAUTH_TELEMETRY_DEBUG`: print JSON instead of POSTing.
- `RUSTAUTH_TELEMETRY_ENDPOINT`: collector URL.

### Enablement precedence

`RUSTAUTH_TELEMETRY` takes precedence over `TelemetryOptions::enabled`:

- `RUSTAUTH_TELEMETRY=false` (or `0`) is a hard opt-out: telemetry stays off
  even when application code calls `TelemetryOptions::enabled(true)`.
- `RUSTAUTH_TELEMETRY=true` (or `1`) enables telemetry on its own, regardless
  of the options value.
- When the variable is unset, `TelemetryOptions` decides (disabled by default).

Telemetry is additionally suppressed under tests unless
`TelemetryContext::skip_test_check` is set, and remains a no-op until an
endpoint or custom sink exists (see above).

## Status

Experimental beta. Payload shape, detection behavior, environment variables,
and transport hooks may change before stable release.

## Better Auth compatibility

Server-side telemetry publisher and payload compatibility. Aligned with Better
Auth 1.6.9 where it matters; RustAuth is not a line-by-line port.

Upstream `@better-auth/telemetry` ships OAuth/social-provider snapshots in the
same package. RustAuth splits that behind the `oauth` feature so direct crate
users can keep a smaller dependency graph; enable `oauth` (or use the `rustauth`
`telemetry` feature) for social-provider parity.

For route-level parity, test counts, differences, and gaps, see
[UPSTREAM.md](./UPSTREAM.md). Run OAuth snapshot coverage with
`cargo test -p rustauth-telemetry --features oauth`.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/salasebas/rustauth)
