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

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
