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
- OAuth/social-provider config snapshots when the `oauth` feature is enabled.
- Test hooks for deterministic telemetry assertions.

## Feature Flags

Default features preserve HTTP transport:

- `http` (default): JSON POST transport through `reqwest`.
- `oauth`: serializes configured social providers into the `socialProviders`
  branch of [`get_telemetry_auth_config`](https://docs.rs/openauth-telemetry/latest/openauth_telemetry/fn.get_telemetry_auth_config.html).
  Without this feature, `socialProviders` is always `[]` even when
  `OpenAuthOptions` carries social providers.

Direct consumers must opt in explicitly:

```toml
openauth-telemetry = { version = "0.0.6", features = ["oauth"] }
```

The umbrella [`openauth`](../openauth/README.md) `telemetry` feature already
enables `openauth-telemetry/oauth` for you, so application code that depends on
`openauth` with `features = ["telemetry"]` does not need a separate flag.

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

The [`openauth-cli`](../openauth-cli/README.md#telemetry) binary reuses these
variables for `generate` / `migrate` telemetry (`cli_generate`, `cli_migrate`).

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

## Better Auth compatibility

Server-side telemetry publisher and payload compatibility. Aligned with Better
Auth 1.6.9 where it matters; OpenAuth is not a line-by-line port.

Upstream `@better-auth/telemetry` ships OAuth/social-provider snapshots in the
same package. OpenAuth splits that behind the `oauth` feature so direct crate
users can keep a smaller dependency graph; enable `oauth` (or use the `openauth`
`telemetry` feature) for social-provider parity.

For route-level parity, test counts, differences, and gaps, see
[UPSTREAM.md](./UPSTREAM.md). Run OAuth snapshot coverage with
`cargo test -p openauth-telemetry --features oauth`.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
