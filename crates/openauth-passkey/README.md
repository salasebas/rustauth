# openauth-passkey

Server-side passkey plugin for OpenAuth-RS.

## What It Is

`openauth-passkey` adds WebAuthn/passkey registration, authentication, and
credential management endpoints to OpenAuth. It is server-side only and uses
`webauthn-rs` for ceremony generation and cryptographic verification.

## What It Provides

- `/passkey/*` registration, authentication, list, update, and delete endpoints.
- A `passkeys` table schema contribution.
- Server-side WebAuthn ceremony state stored through OpenAuth verification
  storage and referenced by a signed short-lived cookie.
- Configurable relying-party ID, origin, relying-party name, user verification,
  authenticator selection, and registration user resolution.
- Ceremony and per-challenge rate limits for verify endpoints (see
  `PasskeyOptions::rate_limit` and `PasskeyOptions::challenge_rate_limit`).

## Quick Start

Enable the `passkey` feature on the umbrella `openauth` crate (or depend on
`openauth-passkey` directly):

```toml
[dependencies]
openauth = { version = "0.1.1", features = ["passkey"] }
```

```rust
use openauth::OpenAuth;
use openauth::passkey::{passkey, PasskeyOptions};

let auth = OpenAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .base_url("https://app.example.com")
    .plugin(
        passkey(
            PasskeyOptions::default()
                .rp_id("app.example.com"),
        ),
    )
    .build()?;
# let _ = auth;
# Ok::<(), Box<dyn std::error::Error>>(())
```

For production deployments, set an explicit public `base_url`, and configure
`rp_id`/`origin` in `PasskeyOptions` when your auth server runs behind a proxy,
custom domain, or multi-origin setup.

Integration tests that inject a fake WebAuthn backend should enable the
`test-util` feature on this crate and call `PasskeyOptions::backend(...)`.
Production apps use the built-in `webauthn-rs` backend by default.

## Endpoint Summary

- `GET /passkey/generate-register-options`
- `POST /passkey/verify-registration`
- `GET /passkey/generate-authenticate-options`
- `POST /passkey/verify-authentication`
- `GET /passkey/list-user-passkeys`
- `POST /passkey/update-passkey`
- `POST /passkey/delete-passkey`

Registration with an existing session requires a fresh session according to
OpenAuth core's `fresh_age` setting.

## Status

Beta. The plugin is usable for controlled integrations, but validate it against
the browsers, authenticators, RP ID, and origins used by your deployment before
production rollout.

## Better Auth compatibility

Server-side passkey routes and schema are aligned with Better Auth 1.6.9 where
it matters; OpenAuth is not a line-by-line port. For route-level parity, test
counts, differences, and gaps, see [UPSTREAM.md](./UPSTREAM.md).

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
