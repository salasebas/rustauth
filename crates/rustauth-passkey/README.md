# rustauth-passkey

Server-side passkey plugin for RustAuth.

## What It Is

`rustauth-passkey` adds WebAuthn/passkey registration, authentication, and
credential management endpoints to RustAuth. It is server-side only and uses
`webauthn-rs` for ceremony generation and cryptographic verification.

## What It Provides

- `/passkey/*` registration, authentication, list, update, and delete endpoints.
- A `passkeys` table schema contribution.
- Server-side WebAuthn ceremony state stored through RustAuth verification
  storage and referenced by a signed short-lived cookie.
- Configurable relying-party ID, origin, relying-party name, user verification,
  authenticator selection, and registration user resolution.
- Ceremony and per-challenge rate limits for verify endpoints (see
  `PasskeyOptions::rate_limit` and `PasskeyOptions::challenge_rate_limit`).

## Quick Start

Enable the `passkey` feature on the umbrella `rustauth` crate (or depend on
`rustauth-passkey` directly):

```toml
[dependencies]
rustauth = { version = "0.2.0", features = ["passkey"] }
```

```rust
use rustauth::RustAuth;
use rustauth::passkey::{passkey, PasskeyOptions};

let auth = RustAuth::builder()
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
RustAuth core's `fresh_age` setting.

## Status

Beta. The plugin is usable for controlled integrations, but validate it against
the browsers, authenticators, RP ID, and origins used by your deployment before
production rollout.

## Better Auth compatibility

Server-side passkey routes and schema are aligned with Better Auth 1.6.9 where
it matters; RustAuth is not a line-by-line port. For route-level parity, test
counts, differences, and gaps, see [UPSTREAM.md](./UPSTREAM.md).

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/salasebas/rustauth)
