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

```rust
use openauth::OpenAuth;
use openauth_passkey::{passkey, PasskeyOptions};

let auth = OpenAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .base_url("https://app.example.com")
    .plugin(passkey(PasskeyOptions::default()))
    .build()?;
# let _ = auth;
# Ok::<(), Box<dyn std::error::Error>>(())
```

For production deployments, set an explicit public `base_url`, and configure
`rp_id`/`origin` in `PasskeyOptions` when your auth server runs behind a proxy,
custom domain, or multi-origin setup.

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

## Upstream parity (Better Auth 1.6.9)

Upstream: `@better-auth/passkey` (server routes only; no TS client in this crate).
Estimated server-side parity: **~99%**; remaining differences are client-only or
intentional Rust/OpenAuth architecture choices.

### Status

| Area | Status | Notes |
| --- | --- | --- |
| HTTP endpoints | **High (~99%)** | Same **7** routes (method + path) |
| Challenge state | **High** | Verification store + `better-auth-passkey` cookie, 5 min TTL |
| WebAuthn | **High** | `webauthn-rs` vs `@simplewebauthn/server`; observable contract aligned |
| Error codes | **High** | 14 `PASSKEY_ERROR_CODES` matched |
| Tests | **Beyond upstream** | **60+** Rust tests vs 19 upstream server Vitest cases |

Challenge state is stored server-side, referenced by the signed cookie, and expires
after 5 minutes. Registration and authentication cover sessions, `resolve_user`,
extensions, fresh-session checks, `after_verification`, duplicate credential rejection,
discoverable credentials, counter updates, and challenge cleanup. Public JSON uses
upstream `credentialID`; stored `publicKey` is base64-encoded COSE public-key CBOR.

### Intentional differences

- Database table defaults to `passkeys` with snake_case fields; public responses stay
  in the upstream camelCase shape.
- A hidden `webauthn_credential` JSON field persists complete `webauthn-rs` state for
  secure authentication and counter updates.
- Stricter session-scoped authentication challenge checks reject credentials outside
  the session-scoped challenge.
- Ceremony and per-challenge rate limits are configurable via `PasskeyOptions` (upstream
  relies on the global limiter only).
- `verify-authentication` returns generic `AUTHENTICATION_FAILED` for unknown credentials
  to avoid credential-ID enumeration.
- Discoverable authentication without a session is supported as an OpenAuth extra.

### Open gaps/risks

- Optional `mergeSchema` field rename is not ported.
- Legacy `publicKey`-only verify paths from upstream are not ported.
- Better Auth client helpers, browser ceremonies, and TypeScript inference helpers are
  out of scope (server-only crate).

### Upstream lookup

1. Read the pin in [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md).
2. Open `reference/upstream-src/<version>/repository/packages/passkey/` (run `./scripts/fetch-upstream-better-auth.sh` if missing).
3. Map Rust modules in `crates/openauth-passkey/src/` to upstream `.ts` by route paths, exported handlers, and `passkey.test.ts`.
4. Add a failing Rust integration test before changing behavior; match HTTP status, JSON error codes, and DB side effects—not TypeScript types.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
