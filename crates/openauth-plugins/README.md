# openauth-plugins

Official server-side plugin modules for OpenAuth-RS.

## What It Is

`openauth-plugins` groups Better Auth-inspired server features translated into
OpenAuth's Rust plugin contracts. Use it when you want optional auth behavior
without pulling each feature into `openauth-core`.

The deprecated upstream `oidc-provider` and MCP authorization-server plugins are
not implemented here. Use `openauth-oauth-provider` for OAuth 2.1, OpenID
Connect provider behavior, and MCP protected-resource metadata.

## What It Provides

Current modules include access control, additional fields, admin, anonymous
users, API keys, bearer sessions, CAPTCHA hooks, custom sessions, device
authorization, email OTP, generic OAuth, Have I Been Pwned checks, JWT, last
login method, magic links, multi-session, OAuth proxy, one-tap, one-time
tokens, OpenAPI, organizations, phone number, SIWE, two-factor, and username.

Some plugins are pure helpers. Many require an OpenAuth adapter because they
store users, sessions, keys, organizations, tokens, or verification state.

## Quick Start

```rust
use openauth::OpenAuth;
use openauth_plugins::prelude::*;

let auth = OpenAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .plugin(admin())
    .plugin(jwt()?)
    .build()?;
# let _ = auth;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Import factories from [`prelude`](./src/prelude.rs) when wiring several plugins.
Each module exposes `name()` for defaults and `name_with(Options)` when you need
configuration. Plugins that require mandatory callbacks (magic link email, CAPTCHA,
SIWE, and similar) expose only `name_with`.

Register plugins on [`OpenAuth::builder()`](../openauth/README.md):

- `.plugin(x)` — append one plugin (chain as needed).
- `.plugins(vec![...])` — append a batch (same as chaining `.plugin`).

When building [`OpenAuthOptions`](../openauth-core/README.md) directly,
`.plugin(x)` appends and `.plugins(vec![...])` **replaces** the full list.

```rust
use openauth::OpenAuth;
use openauth_plugins::prelude::*;

let core = vec![admin(), bearer()];
let auth = OpenAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .plugins(core)
    .plugin(jwt()?)
    .build()?;
# let _ = auth;
# Ok::<(), Box<dyn std::error::Error>>(())
```

`email_otp` and `phone_number` resolve the database adapter from the auth
context at runtime; pass the adapter only to `OpenAuth::builder().adapter(...)`.

Use module-specific options when a plugin needs application callbacks such as
email sending, OTP delivery, CAPTCHA verification, SIWE verification, or custom
authorization policy.

## Naming conventions

- **Database logical names** (adapter queries, schema metadata): `snake_case`
  (`device_code`, `wallet_address`, `two_factor`).
- **HTTP JSON** (request/response bodies, OpenAPI): `camelCase` (`userId`,
  `walletAddress`) for Better Auth parity.
- **OAuth protocol endpoints** (device authorization, token grants): RFC-defined
  `snake_case` (`device_code`, `expires_in`) — not converted to camelCase.

Plugin options **metadata** JSON keeps camelCase keys (for example
`schema.walletAddress` on SIWE).

## Operational Notes

- Run adapter migrations after adding plugins that contribute schema.
- Prefer these plugins for server behavior; helper SDKs should stay outside this
  crate.
- API key storage can use the database and selected secondary-storage paths.
- In pure `SecondaryStorage` mode (no database fallback) the `api-key:by-ref:*`
  listing index is mutated through atomic `compare_and_set` /
  `delete_if_value`. Multi-process deployments need a secondary-storage backend
  that implements those methods with real backend atomicity, or the database
  fallback, to keep `/api-key/list` from dropping concurrently written keys.
- OpenAPI support serves generated auth schemas and optional Scalar reference
  UI.

## Status

Experimental beta. Individual plugin APIs, schemas, endpoints, hooks, and
error codes may change before stable release.

## Better Auth compatibility

Server-side official plugin behavior is aligned with Better Auth 1.6.9 where it
matters; OpenAuth is not a line-by-line port. For route-level parity, test
counts, differences, and gaps, see [UPSTREAM.md](./UPSTREAM.md).

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
