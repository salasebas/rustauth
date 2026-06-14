# rustauth-core

Core contracts and server primitives for RustAuth.

## What It Is

`rustauth-core` contains the framework-neutral pieces shared by the workspace:
API routing, auth context, cookies, crypto helpers, database adapter traits,
schema planning, errors, options, plugin contracts, sessions, users,
verification storage, and rate limiting.

Application code usually starts with `rustauth`. Adapter and plugin crates use
`rustauth-core` directly.

## What It Provides

- Core email/password, session, account, social sign-in, and verification route
  contracts.
- Database adapter traits and schema/migration metadata.
- `MemoryAdapter` for tests and local prototypes.
- Plugin, endpoint, hook, schema, and rate-limit extension contracts.
- Cookie, JWT/JWE, secret-rotation, and request/response primitives.

## Quick Start

```rust
use rustauth_core::db::{auth_schema, AuthSchemaOptions};

let schema = auth_schema(AuthSchemaOptions::default());
let user_table = schema.table_name("user")?;
assert_eq!(user_table, "users");
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Custom table and column names

Configure logical→physical mapping in `RustAuthOptions` (`user.schema`, `session.schema`, …).
SQL adapters apply renames when generating queries. Domain stores (`DbUserStore`, `PasskeyStore`, …)
and [`AuthContext::schema`](crate::context::AuthContext::schema) map adapter records back to logical
field names when needed.

Typical app code uses HTTP routes and stores — not raw adapter queries. Plugin authors that call
[`DbAdapter`](crate::db::DbAdapter) directly can validate names and map records:

```rust
use rustauth_core::db::{DbValue, FindOne};

let users = context.schema().table("user")?;
let record = adapter
    .find_one(
        FindOne::new(users.model())
            .where_clause(users.where_eq("email", DbValue::String(email))?)
    )
    .await?
    .map(|record| users.map_record(record))
    .transpose()?;
# Ok::<(), rustauth_core::error::RustAuthError>(())
```

Prefer [`DbUserStore::from_context`](crate::user::DbUserStore::from_context) in handlers instead of
building queries by hand.

## Handler and plugin patterns

HTTP routes and plugins should treat [`AuthContext`](crate::context::AuthContext) as the runtime hub:

- `context.users()`, `context.sessions()`, and `context.verifications()` for store access.
- `context.adapter_ref()` or `context.require_adapter()` when you need the database adapter directly.
- [`create_auth_endpoint`](crate::api::create_auth_endpoint) for async HTTP handlers
  (`Fn(AuthContext, ApiRequest) -> impl Future`, no manual `Box::pin`).
- [`create_auth_endpoint_raw`](crate::api::create_auth_endpoint_raw) when you need the
  pinned `EndpointFuture` handler style directly.
- `with_async_after_hook` / `with_async_before_hook` for async plugin hooks.

Core routes, passkey endpoints, and all first-party plugins follow this pattern.

For a full auth server, prefer the `rustauth` builder:

```rust
use rustauth::RustAuth;

let auth = RustAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .base_url("https://app.example.com/api/auth")
    .build()?;
# let _ = auth;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Plugin registration on `RustAuthOptions`:

- `.plugin(plugin)` appends one entry.
- `.plugins(vec![...])` appends a batch (like chaining `.plugin`).
- `.set_plugins(vec![...])` replaces the full list.

The `rustauth` builder also exposes `.plugin` and `.plugins`; both append there
appends a batch without discarding plugins registered earlier on the builder.

## Feature Flags

Default features are empty (`default = []`). Enable only what you need:

- `jose`: JOSE/JWE helpers backed by `josekit`. **Recommended for production**
  when using cookie JWE cache (`cookies/cache.rs` returns
  `FeatureDisabled { feature: "jose" }` without it).
- `oauth`: OAuth/social route support and OAuth helper re-exports.
- `social-providers`: social provider re-exports (requires `oauth`).

```toml
rustauth-core = { version = "0.1.0", features = ["jose"] }
```

## Production Notes

- Configure a strong secret and explicit `base_url`.
- Use a durable adapter such as SQLx, `tokio-postgres`, or
  `deadpool-postgres`; `MemoryAdapter` is not persistent.
- Use distributed rate-limit storage for multi-instance deployments.
- Core owns server boundaries; framework wiring lives in adapter crates (e.g.
  `rustauth-axum`).

## Outbound delivery (security)

Email and SMS hooks (`SendVerificationEmail`, `SendResetPassword`, plugin OTP
senders) are async and dispatched in the background so HTTP responses do not
wait on SMTP/SMS latency. See [docs/security-outbound-delivery.md](../../docs/security-outbound-delivery.md).

- Re-exported helpers: `dispatch_outbound`, `OutboundSendFuture`, `ready_outbound`.
- Default background runner: `TokioBackgroundTaskRunner` when
  `AdvancedOptions::background_tasks` is unset.
- Optional `AdvancedOptions::outbound_min_response_time` configuration stub for future minimum response wall time.

## Status

Experimental beta. Adapter, plugin, option, and route contracts may change
before stable release.

## Better Auth compatibility

Server-side core (routes, cookies, crypto, DB adapters, plugins), aligned with
Better Auth 1.6.9 where it matters; not a line-by-line port. See
[UPSTREAM.md](./UPSTREAM.md) for route parity, test counts, differences, and gaps.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/salasebas/rustauth)
