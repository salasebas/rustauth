# openauth-core

Core contracts and server primitives for OpenAuth-RS.

## What It Is

`openauth-core` contains the framework-neutral pieces shared by the workspace:
API routing, auth context, cookies, crypto helpers, database adapter traits,
schema planning, errors, options, plugin contracts, sessions, users,
verification storage, and rate limiting.

Application code usually starts with `openauth`. Adapter and plugin crates use
`openauth-core` directly.

## What It Provides

- Core email/password, session, account, social sign-in, and verification route
  contracts.
- Database adapter traits and schema/migration metadata.
- `MemoryAdapter` for tests and local prototypes.
- Plugin, endpoint, hook, schema, and rate-limit extension contracts.
- Cookie, JWT/JWE, secret-rotation, and request/response primitives.

## Quick Start

```rust
use openauth_core::db::{auth_schema, AuthSchemaOptions};

let schema = auth_schema(AuthSchemaOptions::default());
let user_table = schema.table_name("user")?;
assert_eq!(user_table, "users");
# Ok::<(), Box<dyn std::error::Error>>(())
```

For a full auth server, prefer the `openauth` builder:

```rust
use openauth::OpenAuth;

let auth = OpenAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .base_url("https://app.example.com/api/auth")
    .build()?;
# let _ = auth;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Feature Flags

Default features preserve the broad compatibility surface:

- `jose`: JOSE/JWE helpers backed by `josekit`.
- `oauth`: OAuth/social route support and OAuth helper re-exports.
- `social-providers`: social provider re-exports.

Use `default-features = false` for a smaller core build when you do not need
JOSE or social provider support.

## Production Notes

- Configure a strong secret and explicit `base_url`.
- Use a durable adapter such as SQLx, `tokio-postgres`, or
  `deadpool-postgres`; `MemoryAdapter` is not persistent.
- Use distributed rate-limit storage for multi-instance deployments.
- Keep browser/client SDK behavior outside core; core owns server boundaries.

## Status

Experimental beta. Adapter, plugin, option, and route contracts may change
before stable release.

## Upstream parity (Better Auth 1.6.9)

Upstream splits contracts (`@better-auth/core`) from runtime
(`packages/better-auth/src`); OpenAuth merges both into this crate. The `openauth`
facade re-exports core plus optional integrations.

| Upstream | OpenAuth |
| --- | --- |
| `@better-auth/core` (types, DB, endpoints, utils) | `openauth-core` modules |
| `better-auth` server runtime (routes, cookies, crypto) | `openauth-core` (`api`, `cookies`, `crypto`, …) |
| `@better-auth/core/oauth2` | `openauth-oauth` (feature `oauth`) |
| `@better-auth/core/social-providers` | `openauth-social-providers` |
| Product plugins (`admin`, `organization`, …) | `openauth-plugins` and sibling crates |
| `@better-auth/core/instrumentation` | Not in core (`openauth-telemetry` is separate) |
| JS/React/Vue clients | N/A (server-only) |

### Status

**Parity level (server, in-scope):** High for email/password, session, cookies,
crypto, DB adapter traits, rate limiting, and plugin pipeline. Medium for some
top-level options and OpenAPI exposure. Low/N/A for OpenTelemetry spans in core
and browser client SDKs.

**Test coverage:** ~501 Rust tests total (~453 in-scope excluding oauth/social);
76 files under `tests/` plus 2 unit tests in `src/`. Upstream in-scope baseline is
~50 `.test.ts` files with ~184 `it()` in `@better-auth/core` and ~770+ in
better-auth server tests. Every in-scope HTTP route has at least one test, but
many routes have shallow coverage compared with upstream suites such as
`session-api.test.ts`.

**Completed:** Social OAuth implicit account linking follows the central
`handle_oauth_user_info` policy across authorization-code callbacks and `idToken`
sign-in: existing same-email users link when the provider email is verified;
unverified provider emails require the provider in `account.account_linking.trusted_providers`;
`disable_implicit_linking` and disabled account linking fail closed. Explicit
link-account flows keep email-match and `allow_different_emails` behavior.

**SQL adapter contracts (shared with SQL crates):** `SqlDialect::quote_identifier`
quotes dotted identifiers per segment (e.g. PostgreSQL `internal.users` compiles as
`"internal"."users"`), matching Better Auth PostgreSQL e2e schema-qualified names.
String pattern filters escape `%`, `_`, and `\` before `LIKE`/`ILIKE` so untrusted
filter input cannot broaden a query.

### Intentional differences

- OpenAuth uses static `trusted_providers: Vec<String>` instead of Better Auth's
  JavaScript `trustedProviders` array-or-function union. Request-scoped dynamic
  resolution would require a public Rust callback API and should be designed separately.
- Error responses keep OpenAuth's typed JSON/redirect conventions rather than
  duplicating every Better Auth string shape where observable security behavior is
  equivalent.
- Identifier segments remain strict ASCII SQL identifiers; empty segments, multiple
  dots, spaces, and punctuation are rejected rather than escaped into SQL.
- Pattern filters treat adapter input as literal user data; Better Auth's Kysely
  helper allows SQL wildcard semantics from the input string.

### Open gaps/risks

- Deeper test matrices for session revocation and account routes; route tests run
  with CSRF/origin checks disabled.
- Social/OAuth token routes live in other crates.
- `trustedProviders` dynamic callbacks are not yet public.
- User lifecycle hooks (`sendDeleteAccountVerification`, fresh-session delete semantics)
  partially diverge.
- Applications needing tenant- or request-dependent trusted providers must construct
  separate `AuthContext` values or wait for a dedicated dynamic trusted-provider API.

### Upstream lookup

1. Read the pin in [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md).
2. Open `reference/upstream-src/<version>/repository/packages/<upstream-package>/` (run `./scripts/fetch-upstream-better-auth.sh` if missing).
3. Map Rust modules in `crates/openauth-core/src/` to upstream `.ts` by route paths, exported handlers, and `*.test.ts` files.
4. Add a failing Rust integration test before changing behavior; match HTTP status, JSON error codes, and DB side effects—not TypeScript types.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
