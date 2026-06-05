# openauth-plugins

Official server-side plugin modules for OpenAuth-RS.

## What It Is

`openauth-plugins` groups Better Auth-inspired server features translated into
OpenAuth's Rust plugin contracts. Use it when you want optional auth behavior
without pulling each feature into `openauth-core`.

The deprecated upstream `oidc-provider` plugin is not implemented here. Use
`openauth-oauth-provider` for OAuth 2.1 and OpenID Connect provider behavior.

## What It Provides

Current modules include access control, additional fields, admin, anonymous
users, API keys, bearer sessions, CAPTCHA hooks, custom sessions, device
authorization, email OTP, generic OAuth, Have I Been Pwned checks, JWT, last
login method, magic links, MCP, multi-session, OAuth proxy, one-tap, one-time
tokens, OpenAPI, organizations, phone number, SIWE, two-factor, and username.

Some plugins are pure helpers. Many require an OpenAuth adapter because they
store users, sessions, keys, organizations, tokens, or verification state.

## Quick Start

```rust
use openauth::OpenAuth;
use openauth_plugins::admin::{admin, AdminOptions};
use openauth_plugins::jwt;

let auth = OpenAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .plugin(admin(AdminOptions::default()))
    .plugin(jwt::jwt()?)
    .build()?;
# let _ = auth;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Use module-specific options when a plugin needs application callbacks such as
email sending, OTP delivery, CAPTCHA verification, SIWE verification, or custom
authorization policy.

## Operational Notes

- Run adapter migrations after adding plugins that contribute schema.
- Prefer server-side plugins here for server behavior; browser-only upstream
  helpers should live in thin client SDKs instead.
- API key storage can use the database and selected secondary-storage paths.
- In pure `SecondaryStorage` mode (no database fallback) the `api-key:by-ref:*`
  listing index is mutated through an in-process lock, so concurrent
  create/delete on one process stay consistent. Multi-process deployments still
  need a secondary-storage backend with atomic collection semantics, or the
  database fallback, to keep `/api-key/list` from dropping concurrently written
  keys.
- OpenAPI support serves generated auth schemas and optional Scalar reference
  UI.

## Status

Experimental beta. Individual plugin APIs, schemas, endpoints, hooks, and
error codes may change before stable release.

## Upstream parity (Better Auth 1.6.9)

Upstream server plugins live under `packages/better-auth/src/plugins/` (26 modules)
plus `@better-auth/api-key` as a separate npm package. OpenAuth consolidates **27
server plugins** in this crate. The deprecated upstream `oidc-provider` plugin is
replaced by `openauth-oauth-provider`. SSO, SCIM, Stripe, and Electron/Expo
surfaces are out of scope here.

### Status

**Parity level:** High for HTTP routes (~130) and schema/hook wiring; June 2026
work closed server gaps for `generateTOTP`, organization access-control options,
api-key `defaultPermissions` and schema merge, two-factor custom OTP storage,
jwt/phone-number/username schema options, and `verification.storeIdentifier: hashed`
(in `openauth-core`). Remaining gaps are mostly test depth and a few organization
options (`allowUserToCreateOrganization` callback, `organizationHooks` async,
session field renames).

**Test coverage:** **610** integration tests under `tests/<plugin>/` vs **986**
upstream `it()` declarations (excluding `test-utils` and `oidc-provider`). Largest
gaps: organization (−150), api-key (−124), email-otp (−42), two-factor (−34).
Several plugins exceed upstream counts (access, bearer, multi_session, one_tap).
Inventory guard: `tests/plugins.rs`
(`upstream_server_plugin_parity_is_explicit_about_replaced_oidc_provider`).

**Completed:** `multi_session` matches upstream for signed per-session cookies,
active-session switching, revocation, max-session limiting, forged-cookie rejection,
and sign-out cleanup. `one_tap`, `oauth_proxy`, core social OAuth, and
`generic_oauth` share the same implicit-linking trust boundary: unverified same-email
provider payloads require explicit `trusted_providers`. `oauth_proxy` preserves
callback rewriting, encrypted preview payloads, replay max-age checks, state cleanup,
production passthrough, skip headers, custom secrets, and database-backed state.
`one_time_token` returns configured session/user output, preserves session
cookie-cache output, rejects expired sessions before cookie setting, preserves
refresh cookies during token generation, and exposes camelCase serializable plugin
options metadata.

### Intentional differences

- Environment naming uses `OPENAUTH_URL` instead of Better Auth's `BETTER_AUTH_URL`.
- One Tap missing-email handling returns `400 EMAIL_NOT_AVAILABLE` instead of
  upstream's `200 { error }` shape.
- Serializable plugin metadata omits Rust closures and callback fields.
- OAuth proxy encrypted payload structs use Rust-owned strongly typed models
  internally; the payload is OpenAuth-to-OpenAuth transport, not a public
  cross-implementation API.

### Open gaps/risks

- Partial test parity vs upstream Vitest suites; some organization permission merge
  semantics; plugin rate limits not always exposed as options.
- Client-only `client.ts` exports and TypeScript inference helpers are N/A.
- Dynamic request-scoped trusted provider resolution from Better Auth is not modeled
  yet; OpenAuth currently exposes static `trusted_providers`.
- Client-only Better Auth behavior remains out of scope for server parity.

### Upstream lookup

1. Read the pin in [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md).
2. Open `reference/upstream-src/<version>/repository/packages/<upstream-package>/` (run `./scripts/fetch-upstream-better-auth.sh` if missing).
3. Map Rust modules in `crates/openauth-plugins/src/` to upstream `.ts` by route paths, exported handlers, and `*.test.ts` files.
4. Add a failing Rust integration test before changing behavior; match HTTP status, JSON error codes, and DB side effects—not TypeScript types.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
