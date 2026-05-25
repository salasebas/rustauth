# OpenAuth Plugins Server Parity Notes

This file records server-side Better Auth parity decisions for
`openauth-plugins`. It is intentionally separate from the crate README.

## Completed

- `multi_session` matches the upstream server behavior for signed per-session
  cookies, active-session switching, revocation, max-session limiting, forged
  cookie rejection, and sign-out cleanup.
- `one_tap`, `oauth_proxy`, core social OAuth, and `generic_oauth` now share the
  same implicit-linking trust boundary: unverified same-email provider payloads
  require explicit `trusted_providers` configuration.
- `oauth_proxy` preserves the upstream server flow for callback rewriting,
  encrypted preview payloads, replay max-age checks, state cleanup,
  production passthrough, skip headers, custom secrets, and database-backed
  state.
- `one_time_token` verification now returns configured session/user output,
  preserves session cookie-cache output, keeps expired-session rejection before
  cookie setting, preserves refresh cookies during token generation, and exposes
  camelCase serializable plugin options metadata.

## Intentional Rust/OpenAuth Differences

- Environment naming uses `OPENAUTH_URL` instead of Better Auth's
  `BETTER_AUTH_URL`.
- One Tap missing-email handling returns an explicit
  `400 EMAIL_NOT_AVAILABLE` OpenAuth error instead of upstream's
  `200 { error }` shape.
- Serializable plugin metadata omits Rust closures and callback fields.
- OAuth proxy encrypted payload structs use Rust-owned strongly typed models
  internally. The payload is an OpenAuth-to-OpenAuth transport, not a public
  cross-implementation API.

## Remaining Server-Side Risk

- Dynamic request-scoped trusted provider resolution from Better Auth is not
  modeled yet; OpenAuth currently exposes static `trusted_providers`.
- Client-only Better Auth behavior remains out of scope for server parity.
