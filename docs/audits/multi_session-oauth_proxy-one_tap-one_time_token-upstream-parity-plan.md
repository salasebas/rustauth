# Upstream Parity Audit: multi-session, oauth-proxy, one-tap, one-time-token

## Summary

This audit compares the OpenAuth server-side implementations for `multi_session`,
`oauth_proxy`, `one_tap`, and `one_time_token` against Better Auth 1.6.9 under
`upstream/better-auth/`. The planned code changes are limited to confirmed
server-side parity, security-boundary, and response-shape gaps in
`openauth-plugins`.

## Upstream Files Inspected

- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/multi-session/index.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/multi-session/multi-session.test.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/multi-session/error-codes.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/multi-session/client.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/oauth-proxy/index.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/oauth-proxy/utils.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/oauth-proxy/oauth-proxy.test.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/one-tap/index.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/one-tap/client.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/one-time-token/index.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/one-time-token/utils.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/one-time-token/one-time-token.test.ts`

## OpenAuth Files Inspected

- `crates/openauth-plugins/src/multi_session/`
- `crates/openauth-plugins/src/oauth_proxy/`
- `crates/openauth-plugins/src/one_tap/`
- `crates/openauth-plugins/src/one_time_token/`
- `crates/openauth-plugins/tests/multi_session/`
- `crates/openauth-plugins/tests/oauth_proxy/`
- `crates/openauth-plugins/tests/one_tap/`
- `crates/openauth-plugins/tests/one_time_token/`
- `crates/openauth-core/src/auth/oauth/account_linking.rs`
- `crates/openauth-core/src/api/output.rs`
- `crates/openauth-core/src/api/routes/social/flow.rs`
- `crates/openauth-core/tests/api/routes/social_oauth.rs`
- `crates/openauth-plugins/src/generic_oauth/routes.rs`
- `crates/openauth-plugins/tests/generic_oauth/`

## Confirmed Matches

- `multi_session` matches upstream's main server behavior: signed per-session
  cookies, list/set-active/revoke endpoints, same-user replacement,
  max-session limiting, forged-cookie rejection, active-session promotion, and
  sign-out revocation.
- `oauth_proxy` already covers upstream's core flow: sign-in callback rewrite,
  production callback passthrough, encrypted profile payloads, max-age replay
  protection, state binding checks, skip header, custom secret, database state
  storage, and same-origin unwrap.
- OpenAuth intentionally uses `OPENAUTH_URL` rather than upstream
  `BETTER_AUTH_URL`.
- OpenAuth intentionally keeps one-tap missing-email failures as explicit
  `400 EMAIL_NOT_AVAILABLE` JSON errors rather than upstream's `200 { error }`.

## Confirmed Differences

- `one_tap` passes `is_trusted_provider: true` for every Google One Tap request,
  allowing implicit linking for same-email unverified provider payloads even
  when Google is not configured as trusted.
- `oauth_proxy` passes proxied OAuth payloads as trusted by default, which can
  bypass the same implicit-linking boundary for unverified provider emails.
- `one_time_token` verify responses serialize raw `Session` and `User` values
  instead of OpenAuth's configured output shape with returned additional fields.
- `one_time_token` verify sets only the session token cookie and skips session
  cookie-cache output when cookie cache is enabled.
- `one_time_token` generate authenticates the current session but drops refresh
  cookies returned by session lookup.
- `one_time_token` does not currently expose serializable plugin options
  metadata.
- The same OAuth implicit-linking trust issue also exists outside the original
  plugin set in OpenAuth's core social OAuth routes and the `generic_oauth`
  plugin callback: those flows passed `is_trusted_provider: true`
  unconditionally.

## Risks

- OAuth implicit-linking changes affect account linking for unverified provider
  payloads. Verified email flows and explicitly trusted providers should remain
  unchanged.
- Session output hardening must preserve existing one-time-token wire fields
  while adding configured returned fields.
- Cookie changes should not set cookies after an expired session is detected.

## Proposed Fixes

- Compute provider trust from
  `context.options.account.account_linking.trusted_providers` in `one_tap` and
  `oauth_proxy`, instead of treating these plugin flows as trusted
  unconditionally.
- Reuse `session_user_output` and `session_response_cookies` in
  `one_time_token` verify responses.
- Append current-session refresh cookies to successful
  `/one-time-token/generate` responses.
- Add camelCase `one_time_token` options metadata for serializable fields:
  `expiresIn`, `disableClientRequest`, `disableSetSessionCookie`,
  `storeToken`, and `setOttHeaderOnNewSession`.
- Extend the same trusted-provider fix to core social OAuth and `generic_oauth`
  so all server-side OAuth sign-in callbacks rely on verified provider email or
  explicit `trusted_providers` configuration.

## Tests To Add Or Update

- `one_tap`: reject implicit linking for an existing same-email user when the
  Google One Tap payload is unverified and Google is not trusted.
- `one_tap`: allow that same flow when `google` is configured as a trusted
  provider.
- `oauth_proxy`: redirect with `error=user_creation_failed` and create no
  account/session for an untrusted unverified same-email preview payload.
- `oauth_proxy`: allow the same preview payload when `google` is trusted.
- `one_time_token`: include returned additional user/session fields in verify
  output.
- `one_time_token`: set session cache cookie on verify when cookie cache is
  enabled.
- `one_time_token`: preserve refresh cookies from session lookup on generate.
- `one_time_token`: expose camelCase plugin options metadata.
- `openauth-core` social OAuth callback: reject implicit linking for an
  existing same-email user when the provider email is unverified and the
  provider is not trusted; allow the same flow when trusted.
- `openauth-core` social `idToken` sign-in: cover the same untrusted/trusted
  implicit-linking boundary.
- `generic_oauth`: cover untrusted/trusted implicit-linking behavior for
  unverified same-email callback payloads.

## Intentionally Left Unchanged

- No `multi_session` code changes are planned.
- No change to the `OPENAUTH_URL` environment variable.
- No change to one-tap's explicit missing-email error response.
- No client-side plugin behavior is in scope.
- Upstream's dynamic `trustedProviders` callback remains represented in
  OpenAuth as explicit static `trusted_providers` configuration. Adding a
  request-scoped provider resolver would be a public Rust API design change and
  is intentionally left for a focused follow-up.
