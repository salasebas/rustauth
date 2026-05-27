# Device Authorization, Email OTP, Generic OAuth, and Have I Been Pwned Upstream Parity Audit

## Upstream Files Inspected

- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/device-authorization/{index.ts,routes.ts,schema.ts,error-codes.ts,device-authorization.test.ts}`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/email-otp/{index.ts,routes.ts,types.ts,otp-token.ts,utils.ts,error-codes.ts,email-otp.test.ts}`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/generic-oauth/{index.ts,routes.ts,types.ts,error-codes.ts,generic-oauth.test.ts}` and provider helper files under `providers/`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/haveibeenpwned/{index.ts,haveibeenpwned.test.ts}`

## OpenAuth Files Inspected

- `crates/openauth-plugins/src/device_authorization/**` and `crates/openauth-plugins/tests/device_authorization/**`
- `crates/openauth-plugins/src/email_otp/**` and `crates/openauth-plugins/tests/email_otp/**`
- `crates/openauth-plugins/src/generic_oauth/**` and `crates/openauth-plugins/tests/generic_oauth/**`
- `crates/openauth-plugins/src/haveibeenpwned/**` and `crates/openauth-plugins/tests/haveibeenpwned/**`
- Supporting session and secondary-storage code in `crates/openauth-core/src/session.rs`, `crates/openauth-core/src/api/output.rs`, and `crates/openauth-core/src/api/routes/shared.rs`

## Confirmed Matches

- Device Authorization exposes the upstream routes, default lifetimes, code lengths, polling interval, code/user-code generators, client validation hook, request hook, verification URI construction, OAuth error names, cache headers, pending/approved/denied lifecycle, and code cleanup after terminal states.
- Email OTP exposes the upstream server routes, default OTP length and expiry, sign-in/sign-up behavior, password reset behavior, verification callbacks, resend strategies, hashed/encrypted/custom storage, attempt tracking, and rate limits.
- Generic OAuth exposes the upstream sign-in, callback, and link endpoints; provider helpers; discovery support; PKCE; token and authorization URL params; issuer validation; account linking checks; and user-info mapping hooks.
- Have I Been Pwned uses the upstream k-anonymity SHA-1 prefix/suffix flow, `Add-Padding: true`, Better Auth user agent, default checked paths, disabled option, custom compromised-password message, and equivalent 400/500 failure boundaries.

## Confirmed Differences

- Email OTP `/email-otp/create-verification-otp` returns `{ "otp": "..." }` in OpenAuth, while upstream returns the OTP as a bare JSON string.
- Email OTP server create/get/check endpoints reject `change-email`; upstream only rejects `change-email` on the public send endpoint and supports it for server-only OTP operations.
- Email OTP hashed/custom-hashed `getVerificationOTP` uses a different error message from upstream.
- Email OTP `/email-otp/change-email` returns an extra `user` body field; upstream returns `{ "success": true }`.
- Email OTP-created sessions use `DbSessionStore` directly, bypassing configured secondary storage.
- Device Authorization approved token exchange uses `DbSessionStore` directly, bypassing configured secondary storage.
- Generic OAuth callback-time provider/config errors can bubble as raw `OpenAuthError::Api` instead of being normalized into the existing OAuth error response path.
- Generic OAuth provider-not-found responses do not include the requested provider id where upstream includes it.

## Risks

- Response shape changes may break consumers that depended on the existing Rust-specific `{ "otp": ... }` or change-email `user` field.
- Session-store changes must preserve existing database-backed behavior while adding secondary-storage support.
- Generic OAuth error normalization must avoid changing successful callback/link/sign-in behavior.
- HIBP performs live network I/O in production; tests must continue using injectable checkers only.

## Proposed Fixes

- Update Email OTP server response and validation behavior to match upstream while keeping Rust-native explicit errors and strong types.
- Route Email OTP and Device Authorization session creation through `openauth_core::session::SessionStore`.
- Normalize Generic OAuth callback provider/config errors to redirects with existing OAuth error codes and add provider id to provider-not-found messages.
- Leave HIBP code unchanged unless implementation finds an untested parity or production-readiness issue.

## Tests To Add Or Update

- Update Email OTP tests that parse `/email-otp/create-verification-otp` to expect a bare JSON string.
- Add Email OTP server tests for `change-email` create/get/check support and the upstream hashed OTP retrieval message.
- Add or update Email OTP change-email tests to assert the upstream success-only response body.
- Add secondary-storage regression tests for Email OTP-created sessions and Device Authorization approved token exchange.
- Add Generic OAuth callback/provider-config regression tests for unknown provider and invalid config normalization.

## Items Intentionally Left Unchanged

- HIBP `UPSTREAM_PLUGIN_ID` remains `haveibeenpwned` for OpenAuth's plugin inventory, while runtime plugin id remains `have-i-been-pwned` to match upstream behavior.
- Existing Rust email validation and normalization remain stricter than upstream where they are defensive and do not violate a required server contract.
- No new dependencies are proposed.
