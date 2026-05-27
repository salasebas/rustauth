# two_factor + username Upstream Parity Audit Plan

## Summary

This audit compares OpenAuth's server-side `two_factor` and `username` plugin behavior against Better Auth 1.6.9. The implementation should preserve OpenAuth's Rust-native structure while closing high-confidence parity gaps in authentication state, verification boundaries, and observable response behavior.

## Upstream Files Inspected

- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/username/index.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/username/schema.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/username/error-codes.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/username/client.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/username/username.test.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/two-factor/index.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/two-factor/types.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/two-factor/schema.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/two-factor/error-code.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/two-factor/constant.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/two-factor/verify-two-factor.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/two-factor/totp/index.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/two-factor/otp/index.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/two-factor/backup-codes/index.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/two-factor/two-factor.test.ts`

## OpenAuth Files Inspected

- `crates/openauth-plugins/src/username/{mod.rs,endpoints.rs,hooks.rs,options.rs,schema.rs,errors.rs}`
- `crates/openauth-plugins/tests/username/{mod.rs,flow.rs,schema.rs,validation.rs}`
- `crates/openauth-plugins/src/two_factor/**`
- `crates/openauth-plugins/tests/two_factor/{mod.rs,helpers.rs}`
- `crates/openauth-core/src/api/routes/{sign_up.rs,update_user.rs,email_verification.rs}`
- `crates/openauth-core/src/api/services/email_password.rs`
- `crates/openauth-core/src/auth/email_password.rs`
- `crates/openauth-core/src/options/{email_password.rs,email_verification.rs}`
- `crates/openauth-core/src/cookies/session.rs`

## Confirmed Matches

- `username` registers the expected plugin id, error codes, schema fields, default lowercase normalization, default validation characters, sign-up fallback between `username` and `displayUsername`, normalized duplicate checks, normalized availability checks, and generic credential failure responses.
- `two_factor` registers the expected plugin id, user and two-factor schema, error codes, TOTP enrollment, verified-row lifecycle, OTP generation and verification, backup-code consumption, trusted-device rotation, custom table name support, passwordless policy, and rate limit surface.
- OpenAuth intentionally uses snake_case database fields and Rust structs while preserving public JSON names such as `totpURI`, `backupCodes`, `twoFactorRedirect`, `twoFactorMethods`, `rememberMe`, `trustDevice`, and `disableSession`.

## Confirmed Differences

- `/sign-in/username` does not parse `callbackURL` and does not enforce `email_password.require_email_verification` after successful password verification.
- `two_factor` only registers its sign-in after-hook for `/sign-in/email`; upstream also challenges `/sign-in/username` and `/sign-in/phone-number`.
- The 2FA challenge deletes the session cookie while preserving `dont_remember`, but verification does not read that retained cookie to recreate a non-persistent session for `rememberMe: false` sign-ins.
- Backup code generation splits custom-length codes at `length / 2`; upstream always inserts the dash after the first five characters.

## Risks

- Username email-verification handling must not leak account state: wrong passwords must remain `INVALID_USERNAME_OR_PASSWORD`, while `EMAIL_NOT_VERIFIED` is returned only after a correct password.
- Two-factor after-hooks must stay limited to credential-like sign-in routes and must not challenge magic-link, email-OTP, OAuth, or unrelated authenticated endpoints.
- Preserving `rememberMe: false` through 2FA depends on keeping the `dont_remember` cookie during the challenge and expiring it only after trusted-device success, matching the upstream flow.
- Backup-code formatting changes the visible format for non-default lengths, so tests should lock down the intended upstream-compatible shape.

## Proposed Fixes

- Extend `SignInUsernameBody` to accept `callbackURL`/`callback_url`.
- Add username sign-in email-verification gating after password verification and before session creation. When `send_on_sign_in` is enabled and a sender exists, generate a verification token using the same claim shape as core email verification and call the configured sender.
- Register the two-factor async after-hook for `/sign-in/username` and `/sign-in/phone-number`.
- In `verify_context`, read the retained signed `dont_remember` cookie and carry it through `VerifyFlow`; in `VerifyFlow::valid`, use short session expiry and non-persistent session cookies when it is set.
- Split generated backup codes after five characters, matching Better Auth.

## Tests To Add Or Update

- Username sign-in returns `INVALID_USERNAME_OR_PASSWORD` for a wrong password on an unverified account.
- Username sign-in returns `EMAIL_NOT_VERIFIED` for a correct password on an unverified account.
- Username sign-in invokes the configured verification email sender when `send_on_sign_in` is enabled.
- Two-factor challenges `/sign-in/username` after TOTP is enrolled and verified.
- Two-factor preserves non-persistent session behavior after a `rememberMe: false` sign-in completes 2FA.
- Backup codes with custom length 8 are formatted as `xxxxx-xxx`.

## Intentionally Left Unchanged

- No new dependencies.
- No custom OTP or backup-code crypto extension APIs in this pass.
- Existing Rust-native field names, strong types, explicit errors, and module boundaries remain.
- Rust OTP sender failures stay explicit instead of being swallowed in the background.
- Full workspace verification is not planned unless implementation crosses crate boundaries.
