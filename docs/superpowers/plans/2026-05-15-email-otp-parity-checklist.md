# Email OTP Residual Parity Checklist

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this checklist task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close residual server-side parity gaps between OpenAuth `email_otp` and Better Auth upstream.

**Architecture:** Keep the plugin modular under `crates/openauth-plugins/src/email_otp/`, expose only the core callback/helper API needed by multiple routes, and cover each security-sensitive behavior with focused integration tests.

**Tech Stack:** Rust, OpenAuth core/plugin APIs, `MemoryAdapter`, `AuthRouter`, async integration tests.

---

## Checklist

- [x] Revalidate `git status --short --branch` and merge local `main` if it moved.
  - Done: branch `codex/email-otp-plugin` is clean and `HEAD..main = 0` after merge commit `9ad3592`.
- [x] Make `getVerificationOTP` query-first/query-only and reject non-recoverable hashed storage.
  - Done: `GET /email-otp/get-verification-otp?email=...&type=...` no longer accepts JSON body fallback and rejects `Hashed`/`CustomHash` retrieval with `INVALID_OTP`.
- [x] Use rotating secret material for encrypted OTP storage.
  - Done: email OTP storage now uses `context.secret_config`, and `SecretMaterial` implements symmetric `SecretSource`.
- [x] Add typed email verification callbacks to core options and invoke them from core/email OTP verification paths.
  - Done: `before_email_verification`/`after_email_verification` are typed core options and are invoked by core `/verify-email`, email OTP `/verify-email`, and email OTP `/change-email`.
- [x] Add password reset callback and session revocation options to core password options and invoke them from core/email OTP reset paths.
  - Done: `on_password_reset` and `revoke_sessions_on_password_reset` are typed core password options and are invoked by core and email OTP reset flows.
- [x] Ensure `override_default_email_verification` suppresses sign-up OTP hook when both flags are enabled.
  - Done: the sign-up hook is only registered when `send_verification_on_sign_up` is true and `override_default_email_verification` is false.
- [x] Revalidate `change-email` after OTP before mutating email.
  - Done: email OTP change-email rechecks same-email and target-in-use after consuming a valid OTP and before update.
- [x] Return user payloads with configured additional fields in email OTP sign-in/verify/change-email flows.
  - Done: sign-in, verify-email, and change-email use the core user response helper.
- [x] Reuse core additional-field conversion/response helpers instead of plugin-local duplication.
  - Done: plugin-local additional-field conversion was removed in favor of `openauth_core::api::additional_fields`.
- [x] Add missing tests for `getVerificationOTP`, storage, resend, consume/attempts, disable sign-up, callbacks, reset revocation, additional fields, and change-email edge cases.
  - Done: added focused tests under `crates/openauth-plugins/tests/email_otp/`, plus core callback/reset tests.
- [x] Keep source/test files under the existing size threshold by splitting by flow.
  - Done: largest email OTP source/test file is under 500 lines (`tests/email_otp/mod.rs` at 481 lines).
- [x] Run `cargo fmt --check`.
  - Done: passed after final `main` merge.
- [x] Run `cargo clippy -p openauth-core -p openauth-plugins --all-targets -- -D warnings`.
  - Done: passed after final `main` merge.
- [x] Run `cargo test -p openauth-core`.
  - Done: passed after final `main` merge.
- [x] Run `cargo test -p openauth-plugins`.
  - Done: passed after final `main` merge.
- [x] Confirm branch is clean.
  - Done before this checklist status update; this file update will be committed separately.
