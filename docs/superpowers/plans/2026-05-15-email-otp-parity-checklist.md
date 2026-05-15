# Email OTP Residual Parity Checklist

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this checklist task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close residual server-side parity gaps between OpenAuth `email_otp` and Better Auth upstream.

**Architecture:** Keep the plugin modular under `crates/openauth-plugins/src/email_otp/`, expose only the core callback/helper API needed by multiple routes, and cover each security-sensitive behavior with focused integration tests.

**Tech Stack:** Rust, OpenAuth core/plugin APIs, `MemoryAdapter`, `AuthRouter`, async integration tests.

---

## Checklist

- [ ] Revalidate `git status --short --branch` and merge local `main` if it moved.
- [ ] Make `getVerificationOTP` query-first/query-only and reject non-recoverable hashed storage.
- [ ] Use rotating secret material for encrypted OTP storage.
- [ ] Add typed email verification callbacks to core options and invoke them from core/email OTP verification paths.
- [ ] Add password reset callback and session revocation options to core password options and invoke them from core/email OTP reset paths.
- [ ] Ensure `override_default_email_verification` suppresses sign-up OTP hook when both flags are enabled.
- [ ] Revalidate `change-email` after OTP before mutating email.
- [ ] Return user payloads with configured additional fields in email OTP sign-in/verify/change-email flows.
- [ ] Reuse core additional-field conversion/response helpers instead of plugin-local duplication.
- [ ] Add missing tests for `getVerificationOTP`, storage, resend, consume/attempts, disable sign-up, callbacks, reset revocation, additional fields, and change-email edge cases.
- [ ] Keep source/test files under the existing size threshold by splitting by flow.
- [ ] Run `cargo fmt --check`.
- [ ] Run `cargo clippy -p openauth-core -p openauth-plugins --all-targets -- -D warnings`.
- [ ] Run `cargo test -p openauth-core`.
- [ ] Run `cargo test -p openauth-plugins`.
- [ ] Confirm branch is clean.
