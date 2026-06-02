# Parity: email-otp

| Field | Value |
|-------|-------|
| Upstream | `packages/better-auth/src/plugins/email-otp/` |
| OpenAuth | `crates/openauth-plugins/src/email_otp/` |
| Plugin ID | `email-otp` |
| Tests | **31** OA / **90** BA |
| Global status | 🟡 **Partial** — full routes; test gap on resend/attempts matrices |

Requires `DbAdapter` for verification storage.

---

## Endpoints (11 routes)

| Method | Route | OA | BA | Notes |
|--------|------|:--:|:--:|-------|
| POST | `/email-otp/send-verification-otp` | ✅ | ✅ | |
| POST | `/email-otp/create-verification-otp` | ✅ | ✅ | OA explicit HTTP route |
| GET | `/email-otp/get-verification-otp` | ✅ | ✅ | Server API |
| POST | `/email-otp/check-verification-otp` | ✅ | ✅ | BA docs say GET; impl is POST |
| POST | `/email-otp/verify-email` | ✅ | ✅ | |
| POST | `/sign-in/email-otp` | ✅ | ✅ | |
| POST | `/email-otp/request-password-reset` | ✅ | ✅ | |
| POST | `/forget-password/email-otp` | ✅ | ✅ | Deprecated alias |
| POST | `/email-otp/reset-password` | ✅ | ✅ | |
| POST | `/email-otp/request-email-change` | ✅ | ✅ | |
| POST | `/email-otp/change-email` | ✅ | ✅ | |

---

## Schema / storage

| Aspect | OA | BA |
|---------|:--:|:--:|
| Dedicated plugin table | — | — |
| Verification store (identifier + OTP) | ✅ | ✅ |
| `storeOTP`: plain / hashed / encrypted / custom | ✅ | ✅ |

---

## Hooks

| Hook | OA | BA |
|------|:--:|:--:|
| After `/sign-up/*` when `sendVerificationOnSignUp` | ✅ | ✅ |
| Override `sendVerificationEmail` with `overrideDefaultEmailVerification` | ✅ | ✅ |

---

## Options

| Option | OA | BA | Status |
|--------|:--:|:--:|--------|
| `sendVerificationOTP` callback | ✅ | ✅ | ✅ |
| `expiresIn`, `otpLength` | ✅ | ✅ | ✅ |
| `generateOTP` custom | ✅ | ✅ | ✅ |
| `storeOTP` modes | ✅ | ✅ | ✅ |
| `allowedAttempts` | ✅ | ✅ | 🟡 tests |
| `resend` strategy | ✅ | ✅ | 🟡 tests |
| `overrideDefaultEmailVerification` | ✅ | ✅ | 🟡 tests init |
| `sendVerificationOnSignUp` | ✅ | ✅ | ✅ |

---

## OpenAuth tests

| File | Tests | Focus |
|---------|-------|---------|
| `mod.rs` | 14 | main flows |
| `storage.rs` | 5 | storeOTP modes |
| `server.rs` | 5 | server helpers |
| `callbacks.rs` | 4 | sendVerificationOTP |
| `hooks.rs` | 2 | sign-up hook |
| `additional_fields.rs` | 1 | extra fields |

---

## Upstream scenarios not covered

1. `allowedAttempts` exhaustion per OTP type
2. Resend strategies (cooldown, max resends) full matrix
3. Sign-in vs sign-up matrix per OTP `type`
4. Change-email flow with active session
5. Alias `/forget-password/email-otp` vs canonical route
6. `overrideDefaultEmailVerification` — init path and core email verification interaction

---

## Intentional differences

- Explicit HTTP route for `create-verification-otp` (upstream often only `auth.api.createVerificationOTP` server-side)
- Typed OpenAuth HTTP errors vs `APIError`
