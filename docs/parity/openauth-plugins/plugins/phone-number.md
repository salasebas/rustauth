# Parity: phone-number

| Field | Value |
|-------|-------|
| Upstream | `packages/better-auth/src/plugins/phone-number/` |
| OpenAuth | `crates/openauth-plugins/src/phone_number/` |
| Plugin ID | `phone-number` |
| Tests | **22** OA / **47** BA |
| Global status | 🟡 **Partial** — full routes; test gap on sign-up-on-verify |

Requires `DbAdapter`.

---

## Endpoints (5 routes)

| Method | Route | OA | BA |
|--------|------|:--:|:--:|
| POST | `/sign-in/phone-number` | ✅ | ✅ |
| POST | `/phone-number/send-otp` | ✅ | ✅ |
| POST | `/phone-number/verify` | ✅ | ✅ |
| POST | `/phone-number/request-password-reset` | ✅ | ✅ |
| POST | `/phone-number/reset-password` | ✅ | ✅ |

---

## Schema

| User field | OA | BA |
|------------|:--:|:--:|
| `phoneNumber` | ✅ | ✅ |
| `phoneNumberVerified` | ✅ | ✅ |
| Schema rename options | ✅ | ✅ Jun 2026 |

---

## Hooks

| Hook | OA | BA |
|------|:--:|:--:|
| Before `/update-user` — protect phone | ✅ | ✅ |
| DB hook — reset verified when clearing phone | ✅ | ✅ |
| Rate limit `/phone-number/*` | ✅ | ✅ |

---

## Options

| Option | OA | BA | Status |
|--------|:--:|:--:|--------|
| `sendOTP` callback | ✅ | ✅ | ✅ |
| `verifyOTP` / verifier | ✅ | ✅ | ✅ |
| `signUpOnVerification` | ✅ | ✅ | 🟡 tests |
| `requireVerification` | ✅ | ✅ | 🟡 tests |
| `callbackURL` | ✅ | ✅ | ✅ |

---

## OpenAuth tests

| File | Tests | Focus |
|---------|-------|---------|
| `mod.rs` | 14 | sign-in, verify, reset |
| `edge_cases.rs` | 8 | update-user guard, edge cases |

---

## Upstream scenarios not covered

1. `signUpOnVerification` — combinations with existing user
2. `phoneNumberExists` error paths
3. Password reset OTP expiry
4. Verify + full session cookie
5. Sign-in without prior verify

---

## Cross-plugin integration

| Plugin | Integration |
|--------|-------------|
| anonymous | Link hook includes `/phone-number/verify*` |
| two-factor | After hook on `/sign-in/phone-number` |
