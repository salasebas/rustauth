# Parity: two-factor

| Field | Value |
|-------|-------|
| Upstream | `packages/better-auth/src/plugins/two-factor/` |
| OpenAuth | `crates/openauth-plugins/src/two_factor/` |
| Plugin ID | `two-factor` |
| Tests | **21** OA / **55** BA `it()` |
| Global status | 🟡 **Partial** — routes and options aligned; test depth gap |

> Upstream defines `viewBackupCodes` path-less (`backup-codes/index.ts`); OpenAuth exposes `POST /two-factor/view-backup-codes`. OA tests server consumption in `tests/two_factor/mod.rs`. Upstream test: `should not expose viewBackupCodes to client`.

---

## Endpoints

| Method | Route | OA | BA | Notes |
|--------|------|:--:|:--:|-------|
| POST | `/two-factor/enable` | ✅ | ✅ | |
| POST | `/two-factor/disable` | ✅ | ✅ | |
| POST | `/two-factor/get-totp-uri` | ✅ | ✅ | |
| POST | `/two-factor/verify-totp` | ✅ | ✅ | |
| POST | `/two-factor/send-otp` | ✅ | ✅ | |
| POST | `/two-factor/verify-otp` | ✅ | ✅ | |
| POST | `/two-factor/generate-backup-codes` | ✅ | ✅ | |
| POST | `/two-factor/verify-backup-code` | ✅ | ✅ | |
| POST | `/two-factor/generate-totp` | ✅ | ✅ | Path-less upstream → explicit HTTP (Jun 2026) |
| POST | `/two-factor/view-backup-codes` | ✅ | ✅ (path-less) | OA exposes explicit HTTP |

---

## Schema

| Entity | OA | BA |
|---------|:--:|:--:|
| `twoFactor` table (configurable name) | ✅ | ✅ |
| User `twoFactorEnabled` | ✅ | ✅ |

---

## Hooks

| Hook | OA | BA | Status |
|------|:--:|:--:|--------|
| After `/sign-in/email` → 2FA challenge | ✅ | ✅ | ✅ |
| After `/sign-in/username` | ✅ | ✅ | ✅ |
| After `/sign-in/phone-number` | ✅ | ✅ | ✅ |
| Trust-device cookie | ✅ | ✅ | 🟡 tests |
| Rate limit `/two-factor/*` | ✅ | ✅ | ✅ |

---

## Options

| Option | OA | BA |
|--------|:--:|:--:|
| `skipVerificationOnEnable` | ✅ | ✅ |
| `allowPasswordless` | ✅ | ✅ |
| `trustDeviceMaxAge` | ✅ | ✅ |
| TOTP issuer, digits, period | ✅ | ✅ |
| OTP length, expires | ✅ | ✅ |
| Backup codes count | ✅ | ✅ |
| Custom OTP `hash` / `encrypt`+`decrypt` (`OtpStorage::CustomHash`, `CustomEncrypt`) | ✅ | ✅ Jun 2026 |

---

## OpenAuth tests

| File | Tests | Focus |
|---------|-------|---------|
| `mod.rs` | 21 | enable/disable, TOTP, OTP, backup, sign-in interrupt |

---

## Upstream scenarios not covered

1. Trust-device cookie rotation cycle
2. OTP `allowedAttempts` exhaustion
3. `allowPasswordless` enable/disable matrix
4. Backup verify with `disableSession`
5. Cross-plugin: sign-in phone-number + 2FA interrupt
6. `skipVerificationOnEnable` edge cases
7. `should not expose viewBackupCodes to client` — no dedicated OA test

---

## Intentional differences

| Topic | Detail |
|------|---------|
| `generateTOTP` | OpenAuth: `POST /two-factor/generate-totp` (upstream path-less server API) |
| TOTP in tests | Rust `totp_code` helper vs `@better-auth/utils/otp` |
