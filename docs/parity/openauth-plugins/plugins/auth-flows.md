# Parity: authentication flows

Grouped plugins: **anonymous**, **magic-link**, **username**, **siwe**, **one-tap**, **device-authorization**.

---

## anonymous

| Field | Value |
|-------|-------|
| Tests | **18** OA / **14** BA |
| Status | ✅ **Full** |

| Method | Route | OA | BA |
|--------|------|:--:|:--:|
| POST | `/sign-in/anonymous` | ✅ | ✅ |
| POST | `/delete-anonymous-user` | ✅ | ✅ |

**Schema:** `user.isAnonymous`  
**Hooks:** after on sign-in/sign-up/callback/magic-link/otp/one-tap/passkey/phone — link anonymous → real user  
**OA tests:** `endpoints.rs` (15), `hooks.rs` (3)

---

## magic-link

| Field | Value |
|-------|-------|
| Tests | **27** OA / **23** BA |
| Status | ✅ **Full** |

| Method | Route | OA | BA |
|--------|------|:--:|:--:|
| POST | `/sign-in/magic-link` | ✅ | ✅ |
| GET | `/magic-link/verify` | ✅ | ✅ |

**Options:** `sendMagicLink`, `expiresIn`, `allowedAttempts`, `disableSignUp`, rate limit  
**Notable tests:** `upstream_parity.rs` (13 named BA scenarios)  
**OA tests:** mod, failure_redirects, rate_limit, token_generation

---

## username

| Field | Value |
|-------|-------|
| Tests | **12** OA / **39** BA |
| Status | 🟡 **Partial** (tests) |

| Method | Route | OA | BA |
|--------|------|:--:|:--:|
| POST | `/sign-in/username` | ✅ | ✅ |
| POST | `/is-username-available` | ✅ | ✅ |

**Schema:** `user.username`, `user.displayUsername` — schema rename options ✅ Jun 2026  
**Hooks:** DB normalize on create/update; before sign-up/update-user  
**Test gap:** length validation, special characters, displayUsername normalization

---

## siwe

| Field | Value |
|-------|-------|
| Tests | **25** OA / **18** BA |
| Status | ✅ **Full** |

| Method | Route | OA | BA |
|--------|------|:--:|:--:|
| POST | `/siwe/nonce` | ✅ | ✅ |
| POST | `/siwe/verify` | ✅ | ✅ |

**Schema:** `wallet_addresses` table  
**Options:** `domain`, `getNonce`, `verifyMessage`, `ensLookup`, `anonymous`  
**OA tests:** mod, nonce, verify, address, schema, accounts

---

## one-tap

| Field | Value |
|-------|-------|
| Tests | **14** OA / **0** BA |
| Status | 🎯 **Intentional** (error shape) |

| Method | Route | OA | BA |
|--------|------|:--:|:--:|
| POST | `/one-tap/callback` | ✅ | ✅ |

**Client-only upstream:** `oneTapClient()` — Google One Tap UI hooks (N/A server)  
**Intentional difference:**

| Case | Upstream | OpenAuth |
|------|----------|----------|
| Email unavailable | `200 { error }` | `400 EMAIL_NOT_AVAILABLE` |

**SERVER_PARITY.md:** implicit linking requires `trusted_providers` for unverified providers.

---

## device-authorization

| Field | Value |
|-------|-------|
| Tests | **36** OA / **41** BA |
| Status | 🟡 **Partial** (near full) |

| Method | Route | OA | BA |
|--------|------|:--:|:--:|
| POST | `/device/code` | ✅ | ✅ |
| POST | `/device/token` | ✅ | ✅ |
| GET | `/device` | ✅ | ✅ |
| POST | `/device/approve` | ✅ | ✅ |
| POST | `/device/deny` | ✅ | ✅ |

**Schema:** `device_codes` table  
**OA tests:** code, token, verify, decision, options, schema (6 files)  
**Minor gap:** polling interval edge cases, expired code matrix

---

## Comparative summary

| Plugin | Routes | Schema | Hooks | Test ratio | Status |
|--------|:-----:|:------:|:-----:|:-----------:|:------:|
| anonymous | ✅ | ✅ | ✅ | 1.3x OA | ✅ |
| magic-link | ✅ | ✅ | 🟡 | 1.2x OA | ✅ |
| username | ✅ | ✅ | ✅ | 0.31x OA | 🟡 |
| siwe | ✅ | ✅ | ➖ | 1.4x OA | ✅ |
| one-tap | ✅ | ➖ | ➖ | OA only | 🎯 |
| device-authorization | ✅ | ✅ | ✅ | 0.88x | 🟡 |
