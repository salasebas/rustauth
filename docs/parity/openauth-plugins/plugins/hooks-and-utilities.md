# Parity: hooks and utilities

Plugins without their own HTTP routes or with an auxiliary role: **access**, **additional-fields**, **bearer**, **captcha**, **custom-session**, **haveibeenpwned**, **last-login-method**, **multi-session**, **oauth-proxy**, **one-time-token**, **open-api**.

---

## access

| Field | Value |
|-------|-------|
| Type | RBAC utility (not `AuthPlugin`) |
| Tests | **24** OA / **7** BA |
| Status | ✅ **Full** (+ more OA tests) |

**API:** `create_access_control`, `role`, `request`, `statements`  
**Use:** admin, organization permissions  
**Note:** OpenAuth has a more extensive RBAC test suite than upstream

---

## additional-fields

| Field | Value |
|-------|-------|
| Type | Schema contribution |
| Tests | **3** OA / **12** BA |
| Status | 🎯 **Intentional** |

| Aspect | Upstream | OpenAuth |
|---------|----------|----------|
| Server plugin | No (only `client.ts`) | Yes — `additional_fields()` |
| Purpose | TS type inference | DB schema + runtime validation |

**Options:** `user`/`session` field map — type, required, unique, index, default, `db_name`

---

## bearer

| Field | Value |
|-------|-------|
| Tests | **16** OA / **6** BA |
| Status | ✅ **Full** |

**Behavior:**
- Request: `Authorization: Bearer` → session cookie
- Response: `set-auth-token` header  
**Option:** `requireSignature` (default false)

---

## captcha

| Field | Value |
|-------|-------|
| Tests | **19** OA / **22** BA |
| Status | ✅ **Full** |

**Async middleware** on configured paths (default: sign-up/sign-in/reset email)  
**Header:** `x-captcha-response`  
**Providers:** Cloudflare Turnstile, Google reCAPTCHA, hCaptcha, CaptchaFox

---

## custom-session

| Field | Value |
|-------|-------|
| Tests | **18** OA / **12** BA |
| Status | ✅ **Full** |

**After hook on `/get-session`** — enriches response via callback  
**Optional:** mutate `/multi-session/list-device-sessions`  
**Option:** `shouldMutateListDeviceSessionsEndpoint`

---

## haveibeenpwned

| Field | Value |
|-------|-------|
| Tests | **12** OA / **6** BA |
| Status | ✅ **Full** |

**Password validator** on configured paths (default: sign-up, change/reset password)  
**Runtime plugin ID:** `have-i-been-pwned` vs upstream `haveibeenpwned`  
**Options:** `enabled`, `paths`, `customPasswordCompromisedMessage`

---

## last-login-method

| Field | Value |
|-------|-------|
| Tests | **20** OA / **23** BA |
| Status | ✅ **Full** |

**After hook on `*`** — cookie + optional DB field `last_login_method`  
**Options:** `cookieName`, `maxAge`, `customResolveMethod`, `storeInDatabase`

---

## multi-session

| Field | Value |
|-------|-------|
| Tests | **22** OA / **10** BA |
| Status | ✅ **Full** (SERVER_PARITY.md) |

| Method | Route |
|--------|------|
| GET | `/multi-session/list-device-sessions` |
| POST | `/multi-session/set-active` |
| POST | `/multi-session/revoke` |

**Hooks:** after `*` (multi-session cookies); after `/sign-out`  
**Option:** `maximumSessions` (default 5)  
**SERVER_PARITY:** signed cookies, active switch, revocation, max limit, forged rejection

---

## oauth-proxy

| Field | Value |
|-------|-------|
| Tests | **24** OA / **21** BA |
| Status | ✅ **Full** (SERVER_PARITY.md) |

| Method | Route |
|--------|------|
| GET | `/oauth-proxy-callback` |

**Hooks:** before/after social + oauth2 callbacks  
**SERVER_PARITY:** callback rewrite, encrypted preview, replay max-age, production passthrough, skip headers, DB state

---

## one-time-token

| Field | Value |
|-------|-------|
| Tests | **15** OA / **20** BA |
| Status | ✅ **Full** (SERVER_PARITY.md) |

| Method | Route |
|--------|------|
| GET | `/one-time-token/generate` |
| POST | `/one-time-token/verify` |

**Options:** `expiresIn`, `disableClientRequest`, `generateToken`, `storeToken`, `disableSetSessionCookie`, `setOttHeaderOnNewSession`  
**SERVER_PARITY:** verify output, cookie cache, expired session rejection, refresh cookies on generate

---

## open-api

| Field | Value |
|-------|-------|
| Tests | **9** OA / **10** BA |
| Status | ✅ **Full** |

| Method | Route |
|--------|------|
| GET | `/open-api/generate-schema` |
| GET | `{path}` default `/reference` |

**UI:** Scalar reference  
**Options:** `path`, `disableDefaultReference`, `theme`, `nonce`

---

## Summary

| Plugin | Routes | Mechanism | Tests OA/BA | Status |
|--------|:-----:|-----------|:-----------:|:------:|
| access | ➖ | RBAC lib | 24/7 | ✅ |
| additional-fields | ➖ | Schema init | 3/12 | 🎯 |
| bearer | ➖ | onRequest/onResponse | 16/6 | ✅ |
| captcha | ➖ | middleware | 19/22 | ✅ |
| custom-session | ➖ | after hook | 18/12 | ✅ |
| haveibeenpwned | ➖ | password validator | 12/6 | ✅ |
| last-login-method | ➖ | after hook | 20/23 | ✅ |
| multi-session | 3 | hooks + routes | 22/10 | ✅ |
| oauth-proxy | 1 | hooks + route | 24/21 | ✅ |
| one-time-token | 2 | hooks + routes | 15/20 | ✅ |
| open-api | 2 | routes | 9/10 | ✅ |
