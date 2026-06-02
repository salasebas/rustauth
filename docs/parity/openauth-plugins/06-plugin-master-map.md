# Master map: 26 server-side plugins

Complete reference **OpenAuth `openauth-plugins`** vs Better Auth **v1.6.9**.  
Typical base path: `/api/auth`.

**Status legend**

| Status | Meaning |
|--------|---------|
| ✅ | Server parity verified in code |
| 🟡 | Routes OK; gap in tests or minor options |
| ➖ | No HTTP routes (utility / middleware) |
| 🎯 | Intentional difference (Rust / explicit HTTP) |

---

## Numeric summary

| Metric | Count |
|---------|:--------:|
| Plugins in scope (`PLUGIN_IDS`) | **26** |
| Replaced outside crate (`oidc-provider`) | **1** → `openauth-oauth-provider` |
| **With HTTP routes** | **20** |
| **Without routes** (utility / hooks) | **6** |
| Total HTTP routes OpenAuth | **~119** |
| Path-less upstream APIs without HTTP equivalent | **0** (closed: `POST /two-factor/generate-totp`) |
| Plugins ✅ routes + core | **20** |
| Plugins 🟡 (documented test gap) | **6** |
| Plugins ➖ no routes | **6** |

### What is still “missing”?

| Type of gap | Count |
|-----------------|:--------:|
| **Plugins with real server functional gap** | **0** |
| **Unported upstream server-only APIs** | **0** |
| **Plugins with test-only gap** (routes/schema/core options OK) | **8** |
| **Plugins complete for server** (no relevant functional gap) | **17** |
| **OpenAuth extensions** (not upstream) | api-key revalidate/defer; 2FA hardcoded rate limit; MCP userinfo/jwks handlers |

---

## Quick index

| # | Plugin | Routes | Schema | Hooks | Status |
|---|--------|:-----:|:------:|:-----:|:------:|
| 1 | [access](#1-access) | ➖ | ➖ | ➖ | ✅ |
| 2 | [additional-fields](#2-additional-fields) | ➖ | ✅ | init | 🎯 |
| 3 | [admin](#3-admin) | 15 | ✅ | ✅ | 🟡 tests |
| 4 | [anonymous](#4-anonymous) | 2 | ✅ | ✅ | ✅ |
| 5 | [api-key](#5-api-key) | 7 | ✅ | ✅ | 🟡 tests |
| 6 | [bearer](#6-bearer) | ➖ | ➖ | ✅ | ✅ |
| 7 | [captcha](#7-captcha) | ➖ | ➖ | ✅ | ✅ |
| 8 | [custom-session](#8-custom-session) | ➖ | ➖ | ✅ | ✅ |
| 9 | [device-authorization](#9-device-authorization) | 5 | ✅ | init | ✅ |
| 10 | [email-otp](#10-email-otp) | 11 | ➖ | ✅ | 🟡 tests |
| 11 | [generic-oauth](#11-generic-oauth) | 3 | ➖ | init | 🟡 tests |
| 12 | [haveibeenpwned](#12-haveibeenpwned) | ➖ | ➖ | ✅ | ✅ |
| 13 | [jwt](#13-jwt) | 4 | ✅ | ✅ | 🎯 |
| 14 | [last-login-method](#14-last-login-method) | ➖ | opt | ✅ | ✅ |
| 15 | [magic-link](#15-magic-link) | 2 | ➖ | rate | ✅ |
| 16 | [mcp](#16-mcp) | 9 | ✅ | ✅ | 🎯 |
| 17 | [multi-session](#17-multi-session) | 3 | ➖ | ✅ | ✅ |
| 18 | [oauth-proxy](#18-oauth-proxy) | 1 | ➖ | ✅ | ✅ |
| 19 | [one-tap](#19-one-tap) | 1 | ➖ | ➖ | 🎯 |
| 20 | [one-time-token](#20-one-time-token) | 2 | ➖ | ✅ | ✅ |
| 21 | [open-api](#21-open-api) | 2 | ➖ | ➖ | ✅ |
| 22 | [organization](#22-organization) | 36 | ✅ | callbacks | 🟡 tests |
| 23 | [phone-number](#23-phone-number) | 5 | ✅ | ✅ | 🟡 tests |
| 24 | [siwe](#24-siwe) | 2 | ✅ | ➖ | ✅ |
| 25 | [two-factor](#25-two-factor) | 10 | ✅ | partial | 🟡 tests |
| 26 | [username](#26-username) | 2 | ✅ | ✅ | 🟡 tests |

Extended detail: [plugins/](./plugins/) and [05-third-pass-audit.md](./05-third-pass-audit.md).

---

## 1. access

| Area | Detail |
|------|---------|
| **Plugin ID** | `access` |
| **AuthPlugin** | ➖ No (RBAC utility) |
| **Endpoints** | — |
| **Schema** | — |
| **Hooks** | — |
| **Exports** | `create_access_control`, `role`, `request`, `authorize` |
| **Tests** | OA 24 / UP 6 |
| **Status** | ✅ |

---

## 2. additional-fields

| Area | Detail |
|------|---------|
| **Plugin ID** | `additional-fields` |
| **Endpoints** | — |
| **Schema** | `user` / `session` fields via `PluginSchemaContribution` |
| **Hooks** | `init` — registers schema + runtime fields |
| **Upstream** | TS client only; OA is server schema plugin |
| **Tests** | OA 3 / UP 10 |
| **Status** | 🎯 Intentional |

---

## 3. admin

| Method | Route |
|--------|------|
| POST | `/admin/set-role` |
| GET | `/admin/get-user` |
| POST | `/admin/create-user` |
| POST | `/admin/update-user` |
| GET | `/admin/list-users` |
| POST | `/admin/list-user-sessions` |
| POST | `/admin/ban-user` |
| POST | `/admin/unban-user` |
| POST | `/admin/impersonate-user` |
| POST | `/admin/stop-impersonating` |
| POST | `/admin/revoke-user-session` |
| POST | `/admin/revoke-user-sessions` |
| POST | `/admin/remove-user` |
| POST | `/admin/set-user-password` |
| POST | `/admin/has-permission` |

| Schema (user) | `role`, `banned`, `ban_reason`, `ban_expires` |
| Schema (session) | `impersonated_by` |
| **Hooks** | `init`; DB default role; block banned session; **`after /list-sessions`** filter impersonated |
| **Options** | `AdminOptions`, `AdminSchemaOptions`, `roles`, `admin_user_ids`, … |
| **Tests** | OA 29 / UP 71 |
| **Gap** | list-users/impersonation test depth; OpenAPI audit excludes admin |
| **Status** | 🟡 |

---

## 4. anonymous

| Method | Route |
|--------|------|
| POST | `/sign-in/anonymous` |
| POST | `/delete-anonymous-user` |

| Schema | `user.is_anonymous` |
| **Hooks** | After on sign-in/sign-up/callback/oauth/magic-link/otp/one-tap/phone (+ passkey matcher) |
| **Tests** | OA 18 / UP 12 |
| **Status** | ✅ |

---

## 5. api-key

| Method | Route | Notes |
|--------|------|-------|
| POST | `/api-key/create` | |
| POST | `/api-key/verify` | 🎯 upstream path-less |
| GET | `/api-key/get` | |
| POST | `/api-key/update` | |
| POST | `/api-key/delete` | |
| GET | `/api-key/list` | |
| POST | `/api-key/delete-all-expired-api-keys` | 🎯 upstream path-less |

| Schema | Table `api_keys` (model `api_key`): prefix, key hash, config_id, rate limits, permissions, metadata, … |
| **Hooks** | `async_before *` → session from API key header |
| **Options** | ✅ `defaultPermissions` callback; schema merge at build (Jun 2026) |
| **OA extensions** | `revalidate_secondary_against_database`, `defer_updates` |
| **Tests** | OA 52 / UP 176 |
| **Status** | 🟡 tests |

---

## 6. bearer

| Endpoints | — |
| **Hooks** | `on_request` (Bearer → cookie); `on_response` (`set-auth-token` header) |
| **Options** | `require_signature` |
| **Tests** | OA 16 / UP 5 |
| **Status** | ✅ |

---

## 7. captcha

| Endpoints | — (middleware) |
| **Hooks** | `async_middleware *` on configured paths; header `x-captcha-response` |
| **Providers** | Turnstile, reCAPTCHA, hCaptcha, CaptchaFox |
| **Default paths** | `/sign-up/email`, `/sign-in/email`, `/request-password-reset` |
| **Tests** | OA 19 / UP 17 |
| **Status** | ✅ |

---

## 8. custom-session

| Endpoints | — |
| **Hooks** | `after /get-session` (enriches JSON); optional `after /multi-session/list-device-sessions` |
| **Note** | Does not override GET `/get-session` handler |
| **Tests** | OA 18 / UP 11 |
| **Status** | ✅ |

---

## 9. device-authorization

| Method | Route |
|--------|------|
| POST | `/device/code` |
| GET | `/device` |
| POST | `/device/token` |
| POST | `/device/approve` |
| POST | `/device/deny` |

| Schema | Table `device_codes` |
| **Hooks** | `init` |
| **Tests** | OA 36 / UP 31 |
| **Status** | ✅ |

---

## 10. email-otp

| Method | Route |
|--------|------|
| POST | `/email-otp/send-verification-otp` |
| POST | `/email-otp/create-verification-otp` |
| GET | `/email-otp/get-verification-otp` |
| POST | `/email-otp/check-verification-otp` |
| POST | `/email-otp/verify-email` |
| POST | `/sign-in/email-otp` |
| POST | `/email-otp/request-password-reset` |
| POST | `/forget-password/email-otp` |
| POST | `/email-otp/reset-password` |
| POST | `/email-otp/request-email-change` |
| POST | `/email-otp/change-email` |

| Schema | Uses core `verification` store |
| **Hooks** | Optional after `/sign-up/email`, `/send-verification-email` |
| **Rate limit** | All registry paths; default 60s/3 |
| **Tests** | OA 31 / UP 73 |
| **Status** | 🟡 tests |

---

## 11. generic-oauth

| Method | Route |
|--------|------|
| POST | `/sign-in/oauth2` |
| GET | `/oauth2/callback/:providerId` |
| POST | `/oauth2/link` |

| Schema | — (core `account`) |
| **Hooks** | `init` providers |
| **`storeIdentifier: hashed`** | ✅ via **openauth-core** `verification.store_identifier` |
| **Tests** | OA 41 / UP 59 |
| **Status** | 🟡 tests |

---

## 12. haveibeenpwned

| Endpoints | — |
| **Hooks** | `password_validator` on sign-up/change/reset password |
| **Runtime ID** | `have-i-been-pwned` |
| **Tests** | OA 12 / UP 4 |
| **Status** | ✅ |

---

## 13. jwt

| Method | Route |
|--------|------|
| GET | `{jwks_path}` default `/jwks` |
| GET | `/token` |
| POST | `/sign-jwt` |
| POST | `/verify-jwt` |

| Schema | Table `jwks` |
| **Hooks** | `after /get-session` → header `set-auth-jwt` |
| **Schema options** | ✅ Jun 2026 |
| **Tests** | OA 33 / UP 36 |
| **Status** | 🎯 HTTP sign/verify |

---

## 14. last-login-method

| Endpoints | — |
| **Schema** | Optional `user.last_login_method` |
| **Hooks** | `init`; `after *` cookie + DB |
| **Tests** | OA 20 / UP 21 |
| **Status** | ✅ |

---

## 15. magic-link

| Method | Route |
|--------|------|
| POST | `/sign-in/magic-link` |
| GET | `/magic-link/verify` |

| **Rate limit** | Both routes |
| **Tests** | OA 27 / UP 18 |
| **Status** | ✅ |

---

## 16. mcp

| Method | Route |
|--------|------|
| GET | `/.well-known/oauth-authorization-server` |
| GET | `/.well-known/oauth-protected-resource` |
| GET | `/mcp/authorize` |
| POST | `/mcp/register` |
| POST | `/oauth2/consent` |
| POST | `/mcp/token` |
| GET | `/mcp/userinfo` |
| GET | `/mcp/jwks` |
| GET | `/mcp/get-session` |

| Schema | `oauth_applications`, oauth access tokens, oauth consents |
| **Hooks** | `after *` resume OAuth post-login |
| **Gap upstream** | userinfo/jwks metadata without handler; OA implements |
| **Tests** | OA 30 / UP 36 |
| **Status** | 🎯 |

---

## 17. multi-session

| Method | Route |
|--------|------|
| GET | `/multi-session/list-device-sessions` |
| POST | `/multi-session/set-active` |
| POST | `/multi-session/revoke` |

| **Hooks** | `after *` cookies; `after /sign-out` revoke |
| **Tests** | OA 22 / UP 9 |
| **Status** | ✅ |

---

## 18. oauth-proxy

| Method | Route |
|--------|------|
| GET | `/oauth-proxy-callback` |

| **Hooks** | before/after social + oauth2 + callback |
| **Tests** | OA 24 / UP 18 |
| **Status** | ✅ |

---

## 19. one-tap

| Method | Route |
|--------|------|
| POST | `/one-tap/callback` |

| **Gap** | 🎯 error `400 EMAIL_NOT_AVAILABLE` vs upstream `200 {error}` |
| **Tests** | OA 14 / UP **0** |
| **Status** | 🎯 |

---

## 20. one-time-token

| Method | Route |
|--------|------|
| GET | `/one-time-token/generate` |
| POST | `/one-time-token/verify` |

| **Hooks** | `after *` OTT header on new session |
| **Tests** | OA 15 / UP 13 |
| **Status** | ✅ |

---

## 21. open-api

| Method | Route |
|--------|------|
| GET | `/open-api/generate-schema` |
| GET | `{path}` default `/reference` |

| **Tests** | OA 9 / UP 9 (+ audit 80+ paths) |
| **Status** | ✅ |

---

## 22. organization

**36 routes** — see [plugins/organization.md](./plugins/organization.md).

| Schema tables | `organizations`, `members`, `invitations`, optional `teams`, `team_members`, `organization_roles` |
| Session fields | `activeOrganizationId`, `activeTeamId` |
| **Hooks** | 28 sync callbacks in `OrganizationHooks` (not AuthPlugin path hooks) |
| **Options** | ✅ `ac`, async limits, `customCreateDefaultTeam` (Jun 2026) |
| **Tests** | OA 32 / UP 182 |
| **Status** | 🟡 tests |

---

## 23. phone-number

| Method | Route |
|--------|------|
| POST | `/sign-in/phone-number` |
| POST | `/phone-number/send-otp` |
| POST | `/phone-number/verify` |
| POST | `/phone-number/request-password-reset` |
| POST | `/phone-number/reset-password` |

| Schema | `phone_number`, `phone_number_verified` |
| **Hooks** | `before /update-user`; DB hook clear verified |
| **Rate limit** | `/phone-number/*` 60s/10 (hardcoded) |
| **Schema options** | ✅ Jun 2026 |
| **Tests** | OA 22 / UP 32 |
| **Status** | 🟡 tests |

---

## 24. siwe

| Method | Route |
|--------|------|
| POST | `/siwe/nonce` |
| POST | `/siwe/verify` |

| Schema | `wallet_addresses` |
| **Tests** | OA 25 / UP 17 |
| **Status** | ✅ |

---

## 25. two-factor

| Method | Route |
|--------|------|
| POST | `/two-factor/enable` |
| POST | `/two-factor/disable` |
| POST | `/two-factor/get-totp-uri` |
| POST | `/two-factor/verify-totp` |
| POST | `/two-factor/send-otp` |
| POST | `/two-factor/verify-otp` |
| POST | `/two-factor/generate-backup-codes` |
| POST | `/two-factor/verify-backup-code` |
| POST | `/two-factor/generate-totp` |
| POST | `/two-factor/view-backup-codes` |

| Schema | Table `twoFactor`; user `two_factor_enabled` |
| **Hooks** | After sign-in email/username/phone |
| **Options** | ✅ custom OTP storage hooks (Jun 2026) |
| **Tests** | OA 21 / UP 55 |
| **Status** | 🟡 tests |

---

## 26. username

| Method | Route |
|--------|------|
| POST | `/sign-in/username` |
| POST | `/is-username-available` |

| Schema | `username`, `display_username` |
| **Hooks** | before sign-up/update; DB normalize |
| **Schema options** | ✅ Jun 2026 |
| **Tests** | OA 12 / UP 33 |
| **Status** | 🟡 tests |

---

## Out of scope

| Plugin | Destination |
|--------|---------|
| `oidc-provider` | `openauth-oauth-provider` |
| `test-utils` | Not ported |

---

## Closure checklist

| # | Item | Plugin | Status |
|---|------|--------|--------|
| 1 | `generateTOTP` server API (`POST /two-factor/generate-totp`) | two-factor | ✅ |
| 2 | `ac: AccessControl` injectable + `roles` | organization | ✅ |
| 3 | Async limits (`organizationLimit`, `membershipLimit`) | organization | ✅ |
| 4 | `customCreateDefaultTeam` | organization | ✅ |
| 5 | `defaultPermissions` callback | api-key | ✅ |
| 6 | Configurable schema merge (`ApiKeyOptions::with_schema`, `api_key_with_build`) | api-key | ✅ |
| 7 | Custom OTP hash/encrypt hooks (`OtpStorage::CustomHash`, `CustomEncrypt`) | two-factor | ✅ |
| 8 | `schema?` field rename | jwt, phone-number, username | ✅ |
| 9 | `verification.storeIdentifier: hashed` (core; used by generic OAuth) | openauth-core | ✅ |
| 10 | Test `/organization/check-slug` | organization | ✅ |

**Pending functional server items: 0** (closed in June 2026 parity work).  
**8 plugins** can still expand upstream test coverage; routes and core options are aligned.
