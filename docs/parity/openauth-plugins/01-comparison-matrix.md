# Comparison matrix: server-side plugins

Reference: Better Auth **v1.6.9** vs `openauth-plugins` **0.0.6**.

**Global status** legend per plugin:

| Symbol | Meaning |
|--------|---------|
| ✅ Full | Complete server-side parity |
| 🟡 Partial | Main functionality present; gaps in options/tests/minor hooks |
| 🔴 Missing | Server functionality absent |
| ➖ N/A | Not applicable (client-only or other crate) |
| 🎯 Intentional | Documented design difference |

---

## Main matrix

| Plugin | Routes | Schema | Hooks | Options | Tests (OA / BA) | Status | Key notes |
|--------|:-----:|:------:|:-----:|:--------:|:---------------:|:------:|-------------|
| [access](./plugins/hooks-and-utilities.md#access) | ➖ | ➖ | ➖ | ✅ | 24 / 7 | ✅ | OpenAuth has more RBAC tests |
| [additional-fields](./plugins/hooks-and-utilities.md#additional-fields) | ➖ | 🎯 | 🎯 | ✅ | 3 / 12 | 🎯 | Upstream client-only; we have server schema |
| [admin](./plugins/admin.md) | ✅ | ✅ | ✅ | 🟡 | 29 / 74 | 🟡 | Less depth on list-users/impersonation tests |
| [anonymous](./plugins/auth-flows.md#anonymous) | ✅ | ✅ | ✅ | ✅ | 18 / 14 | ✅ | OpenAuth more tests |
| [api-key](./plugins/api-key.md) | 🎯 | 🎯 | ✅ | ✅ | 52 / 176 | 🟡 | verify/delete-expired: HTTP OA vs path-less BA; options closed Jun 2026 |
| [bearer](./plugins/hooks-and-utilities.md#bearer) | ➖ | ➖ | ✅ | ✅ | 16 / 6 | ✅ | — |
| [captcha](./plugins/hooks-and-utilities.md#captcha) | ➖ | ➖ | ✅ | ✅ | 19 / 22 | ✅ | 4 providers |
| [custom-session](./plugins/hooks-and-utilities.md#custom-session) | 🎯 | ➖ | ✅ | ✅ | 18 / 12 | ✅ | Enriches `/get-session` |
| [device-authorization](./plugins/auth-flows.md#device-authorization) | ✅ | ✅ | ✅ | ✅ | 36 / 41 | 🟡 | High parity |
| [email-otp](./plugins/email-otp.md) | ✅ | ✅ | ✅ | 🟡 | 31 / 90 | 🟡 | Test gap on resend/attempts matrices |
| [generic-oauth](./plugins/generic-oauth.md) | ✅ | ✅ | 🟡 | ✅ | 41 / 68 | 🟡 | `storeIdentifier: hashed` via **openauth-core**; CSRF/state tests incomplete |
| [haveibeenpwned](./plugins/hooks-and-utilities.md#haveibeenpwned) | ➖ | ➖ | ✅ | ✅ | 12 / 6 | ✅ | — |
| [jwt](./plugins/jwt.md) | 🎯 | ✅ | ✅ | ✅ | 33 / 49 | 🎯 | sign/verify explicit HTTP; schema options ✅ |
| [last-login-method](./plugins/hooks-and-utilities.md#last-login-method) | ➖ | ✅ | ✅ | ✅ | 20 / 23 | ✅ | — |
| [magic-link](./plugins/auth-flows.md#magic-link) | ✅ | ✅ | 🟡 | ✅ | 27 / 23 | ✅ | Dedicated `upstream_parity.rs` |
| [mcp](./plugins/mcp.md) | ✅ | ✅ | ✅ | 🟡 | 30 / 36 | 🎯 | OA implements `/mcp/userinfo`, `/mcp/jwks` (BA metadata without handler) |
| [multi-session](./plugins/hooks-and-utilities.md#multi-session) | ✅ | ➖ | ✅ | ✅ | 22 / 10 | ✅ | SERVER_PARITY.md: complete |
| [oauth-proxy](./plugins/hooks-and-utilities.md#oauth-proxy) | ✅ | ➖ | ✅ | ✅ | 24 / 21 | ✅ | SERVER_PARITY.md: complete |
| [oidc-provider](./03-out-of-scope.md) | ➖ | ➖ | ➖ | ➖ | — / 42 | ➖ | → `openauth-oauth-provider` |
| [one-tap](./plugins/auth-flows.md#one-tap) | ✅ | ➖ | ➖ | 🎯 | 14 / 0 | 🎯 | No upstream tests; different error shape |
| [one-time-token](./plugins/hooks-and-utilities.md#one-time-token) | ✅ | ✅ | ✅ | ✅ | 15 / 20 | ✅ | SERVER_PARITY.md: complete |
| [open-api](./plugins/hooks-and-utilities.md#open-api) | ✅ | ➖ | ➖ | ✅ | 9 / 10 | ✅ | Scalar UI |
| [organization](./plugins/organization.md) | ✅ | ✅ | 🟡 | ✅ | 32 / 182 | 🟡 | `ac`, async limits, `customCreateDefaultTeam`, check-slug test ✅ Jun 2026; test depth gap |
| [phone-number](./plugins/phone-number.md) | ✅ | ✅ | ✅ | ✅ | 22 / 47 | 🟡 | Schema options ✅ |
| [siwe](./plugins/auth-flows.md#siwe) | ✅ | ✅ | ➖ | ✅ | 25 / 18 | ✅ | — |
| [two-factor](./plugins/two-factor.md) | ✅ | ✅ | 🟡 | ✅ | 21 / 77 | 🟡 | `POST /two-factor/generate-totp` ✅; custom OTP hooks ✅ |
| [username](./plugins/auth-flows.md#username) | ✅ | ✅ | ✅ | ✅ | 12 / 39 | 🟡 | Schema options ✅; fewer validation tests |

**Test totals:** OpenAuth **610** | Upstream **986** `it()` (excluding test-utils, oidc-provider).

> Detail: [04-deep-audit-findings.md](./04-deep-audit-findings.md), [05-third-pass-audit.md](./05-third-pass-audit.md).

---

## HTTP routes: summary by category

### No routes (hooks / utilities)

`access`, `additional-fields`, `bearer`, `captcha`, `custom-session`, `haveibeenpwned`, `last-login-method`

### Authentication / identity routes

| Plugin | Routes | Parity |
|--------|-------|---------|
| anonymous | `POST /sign-in/anonymous`, `POST /delete-anonymous-user` | ✅ |
| email-otp | 11 routes under `/email-otp/*`, `/sign-in/email-otp`, deprecated alias | ✅ |
| magic-link | `POST /sign-in/magic-link`, `GET /magic-link/verify` | ✅ |
| phone-number | 5 routes | ✅ |
| username | `POST /sign-in/username`, `POST /is-username-available` | ✅ |
| siwe | `POST /siwe/nonce`, `POST /siwe/verify` | ✅ |
| one-tap | `POST /one-tap/callback` | ✅ |
| generic-oauth | `POST /sign-in/oauth2`, `GET /oauth2/callback/:id`, `POST /oauth2/link` | ✅ |

### Session / security routes

| Plugin | Routes | Parity |
|--------|-------|---------|
| multi-session | 3 routes `/multi-session/*` | ✅ |
| two-factor | 10 routes `/two-factor/*` (incl. `generate-totp`) | ✅ |
| device-authorization | 5 routes `/device/*` | ✅ |
| one-time-token | `GET /generate`, `POST /verify` | ✅ |
| jwt | `GET /jwks`, `GET /token`, `POST /sign-jwt`, `POST /verify-jwt` | 🎯 |
| api-key | 7 routes `/api-key/*` | ✅ |

### Admin / org routes

| Plugin | Routes | Parity |
|--------|-------|---------|
| admin | 14 routes `/admin/*` | ✅ |
| organization | 28–33 routes `/organization/*` | ✅ routes; options aligned Jun 2026 |

### Infra / protocol routes

| Plugin | Routes | Parity |
|--------|-------|---------|
| mcp | 9 routes (well-known + `/mcp/*`) | ✅ |
| oauth-proxy | `GET /oauth-proxy-callback` | ✅ |
| open-api | `GET /open-api/generate-schema`, `GET /reference` | ✅ |

---

## Cross-cutting intentional differences

Documented in `SERVER_PARITY.md` and applicable to several plugins:

| Topic | Upstream | OpenAuth | Affected plugins |
|------|----------|----------|-------------------|
| Base URL env | `BETTER_AUTH_URL` | `OPENAUTH_URL` | oauth-proxy, generic-oauth, mcp |
| Serializable options | Closures at runtime | Closures omitted from metadata | all |
| Implicit account linking | Dynamic `trustedProviders` | Static `trusted_providers` | one-tap, generic-oauth, oauth core |
| HTTP errors | Sometimes `200 { error }` | Explicit HTTP errors | one-tap (`400 EMAIL_NOT_AVAILABLE`) |
| Org metadata | `string` JSON in DB | `serde_json::Value` | organization |
| api-key table | `apikey` | `api_keys` | api-key |
| HIBP plugin ID | `haveibeenpwned` | runtime `have-i-been-pwned` | haveibeenpwned |
| Path-less upstream APIs | `auth.api.*` without path | Explicit POST/GET routes | api-key, jwt, email-otp, 2FA view-backup-codes, org add-member, **generate-totp** |
| Organization check-slug | ✅ POST | ✅ POST + test ✅ | organization |
| MCP userinfo / jwks | Metadata only (no handler) | Routes implemented | mcp |
| MCP protected resource | ✅ registered | ✅ registered | mcp |
| Verification `storeIdentifier: hashed` | Core option | `openauth-core` `verification.store_identifier` ✅ | generic-oauth flows |

---

## Gap-closure priorities (server-only)

Remaining focus is **test depth**, not missing routes/options closed in Jun 2026:

1. **organization** — upstream scenario matrices (multi-org isolation, re-invite combinatorics)
2. **api-key** — rate-limit/refill/secondary-storage timer scenarios
3. **email-otp** — full HTTP matrix with bearer plugin setups
4. **two-factor** — trust-device matrix; client-exposure test for view-backup-codes
5. **generic-oauth** — CSRF/state tampering tests
6. **admin** — list-users filters, impersonation edge cases
