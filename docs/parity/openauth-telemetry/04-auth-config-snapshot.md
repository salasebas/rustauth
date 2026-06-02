# 04 — `get_telemetry_auth_config` snapshot

Sanitizes [`OpenAuthOptions`](../../../crates/openauth-core) / `BetterAuthOptions` to JSON without secrets or callback bodies.

Upstream: `detectors/detect-auth-config.ts`  
OpenAuth: `auth_config.rs`

## Legend

| Status | Meaning |
| --- | --- |
| **Match** | Same semantics when the option exists in core |
| **Partial** | Field present but fixed / incomplete value |
| **N/A** | Upstream JS-only or not modeled in OpenAuth yet |
| **Drift** | Upstream test uses a different name than implementation |

---

## Context

| Field | Upstream | OpenAuth | Status |
| --- | --- | --- | --- |
| `database` | `context.database` | `context.database` | Match |
| `adapter` | `context.adapter` | `context.adapter` | Match |

---

## `emailVerification`

| Field | Upstream | OpenAuth | Status |
| --- | --- | --- | --- |
| `sendVerificationEmail` | bool presence | `is_some()` | Match |
| `sendOnSignUp` / `sendOnSignIn` | `!!` | actual values | Match |
| `autoSignInAfterVerification` | `!!` | bool | Match |
| `expiresIn` | value | value | Match |
| `beforeEmailVerification` | bool | `is_some()` | Match |
| `afterEmailVerification` | bool | `is_some()` | Match |
| `onEmailVerification` (test only) | — | not emitted | **Drift** upstream test |

---

## `emailAndPassword`

| Field | Upstream | OpenAuth | Status |
| --- | --- | --- | --- |
| `enabled`, `disableSignUp`, `requireEmailVerification` | `!!` | core bools | Match |
| `maxPasswordLength`, `minPasswordLength` | optional | from `PasswordOptions` | Match |
| `sendResetPassword`, `onPasswordReset` | bool | `is_some()` | Match |
| `resetPasswordTokenExpiresIn` | value | value | Match |
| `password.hash` / `password.verify` | bool from callbacks | **always `false`** | **Partial** (core does not expose hash callbacks in snapshot) |
| `autoSignIn`, `revokeSessionsOnPasswordReset` | `!!` | bool | Match |

---

## `socialProviders`

| Aspect | Upstream | OpenAuth | Status |
| --- | --- | --- | --- |
| List | `Object.keys` + async factory resolve | `options.social_providers` iteration | Same intent |
| `id` | map key | `provider.id()` | Match |
| Flags (`disableSignUp`, `scope`, …) | from provider object | `oauth` feature: trait metadata | Partial without `oauth`: `[]` |
| `mapProfileToUser`, `getUserInfo`, `verifyIdToken`, `refreshAccessToken` | bool from provider | **hardcoded** per field | **Partial** (no closure introspection) |
| Secrets | excluded | excluded (`oauth` test) | Match |

---

## `plugins`

| Upstream | OpenAuth | Status |
| --- | --- | --- |
| `plugins?.map(p => p.id)` | id `Vec` or `null` if empty | Match (minor `null` vs `undefined`) |

---

## `user`

| Field | Upstream | OpenAuth | Status |
| --- | --- | --- | --- |
| `modelName`, `fields` | from options | **`null`** | **Partial** (not in core) |
| `additionalFields` | raw object | safe metadata (type, required, …) | **OpenAuth improvement** |
| `changeEmail.enabled` | value | value | Match |
| `changeEmail.sendChangeEmailConfirmation` | bool | **`false` fixed** | **Partial** until core wires callback |
| `sendChangeEmailVerification` (test) | — | not emitted | **Drift** test |

---

## `verification` / `session` / `account`

| Block | Upstream | OpenAuth | Status |
| --- | --- | --- | --- |
| `modelName`, `fields` | optional | **`null`** on verification/account; session partial | Partial |
| `session.cookieCache` | values | enabled, maxAge, strategy (`compact`/`jwt`/`jwe`) | Match |
| `session.*` timing / DB flags | values | from `SessionOptions` | Match |
| `account.accountLinking` | values | values | Match |
| `encryptOAuthTokens`, `updateAccountOnSignIn` | values | values | Match |

---

## `hooks` / `secondaryStorage`

| Field | Upstream | OpenAuth | Status |
| --- | --- | --- | --- |
| `hooks.after` / `before` | `!!options.hooks` | **`false` fixed** | **Partial** |
| `secondaryStorage` | `!!` | `options.secondary_storage.is_some()` | Match |

---

## `advanced`

| Field | Upstream | OpenAuth | Status |
| --- | --- | --- | --- |
| `cookiePrefix` | bool (not value) | `is_some()` | Match |
| `cookies` | `!!` | **`false` fixed** | Partial |
| `crossSubDomainCookies.domain` | bool | `domain.is_some()` | Match |
| `crossSubDomainCookies.enabled` | value | value | Match |
| `crossSubDomainCookies.additionalCookies` | value | **`null`** | Partial |
| `database.generateId` | value or function | **`null`** | Partial |
| `database.defaultFindManyLimit` | value | **`null`** | Partial |
| `useNumberId` (upstream test only) | — | not emitted | Drift |
| `ipAddress`, `disableCSRFCheck`, cookie attrs | values | values | Match |
| `cookieAttributes.domain` | bool | bool | Match |

---

## `trustedOrigins`

| Upstream | OpenAuth | Status |
| --- | --- | --- |
| `options.trustedOrigins?.length` | static or dynamic count | Match (count only) |

---

## `rateLimit`

| Field | Upstream | OpenAuth | Status |
| --- | --- | --- | --- |
| `storage`, `window`, `enabled`, `max` | values | values (+ enum → string) | Match |
| `modelName` | optional | **`null`** | Partial |
| `customStorage` | bool | `is_some()` | Match |

---

## `onAPIError` / `logger` / `databaseHooks`

| Block | Upstream | OpenAuth | Status |
| --- | --- | --- |
| `onAPIError.*` | from options | `errorURL`/`throw` null; `onError` false | **Partial** |
| `logger.*` | from options | mostly **null/false** | **Partial** |
| `databaseHooks.*` | bool per hook | **all false** | **Partial** until DB hooks in core |

---

## Gap summary by cause

| Cause | Examples |
| --- | --- |
| **OpenAuth core not modeled yet** | `user.modelName`, hooks, logger, databaseHooks |
| **Decision: no closure introspection** | `password.hash`, dynamic OAuth flags |
| **`oauth` feature off** | `socialProviders: []` |
| **Upstream test drift** | `onEmailVerification`, `useNumberId` |

When `openauth-core` gains fields, update `auth_config.rs` and extend `auth_config_snapshot_*` tests (today 1–2 integration tests).
