# Options matrix — `BetterAuthOptions` ↔ `OpenAuthOptions`

Inventory read from `packages/core/src/types/init-options.ts` and `crates/openauth-core/src/options/`.  
**Do not rely on READMEs alone** — this table reflects fields in code.

**Legend:** ✅ Equivalent field · 🟡 Partial / different API · 🔴 No equivalent in `OpenAuthOptions` · ➖ N/A server-only or excluded

## Top-level

| Upstream (`BetterAuthOptions`) | OpenAuth | Status | Notes |
| --- | --- | --- | --- |
| `appName` | — (hardcoded in context) | 🔴 | `context/builder.rs`: fixed `app_name: "OpenAuth"` |
| `baseURL` | `base_url` | ✅ | No `DynamicBaseURLConfig` type (allowed hosts + fallback) |
| `basePath` | `base_path` | ✅ | Default `/api/auth` in builder |
| `secret` | `secret` | ✅ | |
| `secrets` | `secrets` | ✅ | `$ba$` rotation — tests `crypto/secret_rotation.rs` |
| `database` | via `AuthContext::adapter` | 🟡 | Not in options; adapter passed to builder |
| `secondaryStorage` | `secondary_storage` | ✅ | Sign-up secondary, verification store tests |
| `emailVerification` | `email_verification` | ✅ | See subtable |
| `emailAndPassword` | `email_password` + `password` | 🟡 | Upstream hash/verify nested under `emailAndPassword.password` |
| `socialProviders` | `social_providers` | ➖ | `oauth` feature |
| `plugins` | `plugins` | ✅ | |
| `user` | `user` | 🟡 | No `modelName`/`fields` in options; see `AuthSchemaOptions` |
| `session` | `session` | 🟡 | See subtable |
| `account` | `account` | 🟡 | |
| `verification` | — | 🟡 | Only in `AuthSchemaOptions.store_verification_in_database` |
| `trustedOrigins` | `trusted_origins` | ✅ | `Static` / `Dynamic` enum |
| `rateLimit` | `rate_limit` | ✅ | Rust adds `hybrid`, `missing_ip_policy`, `dynamic_rules` |
| `advanced` | `advanced` | 🟡 | See subtable |
| `logger` | — | 🔴 | Fixed `LoggerOptions::default()` in builder |
| `databaseHooks` | — | 🔴 | Only `AuthPlugin` / `PluginInitOutput.database_hooks` |
| `onAPIError` | — | 🔴 | No `throw` / `onError` / `errorURL` / customizable HTML page |
| `hooks` (global before/after) | — | 🔴 | Plugin hooks only (`plugin.hooks`) |
| `disabledPaths` | `disabled_paths` | ✅ | Router + rate_limit tests |
| `telemetry` | `telemetry` | 🟡 | Real publisher in `openauth-telemetry` + noop in core |
| `experimental.joins` | `experimental.joins` (default **true**) | 🟢 | Adapter factory + sqlx multi-join tests; memory fallback when disabled |
| implicit `production` | `production` | ✅ | Also `env::is_production()` |

## `emailVerification`

| Upstream | OpenAuth | Status |
| --- | --- | --- |
| `sendVerificationEmail` | `send_verification_email` | ✅ |
| `sendOnSignUp` | `send_on_sign_up` | ✅ |
| `sendOnSignIn` | `send_on_sign_in` | ✅ sign_in_email test |
| `autoSignInAfterVerification` | `auto_sign_in_after_verification` | 🟡 | Field exists; **no dedicated route test** |
| `expiresIn` | `expires_in` | ✅ |
| `beforeEmailVerification` | `before_email_verification` | ✅ route tests |
| `afterEmailVerification` | `after_email_verification` | ✅ |

## `emailAndPassword` / password

| Upstream | OpenAuth | Status |
| --- | --- | --- |
| `enabled` | `email_password.enabled` | ✅ |
| `disableSignUp` | `disable_sign_up` | 🟡 | Used in routes; test only in `auth/oauth.rs` |
| `requireEmailVerification` | `require_email_verification` | ✅ |
| `minPasswordLength` / `maxPasswordLength` | `password.min_*` | ✅ |
| `sendResetPassword` | `password.send_reset_password` | ✅ |
| `resetPasswordTokenExpiresIn` | `password.reset_password_token_expires_in` | ✅ |
| `onPasswordReset` | `password.on_password_reset` | ✅ |
| `password.hash` / `password.verify` custom | `PasswordContext::hash` / `verify` | 🔴 | Fixed `hash_password` / `verify_password` in builder |
| `autoSignIn` | `email_password.auto_sign_in` | ✅ |
| `revokeSessionsOnPasswordReset` | `password.revoke_sessions_on_password_reset` | ✅ |
| `onExistingUserSignUp` | `on_existing_user_sign_up` | ✅ | + synthetic response — sign_up_email tests |
| `customSyntheticUser` | internal synthetic logic | 🟡 | Similar behavior; no dedicated TS callback |

## `session`

| Upstream | OpenAuth | Status |
| --- | --- | --- |
| `expiresIn` | `expires_in` | ✅ |
| `updateAge` | `update_age` | ✅ |
| `disableSessionRefresh` | `disable_session_refresh` | ✅ get_session tests |
| `deferSessionRefresh` | `defer_session_refresh` | ✅ POST/GET get-session |
| `storeSessionInDatabase` | `store_session_in_database` | 🟡 | Schema + sign_up test |
| `preserveSessionInDatabase` | `preserve_session_in_database` | 🟡 | `auth/email_password.rs` only |
| `cookieCache.*` | `cookie_cache` | ✅ | Compact/Jwt/Jwe strategies |
| `freshAge` | `fresh_age` | 🟡 | `sensitive_session` / delete-user; **no HTTP fresh gate test** |
| `additionalFields` | `additional_fields` | ✅ | update-session, sign-up tests |

## `user` — `changeEmail` / `deleteUser`

Flow detail in [10-user-lifecycle-gaps.md](./10-user-lifecycle-gaps.md).

### `changeEmail`

| Upstream | OpenAuth | Status |
| --- | --- | --- |
| `enabled` | `ChangeEmailOptions.enabled` | ✅ |
| `updateEmailWithoutVerification` | `update_email_without_verification` | ✅ |
| `sendChangeEmailConfirmation` | — | 🔴 |

### `deleteUser`

| Upstream | OpenAuth | Status |
| --- | --- | --- |
| `enabled` | `DeleteUserOptions.enabled` | ✅ |
| `sendDeleteAccountVerification` | — | 🔴 |
| `beforeDelete` | — | 🔴 |
| `afterDelete` | — | 🔴 |
| `deleteTokenExpiresIn` | — | 🔴 |

## `account`

| Upstream | OpenAuth | Status |
| --- | --- | --- |
| `updateAccountOnSignIn` | `update_account_on_sign_in` | 🟡 | OAuth flows |
| `accountLinking.*` | `account_linking` | 🟡 | SERVER_PARITY.md; oauth tests |
| `encryptOAuthTokens` | `encrypt_oauth_tokens` | ➖ | oauth |
| `skipStateCookieCheck` | — | ➖ | oauth state |
| `storeStateStrategy` | `store_state_strategy` | ➖ | oauth |
| `storeAccountCookie` | `store_account_cookie` | ➖ | oauth tests |

## `verification` (upstream `BetterAuthDBOptions` + flags)

| Upstream | OpenAuth | Status |
| --- | --- | --- |
| `modelName` / `fields` | `AuthSchemaOptions.verification` (`TableOptions`) | 🟡 |
| `disableCleanup` | — | 🔴 |
| `storeIdentifier` (`plain` / `hashed` / fn) | `verification.store_identifier` | ✅ |
| `storeInDatabase` | `store_verification_in_database` | 🟡 | In schema builder, not top-level `OpenAuthOptions` |

## `advanced`

| Upstream | OpenAuth | Status |
| --- | --- | --- |
| `ipAddress.*` | `ip_address` | ✅ | session_ip_metadata, rate limit |
| `useSecureCookies` | `use_secure_cookies` | 🟡 | cookies tests |
| `disableCSRFCheck` | `disable_csrf_check` | 🟡 | **Routes always disable in tests** |
| `disableOriginCheck` | `disable_origin_check` | 🟡 | same |
| `crossSubDomainCookies` | `cross_subdomain_cookies` | 🟡 | |
| `cookies` / `defaultCookieAttributes` | `default_cookie_attributes` | 🟡 | |
| `cookiePrefix` | `cookie_prefix` | ✅ |
| `database.generateId` | `IdPolicy` in schema | 🟡 | `db/id_policy.rs` |
| `trustedProxyHeaders` | — | 🔴 | No dynamic base URL |
| `backgroundTasks` | `background_tasks` | 🟡 | Field exists; **no tests** |
| `skipTrailingSlashes` | `skip_trailing_slashes` | ✅ | `tests/api/router.rs` |

## `rateLimit`

| Upstream | OpenAuth | Status |
| --- | --- | --- |
| `window` / `max` / `enabled` | yes | ✅ |
| `customRules` | `custom_rules` | ✅ |
| `storage` memory/database/secondary | `storage` enum | ✅ |
| `customStorage` | `custom_storage` / `custom_store` | 🟡 | Legacy adapter |
| `modelName` / `fields` | `AuthSchemaOptions.rate_limit` | 🟡 |

## DB schema (`AuthSchemaOptions` — Rust only)

Equivalent spread across upstream (`user.modelName`, `session.fields`, `getAuthTables`).

| Rust field | Approximate upstream |
| --- | --- |
| `user` / `session` / `account` / `verification` / `rate_limit` `TableOptions` | `BetterAuthDBOptions` per model |
| `has_secondary_storage` | `getAuthTables` + secondary logic |
| `store_session_in_database` | `session.storeSessionInDatabase` |
| `store_verification_in_database` | `verification.storeInDatabase` |
| `rate_limit_storage` | `rateLimit.storage` |
| `id_policy` | `advanced.database.generateId` |

## Hooks: where they live

| Upstream type | OpenAuth |
| --- | --- |
| `options.hooks.before` / `after` | Only `AuthPlugin::with_before_hook` / `with_after_hook` |
| `options.databaseHooks` | Only plugin `with_database_hook` + `PluginInitOutput` |
| Plugin `onRequest` / `onResponse` | `AuthPlugin` — `plugin_router.rs` tests |
| Plugin middleware per path | `plugin.middlewares` — plugin_router tests |

The three most visible top-level config fields not yet ported are **`appName`**, **`databaseHooks` on options**, and **`onAPIError`**.
