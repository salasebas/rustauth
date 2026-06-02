# 05 — Boundary: `openauth-core/auth/oauth` ↔ `better-auth/src/oauth2`

This crate (`openauth-oauth`) **does not include** session integration, database access, or HTTP routes. That upstream layer lives in `better-auth` and in OpenAuth in `openauth-core`.

## Responsibility map

| Concern | Upstream | OpenAuth |
| --- | --- | --- |
| Authorize URL, token HTTP, PKCE math, JWT verify | `@better-auth/core/oauth2` | **`openauth-oauth`** |
| OAuth state (PKCE verifier, callback URLs, expiry) | `better-auth/src/oauth2/state.ts` | `openauth-core/src/auth/oauth/state.rs` |
| Account link / sign-up / session | `better-auth/src/oauth2/link-account.ts` | `openauth-core/src/auth/oauth/account_linking.rs` |
| Token encrypt at rest | `better-auth/src/oauth2/utils.ts` | `openauth-core/src/auth/oauth/tokens.rs` |
| Missing email log helper | `better-auth/src/oauth2/errors.ts` | `openauth-core/src/auth/oauth/errors.rs` |
| Request-scoped OAuth state | `better-auth/src/api/state/oauth.ts` | `openauth-core` request state / context |
| HTTP routes callback/sign-in | `better-auth/src/api/routes/callback.ts`, `sign-in.ts` | `openauth-core` API routes |
| Generic OAuth plugin | `better-auth/src/plugins/generic-oauth/` | Core routes + provider registry |
| Built-in social providers | `core/social-providers/*` | `openauth-social-providers` |

## OAuth state (`state`)

| Capability | Upstream | OpenAuth |
| --- | --- | --- |
| Generates 128-char `code_verifier` | ✅ | ✅ |
| Default expiry 10 min | ✅ | ✅ |
| `callbackURL`, `errorURL`, `newUserURL` | ✅ | ✅ |
| Link metadata `{ email, userId }` | ✅ | ✅ `OAuthStateLink` |
| Cookie strategy (signed state) | ✅ | ✅ |
| Database strategy | ✅ | ✅ verification store |
| Single-use replay protection (cookie+DB) | ✅ | ✅ OPE-19 |
| `parseState` error → redirect | ✅ | ✅ |
| CSRF `state` on authorize URL | ✅ (core URL builder) | ✅ uses `openauth-oauth` + core state |

## Account linking (`link-account` / `handle_oauth_user_info`)

| Capability | Upstream | OpenAuth |
| --- | --- | --- |
| Find/create user + account | ✅ | ✅ |
| Trusted provider + verified email linking | ✅ | ✅ |
| `disableImplicitSignUp` / linking rules | ✅ | ✅ |
| `overrideUserInfoOnSignIn` | ✅ | ✅ |
| Provider-scoped account lookup | ✅ | ✅ |
| Preserve tokens when provider omits refresh | ✅ | ✅ |
| Account cookie (JWT) | ✅ | ✅ (requires `jose`) |
| Discord phone-only synthesized email | ✅ test | ⚠️ verify in social providers |
| `email_not_found` rejection | ✅ | ✅ |

## Token encryption at rest

| Capability | Upstream | OpenAuth |
| --- | --- | --- |
| Encrypt when `encryptOAuthTokens` enabled | ✅ | ✅ |
| Legacy plain token migration | ✅ | ✅ |
| `$ba$` prefix / hex detection | ✅ | ✅ equivalent |
| `setTokenUtil` on sign-in | ✅ | ✅ `encrypt_oauth_tokens_for_storage` |

## Generic-oauth plugin (boundary)

Upstream `generic-oauth` is a **routing plugin** that composes the same `@better-auth/core/oauth2` primitives:

| generic-oauth piece | Where in OpenAuth |
| --- | --- |
| Provider config presets (Okta, Auth0, …) | `openauth-social-providers` or manual config |
| Routes: signIn, callback, linkAccount | `openauth-core` routes |
| RFC 9207 `iss` validation | ⚠️ verify in core callback (outside `openauth-oauth`) |
| Custom `getToken` / GET token endpoint | Provider trait overrides |
| State cookie security tests | `openauth-core/tests/api/routes/social_oauth.rs` |

**59 tests** in `generic-oauth.test.ts` — mostly plugin E2E; **33** exercise shared primitives/config. Do not duplicate the matrix here; see [06-tests.md](./06-tests.md).

## Tests in core layer (outside `openauth-oauth`)

### `openauth-core/tests/auth/oauth.rs` (19 tests)

| Test | Covers (upstream equivalent) |
| --- | --- |
| `oauth_token_utils_encrypt_decrypt_and_tolerate_legacy_plain_tokens` | `utils.test.ts` encrypt/decrypt |
| `handle_oauth_user_info_encrypts_all_stored_tokens_exactly_once` | encrypt on link |
| `oauth_state_cookie_strategy_round_trips_without_database` | cookie state |
| `parse_oauth_state_rejects_cookie_state_with_wrong_secret` | state security |
| `oauth_state_database_strategy_persists_and_rejects_expired_state` | DB state |
| `oauth_state_cookie_strategy_is_single_use_with_database` | replay protection |
| `oauth_state_cookie_strategy_without_adapter_skips_single_use_marker` | cookie-only mode |
| `handle_oauth_user_info_sets_account_cookie_when_enabled` | account cookie |
| `handle_oauth_user_info_account_cookie_fails_closed_without_jose` | feature gate |
| `handle_oauth_user_info_creates_user_account_and_session` | basic link flow |
| `handle_oauth_user_info_respects_signup_and_linking_rules` | signup policy |
| `handle_oauth_user_info_uses_trusted_provider_configuration_and_disable_implicit_linking` | trusted provider |
| `handle_oauth_user_info_uses_provider_scoped_account_lookup` | account id scope |
| `handle_oauth_user_info_respects_update_account_on_sign_in_false` | update flag |
| `handle_oauth_user_info_updates_linked_account_tokens_and_user_info` | token refresh on sign-in |
| `handle_oauth_user_info_preserves_linked_account_tokens_when_provider_omits_them` | token preservation |
| `handle_oauth_user_info_does_not_verify_email_when_provider_email_differs` | email verify rules |
| `handle_oauth_user_info_override_updates_email_and_verified_status` | override user info |
| `missing_email_log_message_matches_upstream_guidance` | `errors.ts` |

### `openauth-core/tests/api/routes/social_oauth.rs` (20 tests)

HTTP integration: sign-in redirect, callback, link social, id_token flows, trusted/untrusted providers, POST callback.

Upstream equivalent spread across `link-account.test.ts` + `generic-oauth.test.ts` E2E.

### Upstream `better-auth/src/oauth2/*.test.ts` (28 tests)

| File | Tests | OpenAuth home |
| --- | --- | --- |
| `utils.test.ts` (13) | encrypt/decrypt/migration | `auth/oauth.rs` + `tokens.rs` |
| `link-account.test.ts` (15) | linking rules | `auth/oauth.rs` + `social_oauth.rs` |

## Full flow diagram (social sign-in)

```text
Client                openauth-core                 openauth-oauth              IdP
   |                         |                            |                      |
   |-- POST sign-in/social ->|                            |                      |
   |                         |-- generate_oauth_state     |                      |
   |                         |-- create_authorization_url ->|                      |
   |                         |                            |-- build URL + PKCE   |
   |<- 302 authorize URL ----|                            |                      |
   |---------------------------------------------------------------- redirect -->|
   |                         |                            |                      |
   |<- callback ?code&state -|                            |                      |
   |                         |-- parse_oauth_state        |                      |
   |                         |-- validate_authorization_code ->|                 |
   |                         |                            |-- POST token ------->|
   |                         |<- OAuth2Tokens -------------|                      |
   |                         |-- handle_oauth_user_info   |                      |
   |                         |-- encrypt tokens (core)    |                      |
   |<- session cookie -------|                            |                      |
```

## Do not document as `openauth-oauth` gaps

| Apparent "missing" piece | Reality |
| --- | --- |
| No `generateState` | In `openauth-core` |
| No `handleOAuthUserInfo` | In `openauth-core` |
| No `/callback/:id` route | In `openauth-core` |
| No 35 social providers | In `openauth-social-providers` |
| No generic OAuth plugin type | Composition in core + providers |

## References

- Upstream state: `packages/better-auth/src/oauth2/state.ts`
- Upstream link: `packages/better-auth/src/oauth2/link-account.ts`
- OpenAuth: `crates/openauth-core/src/auth/oauth/`
