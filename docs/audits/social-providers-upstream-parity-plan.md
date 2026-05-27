# Social Providers Upstream Parity Audit Plan

## Summary

Target package: `crates/openauth-social-providers`.

OpenAuth's social providers crate is a server-side Rust provider catalog inspired by Better Auth's core social provider implementations. The audit found broad upstream parity across provider coverage, endpoints, default scopes, authorization URL construction, token exchange forms, ID token verification support, and focused provider tests. The justified fixes are narrow: align the public provider registry order with upstream, update stale crate docs, and normalize selected userinfo fetch failures to the upstream `null` behavior by returning `Ok(None)`.

## Upstream Files Inspected

- `upstream/better-auth/1.6.9/repository/packages/core/src/social-providers/index.ts`
- `upstream/better-auth/1.6.9/repository/packages/core/src/social-providers/*.ts`
- `upstream/better-auth/1.6.9/repository/packages/core/src/oauth2/validate-authorization-code.ts`
- `upstream/better-auth/1.6.9/repository/packages/core/src/oauth2/refresh-access-token.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/social.test.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/api/routes/account.test.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/api/routes/sign-in.test.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/api/routes/callback.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/api/routes/account.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/oauth2/link-account.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/oauth2/link-account.test.ts`

## OpenAuth Files Inspected

- `crates/openauth-social-providers/src/lib.rs`
- `crates/openauth-social-providers/src/*.rs`
- `crates/openauth-social-providers/src/runtime/*.rs`
- `crates/openauth-social-providers/tests/*.rs`
- `crates/openauth-social-providers/Cargo.toml`
- `crates/openauth-social-providers/README.md`
- `crates/openauth-oauth/src/oauth2/authorization_url.rs`
- `crates/openauth-oauth/src/oauth2/validate_authorization_code.rs`
- `crates/openauth-oauth/src/oauth2/refresh_access_token.rs`
- `crates/openauth-oauth/src/oauth2/request.rs`
- `crates/openauth-oauth/src/oauth2/tokens.rs`
- `crates/openauth-core/Cargo.toml`
- `crates/openauth-core/src/lib.rs`
- `crates/openauth-core/src/context.rs`
- `crates/openauth-core/src/options/root.rs`
- `crates/openauth-core/src/options/account.rs`
- `crates/openauth-core/src/api/routes/social.rs`
- `crates/openauth-core/src/api/routes/social/flow.rs`
- `crates/openauth-core/src/api/routes/account.rs`
- `crates/openauth-core/src/api/routes/account/support.rs`
- `crates/openauth-core/src/auth/oauth/account_linking.rs`
- `crates/openauth-core/tests/api/routes/social_oauth.rs`
- `crates/openauth-core/tests/api/routes/account_tokens.rs`
- `crates/openauth-core/tests/api/routes/unlink_account.rs`

## Confirmed Matches

- Provider coverage matches upstream's 35 built-in social providers.
- Provider IDs and names match upstream, including `microsoft` for Microsoft Entra ID.
- Authorization, token, userinfo, JWKS, and environment-specific endpoints match upstream for the audited providers.
- Default scopes and `disableDefaultScope` behavior are represented in Rust as typed `ProviderOptions::disable_default_scope`.
- PKCE is enforced for providers where upstream requires a `codeVerifier`, including Google, Figma, Paybin, Salesforce, Twitter, Vercel, Railway, and Zoom when enabled.
- Token exchange helpers preserve upstream form behavior: POST client auth by default, Basic auth for providers that require it, `code_verifier`, `device_id`, `resource`, and refresh-token forms.
- ID token verification support is implemented for security-sensitive providers such as Apple, Google, Microsoft Entra ID, Twitch, Facebook limited login, Cognito, Line, PayPal custom verification, and Paybin ID token mapping.
- The crate is available through `openauth-core` behind the `social-providers` feature and through the top-level `openauth` re-export.
- Baseline verification command `cargo test -p openauth-social-providers` passed before edits.

## Confirmed Differences

- `PROVIDER_IDS` contains the same provider IDs as upstream but not in upstream `socialProviderList` order.
- `crates/openauth-social-providers/src/lib.rs` still describes provider modules as placeholders, which is inaccurate.
- Several userinfo methods return `Err` on missing access tokens, HTTP non-success, request failures, or JSON decode failures where upstream `getUserInfo` returns `null`. The affected concrete providers in this pass are Figma, Railway, Linear, Kick, Reddit, Roblox, Spotify, and Polar.
- Several additional network-backed userinfo paths still propagated transport or JSON decode errors where upstream resolves `null`: Atlassian, Cognito access-token fallback, Discord, Kakao, Line access-token fallback, Naver, PayPal, Slack, Tiktok, WeChat, HuggingFace, Salesforce, and Vercel.
- Core social callback and ID-token routes discarded `handle_oauth_user_info` account cookies when `account.store_account_cookie` was enabled.
- Account token refresh routes persisted refreshed tokens but did not emit the refreshed `account_data` cookie when `account.store_account_cookie` was enabled.
- `AccountLinkingOptions::allow_unlinking_all` existed but the unlink route ignored it and always rejected unlinking the last account.
- Explicit social account linking diverged from upstream in several security-sensitive paths: it accepted already-linked provider accounts without checking whether they belonged to the current user, did not update tokens on an already-linked account, did not honor `account_linking.enabled` or trusted-provider/email-verified checks, and did not honor `update_user_info_on_link`.
- Rust intentionally exposes stronger typed options and mapper patch structs instead of accepting arbitrary JavaScript object spreads.

## Risks

- Returning `Ok(None)` for userinfo failures reduces diagnostics at the provider method boundary, but it matches upstream's observable social callback behavior and avoids treating absent provider profile data as an infrastructure failure.
- Keeping explicit errors for token exchange, ID token validation helpers, and malformed security tokens is important because those paths are security-sensitive and not equivalent to a missing profile.
- Broad callback customization parity for every upstream `getUserInfo`, `mapProfileToUser`, `refreshAccessToken`, and `verifyIdToken` hook is not implemented uniformly across all Rust providers; adding that everywhere would widen the public API and should be a separate design pass.

## Proposed Fixes

- Align `PROVIDER_IDS` order exactly with upstream `socialProviderList`.
- Replace stale placeholder crate docs with accurate server-side provider catalog documentation.
- Change Figma and Railway `get_user_info` return types to `Result<Option<_>, OAuthError>` and adapt their runtime wrappers.
- Normalize userinfo missing access token and provider fetch/decode failure behavior to `Ok(None)` for Figma, Railway, Linear, Kick, Reddit, Roblox, Spotify, and Polar.
- Continue the same userinfo-null normalization for remaining network-backed paths that still propagate transport or JSON decode errors: Atlassian, Cognito access-token fallback, Discord, Kakao, Line access-token fallback, Naver, PayPal, Slack, Tiktok, and WeChat.
- Complete the same userinfo-null normalization for HuggingFace, Salesforce, and Vercel JSON/transport failures.
- Leave token exchange, refresh token, and ID token verification error handling explicit.
- Preserve generated/refreshed `account_data` cookies on OAuth callback, ID-token sign-in, `get-access-token`, and `refresh-token` responses when `account.store_account_cookie` is enabled.
- Honor `allow_unlinking_all` in the unlink route.
- Bring explicit link-social behavior closer to upstream by rejecting disabled/untrusted unverified links, rejecting provider accounts already linked to another user, updating tokens for same-user linked accounts, and applying `update_user_info_on_link` after successful explicit links.

## Tests To Add Or Update

- Add a registry test asserting `PROVIDER_IDS` exactly equals upstream order and contents.
- Add or update provider tests proving missing access tokens return `Ok(None)` for Figma, Railway, Linear, Kick, Reddit, Roblox, Spotify, and Polar.
- Add runtime wrapper coverage for Figma and Railway to verify the trait path also returns `None` instead of an error.
- Add a Tiktok missing-token regression test; rely on existing provider tests plus scoped clippy/nextest for the mechanical userinfo error-normalization paths where endpoints are fixed constants or already covered by per-provider HTTP tests.
- Keep existing endpoint, scope, token form, profile mapping, and ID token tests unchanged unless signatures require mechanical updates.
- Add focused core route regressions for account cookies on social callback and token refresh.
- Add a focused unlink route regression for `allow_unlinking_all`.
- Add focused link-social regressions for disabled/untrusted links, cross-user account ownership, token updates for same-user links, and `update_user_info_on_link`.
- Add OAuth callback link-social regressions for provider accounts already linked to a different user and untrusted unverified providers redirecting with upstream-compatible errors.
- Add provider-local userinfo regressions for malformed JSON returning `None` for HuggingFace, Salesforce, and Vercel.

## Items Intentionally Left Unchanged

- No database schema or query changes.
- No unrelated account/session lifecycle changes beyond upstream-parity cookie/link-account behavior.
- No public route request/response shape changes.
- No new dependencies.
- No full workspace verification unless changes unexpectedly cross crate boundaries.
- No broad API expansion for provider-specific custom callbacks beyond existing Rust surfaces.
- No broad constructor expansion solely to inject every fixed upstream userinfo endpoint for negative-path tests.
- Core social callback and account-token route behavior is in scope when it consumes this crate through `SocialOAuthProvider`; the current pass identified that `handle_oauth_user_info` and token refresh persistence already create/update account data, but the social callback/id-token and refresh responses dropped `account_data` cookies when `account.store_account_cookie` was enabled.
- Core account-linking parity also includes honoring `account.account_linking.allow_unlinking_all`; OpenAuth exposed the option but the unlink route still hard-blocked the last account.

## Server-Side Parity Assessment

Estimated server-side parity after this pass: about 95%.

The crate now has full built-in provider coverage, upstream registry order, high endpoint/scope/token-form parity, typed profile mapping for all providers, explicit validation for required credentials and PKCE, and upstream-like `null` behavior for userinfo fetch failures. The remaining gap is mostly API surface rather than core OAuth behavior: upstream JavaScript exposes broad per-provider callback hooks (`getUserInfo`, `mapProfileToUser`, `refreshAccessToken`, `verifyIdToken`) uniformly, while Rust exposes these selectively where the crate already has typed extension points. The second pass also removed the last meaningful userinfo JSON/transport error propagation in built-in providers; the remaining `?` paths in WeChat are token exchange/refresh paths, where explicit errors remain appropriate. The cross-crate social route pass also preserves generated/refreshed account cookies on OAuth callback, id-token, `get-access-token`, and `refresh-token` responses when `account.store_account_cookie` is enabled.

The explicit account-linking server flow now also matches the important upstream security boundaries: disabled linking and untrusted unverified providers are rejected for new links, an already-linked account must belong to the current user, same-user OAuth callback links refresh stored tokens, already-linked id-token links still return success before linking policy checks, and `update_user_info_on_link` is honored for new id-token links.

## Verification Plan

```bash
cargo fmt --all --check
cargo clippy -p openauth-social-providers --all-targets -- -D warnings
cargo nextest run -p openauth-social-providers
cargo clippy -p openauth-core --all-targets -- -D warnings
cargo nextest run -p openauth-core
```
