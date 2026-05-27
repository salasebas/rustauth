# API Key, Bearer, Captcha, Custom Session Upstream Parity Audit

## Summary

Audit target: server-side OpenAuth plugin behavior for `api-key`, `bearer`, `captcha`, and `custom_session` against Better Auth 1.6.9 upstream.

Goal: preserve upstream-observable behavior where it matters while keeping the Rust implementation explicit, secure, and consistent with the current OpenAuth plugin architecture.

## Upstream Files Inspected

- `upstream/better-auth/1.6.9/repository/packages/api-key/src/index.ts`
- `upstream/better-auth/1.6.9/repository/packages/api-key/src/types.ts`
- `upstream/better-auth/1.6.9/repository/packages/api-key/src/schema.ts`
- `upstream/better-auth/1.6.9/repository/packages/api-key/src/adapter.ts`
- `upstream/better-auth/1.6.9/repository/packages/api-key/src/rate-limit.ts`
- `upstream/better-auth/1.6.9/repository/packages/api-key/src/org-authorization.ts`
- `upstream/better-auth/1.6.9/repository/packages/api-key/src/routes/*.ts`
- `upstream/better-auth/1.6.9/repository/packages/api-key/src/api-key.test.ts`
- `upstream/better-auth/1.6.9/repository/packages/api-key/src/org-api-key.test.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/bearer/*`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/captcha/*`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/captcha/verify-handlers/*`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/custom-session/*`
- `upstream/better-auth/1.6.9/repository/docs/content/docs/plugins/api-key/*`
- `upstream/better-auth/1.6.9/repository/docs/content/docs/plugins/bearer.mdx`
- `upstream/better-auth/1.6.9/repository/docs/content/docs/plugins/captcha.mdx`

## OpenAuth Files Inspected

- `crates/openauth-plugins/src/api_key/**`
- `crates/openauth-plugins/src/bearer/**`
- `crates/openauth-plugins/src/captcha/**`
- `crates/openauth-plugins/src/custom_session/**`
- `crates/openauth-plugins/tests/api_key/**`
- `crates/openauth-plugins/tests/bearer/**`
- `crates/openauth-plugins/tests/captcha/mod.rs`
- `crates/openauth-plugins/tests/custom_session/**`
- `crates/openauth-plugins/tests/plugins.rs`

## Confirmed Matches

- API key routes, storage modes, hashing, public response redaction, quota accounting, rate-limit windows, organization authorization, secondary-storage key names, fallback cache invalidation, endpoint registration, and error catalog are broadly implemented.
- Bearer accepts signed and raw session tokens, preserves existing cookies, supports case-insensitive `Bearer`, handles percent-encoded signed tokens, and exposes `set-auth-token` without duplicating CORS exposed headers.
- Captcha supports Cloudflare Turnstile, Google reCAPTCHA, hCaptcha, and CaptchaFox with upstream-equivalent provider payloads, status mapping, and response error codes.
- Custom session transforms `/get-session`, optionally transforms `/multi-session/list-device-sessions`, preserves refreshed Set-Cookie headers, and allows custom shapes without user/session fields.

## Confirmed Differences

- API-key session mocking currently silently continues for invalid matched API keys, failed custom validators, organization-owned keys, validation failures, and missing referenced users. Upstream returns explicit API errors for these matched-key cases.
- API-key mocked sessions do not populate `ip_address` from configured request IP headers.
- API-key create currently defaults `remaining` to `refillAmount` when `remaining` is omitted, while upstream now preserves omitted/default `remaining` as `null`.
- API-key update returns the refill amount error for both one-sided refill fields; upstream distinguishes interval-without-amount as `REFILL_INTERVAL_AND_AMOUNT_REQUIRED`.
- Malformed secondary-storage API key payloads currently propagate a deserialization adapter error; upstream treats invalid secondary payloads as missing.
- Legacy double-stringified API key metadata is parsed for responses but not migrated back to database-backed storage.
- Captcha endpoint matching is exact route registration in Rust; upstream protects requests whose URL contains a configured endpoint string.
- Bearer and custom-session plugin options serialize with snake_case keys instead of upstream camelCase.
- Captcha missing secret key is rejected at plugin construction in Rust, while upstream returns a request-time 500. This is intentionally safer for production configuration.

## Risks

- API-key session-hook error changes make invalid API-key headers fail fast instead of falling through to cookie/session auth. This matches upstream for matched API-key configuration but can reveal integrations that were accidentally sending bad API key headers.
- Metadata migration writes are best-effort and must not fail the user request if the adapter update fails.
- Captcha substring matching can protect broader routes when users configure a broad endpoint such as `/sign-up`; this is upstream-compatible but should be documented by tests.

## Proposed Fixes

- Return explicit plugin API error responses from the API-key session hook for matched but invalid API-key inputs, while preserving no-match behavior.
- Add API-key request IP extraction using existing core IP utilities and configured `advanced.ip_address` options.
- Preserve `remaining: null` on create when omitted, regardless of refill settings.
- Split refill update validation so amount-only and interval-only cases produce the matching upstream error code.
- Make secondary-storage deserialization best-effort and return `None` for malformed payloads.
- Add best-effort database metadata normalization for API-key `get`, `list`, `verify`, and `update` response paths.
- Register captcha middleware on wildcard path and perform upstream-style `url.contains(endpoint)` filtering in the middleware.
- Serialize bearer and custom-session options with upstream camelCase field names.

## Tests To Add Or Update

- API key session hook rejects short keys, failed validators, org-owned session mocking, and missing referenced users; mocked session includes trusted request IP.
- API key create keeps omitted `remaining` as null when refill options are present.
- API key update interval-without-amount returns `REFILL_INTERVAL_AND_AMOUNT_REQUIRED`.
- API key secondary storage ignores malformed payloads.
- API key legacy metadata is returned parsed and migrated for database-backed get/list/verify/update.
- Captcha custom endpoint `/sign-up` protects `/sign-up/email`.
- Bearer and custom-session serialized options use upstream camelCase keys.

## Intentionally Left Unchanged

- TypeScript client SDKs, type inference tests, and browser-only helpers are not ported.
- No new dependencies are needed.
- OpenAuth's current server/direct-call emulation for API-key server-only fields remains unchanged because the Rust HTTP routing surface does not currently model the same distinction as Better Auth's direct server API.
- Upstream `USER_BANNED` behavior is not added unless OpenAuth core gains a first-class banned user field.
- Captcha missing secret key remains a startup/configuration error in Rust.
