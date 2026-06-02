# Deep audit (code + tests)

Second pass over **real sources and tests** (not READMEs). Reference: Better Auth **v1.6.9**.

---

## Methodology

| OpenAuth source | Upstream source |
|-----------------|-----------------|
| `crates/openauth-plugins/src/**/*.rs` | `packages/better-auth/src/plugins/**/*.ts` |
| `crates/openauth-plugins/tests/**/*.rs` | `packages/api-key/src/**/*.ts` |
| `rg 'create_auth_endpoint'`, hooks in `mod.rs` | `createAuthEndpoint`, `hooks`, `onRequest`, `init` |
| Count `#[test]` / `#[tokio::test]` | Count `it(` in `*.test.ts` |

---

## Findings that were missing or imprecise

### 1. Path-less upstream pattern vs HTTP routes in OpenAuth

Better Auth registers several endpoints with `createAuthEndpoint({ method })` **without a path**. They are invoked via `auth.api.*` (server RPC). OpenAuth exposes many as **explicit HTTP routes** under the base path.

| Capability | Upstream (v1.6.9) | OpenAuth | Parity impact |
|-----------|-------------------|----------|-----------------|
| Verify API key | Path-less `verifyApiKey` | `POST /api-key/verify` | 🎯 Broader HTTP surface |
| Delete expired keys | Path-less `deleteAllExpiredApiKeys` | `POST /api-key/delete-all-expired-api-keys` | 🎯 Same |
| Create email OTP | Path-less `createVerificationOTP` | `POST /email-otp/create-verification-otp` | 🎯 Same |
| Read email OTP | Path-less `getVerificationOTP` | `GET /email-otp/get-verification-otp` | 🎯 Same |
| Sign JWT | Path-less `signJWT` | `POST /sign-jwt` | 🎯 Same |
| Verify JWT | Path-less `verifyJWT` | `POST /verify-jwt` | 🎯 Same |
| View 2FA backup codes | Path-less `viewBackupCodes` | `POST /two-factor/view-backup-codes` | 🎯 Same (upstream docs name the path) |
| Add org member | Path-less `addMember` (`crud-members.ts`) | `POST /organization/add-member` | 🎯 Same |
| Generate TOTP | Path-less `generateTOTP` | `POST /two-factor/generate-totp` | 🎯 Same (closed Jun 2026) |

**Conclusion:** not arbitrary extra endpoints; they materialize upstream server-only APIs as REST.

### 2. Route with upstream parity — check-slug test added

| Route | Upstream | OpenAuth | OA tests |
|------|----------|----------|----------|
| `POST /organization/check-slug` | ✅ `crud-org.ts` | ✅ `organization/routes/org/query.rs` | ✅ Jun 2026 (`query.rs`) |

> **Correction (third pass):** doc 04 initially said no OA test. Upstream 1.6.9 has this route in both. See [05-third-pass-audit.md](./05-third-pass-audit.md).

### 3. MCP: metadata vs real routes

Upstream `getMCPProviderMetadata` advertises:

- `userinfo_endpoint`: `{baseURL}/mcp/userinfo`
- `jwks_uri`: `{baseURL}/mcp/jwks`

In snapshot 1.6.9, the `mcp` plugin **does not register handlers** for those paths (metadata only). Consent delegates to embedded `oidcProvider` (`POST /oauth2/consent`).

OpenAuth **does implement**:

| Route | OA | BA (registered route) |
|------|:--:|:--------------------:|
| `GET /mcp/userinfo` | ✅ | metadata only |
| `GET /mcp/jwks` | ✅ | metadata only |
| `POST /oauth2/consent` | ✅ | ✅ (via embedded OIDC) |

**Conclusion:** OpenAuth closes the gap between MCP metadata and effective routes.

### 4. `access` in `PLUGIN_IDS` without `AuthPlugin`

`access` exports RBAC helpers (`create_access_control`, `role`) but **does not build a mountable plugin**. Same as upstream. Listed in `PLUGIN_IDS` for ID alignment, not routes.

### 5. `haveibeenpwned`: dual ID

| Constant | Value |
|-----------|-------|
| `UPSTREAM_PLUGIN_ID` | `haveibeenpwned` |
| `RUNTIME_PLUGIN_ID` (plugin registry) | `have-i-been-pwned` |

Equivalent behavior; different runtime registry name.

### 6. Admin hook on **core** route

Admin filters impersonated sessions in an **`after /list-sessions`** hook (core route, not `/admin/*`). OpenAuth replicates in `admin/mod.rs`. Easy to miss in plugin-only matrices.

### 7. Anonymous: broad hook coverage

After-hooks on: `/sign-in*`, `/sign-up*`, `/callback*`, `/oauth2/callback*`, `/magic-link/verify*`, `/email-otp/verify-email*`, `/one-tap/callback*`, **`/passkey/verify-authentication*`** (passkey not in this crate), `/phone-number/verify*`.

Passkey matcher is prepared; passkey lives outside this crate.

### 8. Captcha: path matching

OpenAuth uses **prefix with segment boundary** (`endpoint_matches_path` in `captcha/mod.rs`) — avoids partial matches like `/sign-up/email-extra`. Upstream uses URL substring. **Possible divergence** on ambiguous paths.

### 9. Corrected test counts

Counting only `it(` (not `describe(`) gives more honest ratios:

| Plugin | OA `#[test]` | BA `it()` |
|--------|:------------:|:---------:|
| organization | 32 | **182** |
| api-key | 52 | **176** |
| email-otp | 31 | **73** |
| two-factor | 21 | **55** |
| admin | 29 | **71** |
| generic-oauth | 41 | **59** |
| phone-number | 22 | **32** |
| jwt | 33 | **36** |
| one-tap | 14 | **0** |
| **Crate total** | **610** | **986** (excl. test-utils, oidc-provider) |

`one-tap`: upstream has **no** `*.test.ts` in plugins; OpenAuth has **14** tests.

### 10. `integration_matrix`: minimal coverage

Only composes **7 plugins**: admin, organization, api_key, jwt, one_time_token, multi_session, two_factor.

20 plugins **not** in Docker E2E smoke (`#[ignore]`).

### 11. Automatic OpenAPI audit

`tests/open_api/mod.rs::generated_schema_audits_all_server_plugin_endpoints` walks **>80 paths** and validates operationId, summary, tags, responses. Strongest cross-cutting safety net in the crate; does not replace behavior tests.

### 12. Organization: route count

| | Count |
|---|----------|
| OpenAuth explicit paths | **36** |
| Upstream paths with string in `createAuthEndpoint` | **35** |
| Difference | none material (check-slug in both) |

Upstream: **28 callbacks** in `OrganizationOptions.organizationHooks` (not `AuthPlugin` hooks). OpenAuth mirrors via `OrganizationHooks` in options.

### 13. Error codes: plugins with explicit registration

OpenAuth registers `ERROR_CODES` / `with_error_code` slices in:

admin, anonymous, api_key, captcha, device_authorization, email_otp, generic_oauth, haveibeenpwned, multi_session, organization, phone_number, two_factor, username.

**No centralized registration:** jwt, siwe, mcp, magic_link, oauth_proxy, one_tap, bearer, custom_session, last_login_method (ad-hoc or core errors).

Organization upstream: **40+** `ORGANIZATION_ERROR_CODES` — OpenAuth `organization/errors.rs` aligns most.

### 14. two-factor: `view-backup-codes` exists upstream

Was wrongly classified as OpenAuth-only. Upstream defines it path-less in `two-factor/backup-codes/index.ts`; tests in `two-factor.test.ts` include `should not expose viewBackupCodes to client`. OpenAuth tests server consumption in `tests/two_factor/mod.rs`.

### 15. Phone number: sync-only callbacks

`phone_number/mod.rs` documents **synchronous** callbacks in Rust vs async upstream — Rust API decision.

### 16. Admin schema upstream

Initial subagent cited `impersonatedBy` on user; in upstream 1.6.9 it is on **session**, not user. OpenAuth: `session.impersonated_by`.

---

## Endpoint matrix: real differences (verified)

| Plugin | OpenAuth-only (HTTP) | Upstream-only (path string) | Notes |
|--------|----------------------|----------------------------|-------|
| api-key | `/api-key/verify`, `/api-key/delete-all-expired-api-keys` | — | upstream path-less |
| jwt | `/sign-jwt`, `/verify-jwt` | — | upstream path-less |
| two-factor | `/two-factor/generate-totp` | — | closed Jun 2026 |
| mcp | `/mcp/userinfo`, `/mcp/jwks` | — | upstream metadata without handler |
| two-factor | — | — | `view-backup-codes` path-less in both; OA exposes HTTP |

Admin, device-authorization, email-otp (named routes), generic-oauth, etc.: **named path parity** verified.

---

## OA tests not obvious from counts alone

| Plugin | Representative tests (fn names) |
|--------|--------------------------------------|
| admin | `list_users_supports_typed_filters_search_sort_and_pagination`, `core_list_sessions_filters_impersonated_sessions` |
| api_key | `concurrent_verification_consumes_remaining_only_once`, `fallback_secondary_storage_keeps_usage_updates_consistent_under_concurrency` |
| bearer | `raw_session_token_is_rejected_when_signature_is_required` |
| captcha | `captcha_prefix_does_not_match_partial_segment` |
| generic_oauth | 29 tests in `routes.rs` (issuer, state, callbacks) |
| magic_link | `upstream_parity.rs` (13 named scenarios) |
| oauth_proxy | `preview_callback_links_unverified_existing_user_when_google_is_trusted` |
| one_tap | 14 tests incl. trusted_providers / linking |
| open_api | `generated_schema_audits_all_server_plugin_endpoints` |
| organization | `list_members_supports_id_slug_pagination_filter_sort_and_total`, dynamic AC, check-slug |
| two_factor | `trusted_device_bypasses_second_factor_and_rotates_cookie`, view-backup-codes in backup flow |

---

## Upstream scenarios **without** OpenAuth tests (revised priority)

1. **organization** — 182 vs 32: large upstream matrices (multi-org isolation, re-invite)
2. **api-key** — clock/rate-limit/refill vitest timers (166 upstream tests)
3. **email-otp** — full HTTP matrix with bearer setups (73 upstream)
4. **two-factor** — `twoFactorMethods` in sign-in response, passwordless matrix
5. **username** — 33 upstream vs 12 OA (exhaustive validation)
6. **generic-oauth** — preset provider E2E, CSRF tampering (hashed identifier via core ✅)

---

## Plugins with verified server parity in tests (sample)

| Plugin | Test evidence |
|--------|----------------|
| multi_session | 22 tests; signed cookies, revoke, max sessions |
| oauth_proxy | 24 tests; encrypted profile, replay, trusted providers |
| one_time_token | 15 tests; cookie cache, OTT header, hashed storage |
| magic_link | `upstream_parity.rs` |
| bearer | 16 tests (> upstream 5) |
| device_authorization | 36 tests (~ upstream 31) |
| anonymous | 18 tests; exhaustive link hooks |

---

## Commands to re-audit

```bash
# OpenAuth endpoints
rg 'create_auth_endpoint\s*\(\s*"' crates/openauth-plugins/src -n

# Upstream endpoints
rg 'createAuthEndpoint\s*\(\s*"' reference/upstream-src/1.6.9/repository/packages/better-auth/src/plugins -n
rg 'createAuthEndpoint\s*\(\s*"' reference/upstream-src/1.6.9/repository/packages/api-key/src -n

# OA tests by name
rg '#\[(tokio::)?test\]' crates/openauth-plugins/tests -c

# Upstream tests (it only)
rg '\bit\s*\(' reference/upstream-src/1.6.9/repository/packages/better-auth/src/plugins --glob '*.test.ts' -c
```
