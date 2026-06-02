# 08 — Second-pass audit (code + tests)

Additional audit reading **line-by-line implementation**, OpenAuth monorepo usage, and upstream consumers outside `core/oauth2/`.

Date: **2026-06-01**.

---

## Summary: what was new

| # | Finding | Type | Action |
| --- | --- | --- | --- |
| 1 | Remote introspection without `aud` + required audience | **Closed** | `introspection_includes_audience` + tests |
| 2 | Upstream `tokenUrlParams` vs Rust `additional_params` (generic-oauth) | **Closed** | Aligned with upstream `additionalParams` |
| 3 | `verify_access_token` unused in monorepo | **Architecture** | AS/MCP uses another path |
| 4 | Upstream SSO uses `validateToken`; OpenAuth SSO uses `openidconnect` | **Outside crate** | See `openauth-sso` / `openauth-oidc` |
| 5 | Upstream `refreshAccessToken`: `scopes` can be `undefined` | **Minor** | Rust → `[]` |
| 6 | POST `client_id` with undefined IdP in TS | **Rust safer** | Does not send empty client_id |
| 7 | ~90 imports of core oauth2 upstream / 35 social providers | **Scope** | Social parity = other crate |
| 8 | `validate_token` used in prod: Apple, Facebook | **Coverage** | Well exercised in social-providers |
| 9 | `verify_jws_with_jwks` used by Facebook (sync path) | **Extra Rust** | Not in upstream index |
| 10 | RFC 9207 `iss` in generic-oauth | **Plugin** | In `openauth-plugins`, not oauth crate |

---

## 1. Remote introspection: `aud` validation (closed 2026-06-01)

### Upstream (`verify.ts` lines 189–195)

After successful introspection, if `introspect.aud` is **falsy**, decode with `verifyOptions` **without** `audience`:

```ts
const verify = introspect.aud
  ? UnsecuredJWT.decode(unsecuredJwt, opts.verifyOptions)
  : UnsecuredJWT.decode(unsecuredJwt, verifyOptions); // audience omitted
```

### OpenAuth (`introspection.rs` → `validate_introspection_claims`)

If `options.audience` is non-empty, always requires `audience_matches(claims.get("aud"), ...)`:

- If introspection response **does not include `aud`**, `audience_matches` → `false` → **error**.

### Impact

| Scenario | Upstream | OpenAuth |
| --- | --- | --- |
| Introspect without `aud`, caller requires audience | May **pass** | **Fails** (`audience mismatch`) |
| Introspect with correct `aud` | OK | OK |

**Severity:** medium for integrations using `verify_access_token` + RFC 7662 introspection with minimal responses (`active`, `sub`, `scope` without `aud`).

**Previous tests:** all remote introspection tests in `oauth2_helpers.rs` included `"aud"` in the mock JSON. **No test** for introspection without `aud` with required audience.

**Status:** aligned with upstream via `introspection_includes_audience` in `introspection.rs`. Tests in `verify_access_token_rejects_remote_missing_active_and_missing_audience`.

---

## 2. Generic OAuth: `tokenUrlParams` vs `additional_params` (closed 2026-06-01)

### Upstream (`generic-oauth/routes.ts`)

`tokenUrlParams` → `additionalParams` on `validateAuthorizationCode`:

- Only adds if `!body.has(key)` — **cannot replace** fields already set by the builder.

### OpenAuth (`openauth-plugins/.../provider.rs`)

`token_url_params` → `additional_params` on `AuthorizationCodeRequest` (formerly `override_params`):

- Same semantics as upstream: only adds keys **not already present** on the built body; protected fields remain immutable.
- Regression: `authorization_code_additional_params_cannot_replace_existing_body_fields` and `provider_token_url_params_cannot_override_protected_token_request_values`.

### Refresh

| | Upstream generic-oauth | OpenAuth |
| --- | --- | --- |
| `tokenUrlParams` on refresh | Not found in routes/index | `extra_params` on refresh (equivalent to upstream `extraParams`) |

OpenAuth refresh uses `extra_params` (append/skip), aligned with upstream refresh semantics.

**Status:** **Closed.** Generic OAuth uses `additional_params`, not `override_params`; behavior matches upstream `additionalParams` (no post-builder replacement of standard body fields).

---

## 3. `verify_access_token` — monorepo usage

### Upstream (production)

| Consumer | File |
| --- | --- |
| MCP middleware | `oauth-provider/src/mcp.ts` |
| Resource client SDK helper | `oauth-provider/src/client-resource.ts` |

Also `verifyJwsAccessToken` in `oauth-provider` introspect/revoke.

### OpenAuth

```bash
# grep in crates/ (excluding openauth-oauth tests)
openauth_oauth::verify_access_token  → 0 production uses
```

| Consumer | Implementation |
| --- | --- |
| `openauth-oauth-provider` MCP | `mcp::validate_bearer_token` → `token::validate_access_token` (**DB + JWT plugin**, not `openauth_oauth`) |
| Tests | `crates/openauth-oauth/tests/oauth2_helpers.rs` |

**Conclusion:** the crate **exports** `verify_access_token` with solid tests, but the monorepo **does not wire it** like upstream. MCP parity lives in `openauth-oauth-provider`, not reusing this helper.

**Not an oauth crate bug** — AS architecture decision. Document on the boundary with [oauth-provider parity](../openauth-oauth-provider/README.md).

---

## 4. `validate_token` — real usage in OpenAuth

| Crate | Use |
| --- | --- |
| `openauth-social-providers` | **Apple** (`validate_token_with_client` + nonce + max age) |
| `openauth-social-providers` | **Facebook** (`validate_token` + `verify_jws_with_jwks`) |
| `openauth-oauth` | Tests |

### Additional upstream

| Package | Use |
| --- | --- |
| `packages/sso` | `validateToken` in enterprise OIDC flow (`sso.ts` ~1582) |

### OpenAuth SSO

`openauth-sso` uses **`openidconnect`** for ID token verification, **not** `openauth_oauth::validate_token`.

**Architectural Δ** between Better Auth SSO and OpenAuth SSO — outside `openauth-oauth`, relevant for `openauth-sso` doc.

---

## 5. Minor parsing / grant details

### `scopes` after upstream refresh

```ts
scopes: data.scope?.split(" "),  // undefined if no scope
```

Rust `get_oauth2_tokens` → `scopes: Vec::new()` when missing.

### `client_id` in POST when missing in options (upstream)

`body.set("client_id", primaryClientId)` with `primaryClientId` potentially `undefined` in TS can produce invalid values.

Rust does not add `client_id` to POST body without a primary id.

### `validate_token` and JWKS cache (closed 2026-06-01)

`validate_token_with_client` uses `get_cached_jwks_for_token` (same path as `verify_jws_access_token`). Test: `validate_token_reuses_cached_jwks_for_known_kid`.

---

## 6. Extended upstream coverage (imports)

| Metric | Value |
| --- | --- |
| References to `@better-auth/core/oauth2` in `packages/` | **~90** files/lines |
| Social providers importing oauth2 primitives | **35/35** |
| Unit tests only in `core/oauth2/` | **15** |
| Tests exercising oauth2 via oauth-provider | token.test, logout.test, mcp |
| Tests via social.test.ts | `refreshAccessToken` helper |

OpenAuth concentrates primitive coverage in **57 tests** in this crate + social-providers tests per IdP.

---

## 7. Rust functions without exported upstream equivalent

| Rust | Notes |
| --- | --- |
| `validate_code_verifier` | Extra RFC 7636 |
| `verify_jws_with_jwks` (sync, in-memory JwkSet) | Used by Facebook; upstream only remote `validateToken` |
| `clear_jwks_cache` | Extra |
| `url_host_is_blocked_ip`, SSRF module | Extra; used by **openauth-sso** for endpoint validation |
| `OAuthHttpClient`, redaction | Extra |
| `AuthorizationEndpoint`, etc. | Extra newtypes |

---

## 8. Upstream functions without direct OpenAuth monorepo use

| Upstream | Status in OpenAuth |
| --- | --- |
| `verifyAccessToken` | Exported + tests; **0** prod wiring |
| `verifyJwsAccessToken` | Exported + tests; AS oauth-provider has its own logic |
| `clientCredentialsToken` | Exported; tests; AS/oauth-provider has its own flow |
| `AwaitableFunction` options | Not ported |

---

## 9. Suggested tests (oauth crate)

| Proposed test | Status |
| --- | --- |
| Remote introspection without `aud` + required audience | **Done** — `verify_access_token_rejects_remote_missing_active_and_missing_audience` |
| `validate_token` second call same JWKS URL (cache) | **Done** — `validate_token_reuses_cached_jwks_for_known_kid` |
| `refresh_access_token` with `resource` in body | **Done** — request builder tests in `oauth2_helpers.rs` |
| JWKS URL only, opaque token, no remote | Covered indirectly by `remote_verify` / opaque fallback flows |

---

## 10. Gap closure (2026-06-01)

| Gap | Status | Change |
| --- | --- | --- |
| §1 Introspection without `aud` | **Closed** | `introspection_includes_audience`; updated test + wrong `aud` case |
| §2 `token_url_params` → `additional_params` | **Closed** | `generic_oauth/provider.rs` aligned with upstream |
| §3 `verify_access_token` MCP wiring | **Documented** | No change (AS uses `openauth-oauth-provider`) |
| §5 `validate_token` without cache | **Closed** | `validate_token_with_client` uses `get_cached_jwks_for_token` |
| JWS → remote fallback | **Closed** | `local_jws_failure_allows_remote_fallback` when `remote_verify` present |
| Test `additionalParams` does not replace body | **Closed** | `authorization_code_additional_params_cannot_replace_existing_body_fields` |
| Test `validate_token` cache | **Closed** | `validate_token_reuses_cached_jwks_for_known_kid` |

**Tests:** `cargo nextest run -p openauth-oauth` → **57 passed**.

---

## 11. Second-pass verdict

**No critical open gaps** in grants, PKCE, standard exchange, introspection `aud`, `validate_token` JWKS cache, or generic-oauth `token_url_params` (closed 2026-06-01).

**Documented backlog (non-blocking):**

1. **Architecture:** crate `verify_access_token` does not feed MCP/AS — `openauth-oauth-provider` uses its own validation (§3).
2. **Minor:** `AwaitableFunction` on `ProviderOptions`; upstream client_credentials Base64URL quirk.

The crate is at **high parity** with `@better-auth/core/oauth2` for OAuth2 client primitives.
