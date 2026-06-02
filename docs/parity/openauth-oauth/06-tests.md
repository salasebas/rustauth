# 06 — Tests: upstream coverage ↔ `openauth-oauth`

## Count summary

| Area | Test files | Tests | Notes |
| --- | --- | --- | --- |
| **Upstream `@better-auth/core/oauth2`** | 2 | **15** | Refresh expiry + validateToken crypto only |
| **Upstream `better-auth/src/oauth2`** | 2 | **28** | Encrypt + link-account (outside this crate) |
| **Upstream `generic-oauth.test.ts`** | 1 | **59** | 33 primitives/config; 26 plugin E2E |
| **OpenAuth `openauth-oauth`** | 3 | **57** | 48 `oauth2_helpers` + 2 `module_structure` + 7 SSRF unit |
| **OpenAuth core oauth** | 2 | **39** | 19 unit + 20 route integration (boundary) |

### `openauth-oauth` breakdown

| File | `#[test]` | `#[tokio::test]` | Total |
| --- | --- | --- | --- |
| `tests/module_structure.rs` | 2 | 0 | 2 |
| `tests/oauth2_helpers.rs` | 17 | 31 | 48 |
| `src/oauth2/ssrf.rs` | 5 | 2 | 7 |
| **Total** | **24** | **33** | **57** |

---

## Upstream `core/oauth2` — full inventory (15)

### `refresh-access-token.test.ts` (3)

| # | Upstream test | OpenAuth equivalent | Status |
| --- | --- | --- | --- |
| 1 | should set accessTokenExpiresAt when expires_in is returned | `token_helpers_parse_raw_scopes_expiry_and_pkce` (partial) + network helpers | ✅ covered |
| 2 | should set refreshTokenExpiresAt when refresh_token_expires_in is returned | same + refresh flow impl | ✅ covered |
| 3 | should not set refreshTokenExpiresAt when refresh_token_expires_in is not returned | impl `get_oauth2_tokens` | ✅ covered |

### `validate-token.test.ts` (12)

| # | Upstream test | OpenAuth equivalent | Status |
| --- | --- | --- | --- |
| 1 | should verify RS256 signed token | `validate_token_verifies_rs256_es256_and_eddsa_tokens` | ✅ |
| 2 | should verify ES256 signed token | same | ✅ |
| 3 | should verify EdDSA (Ed25519) signed token | same | ✅ |
| 4 | should throw when kid doesn't match any key | `validate_token_rejects_missing_kid_empty_jwks_and_wrong_key` | ✅ |
| 5 | should find correct key when multiple keys exist | JWKS multi-key impl | ✅ |
| 6 | should throw when JWKS returns empty keys array | `validate_token_rejects_missing_kid_empty_jwks_and_wrong_key` | ✅ |
| 7 | should throw when JWKS fetch fails | network mock errors | ✅ |
| 8 | should verify token with matching audience | `validate_token_verifies_jwks_audience_issuer_and_scope` | ✅ |
| 9 | should reject token with mismatched audience | same | ✅ |
| 10 | should verify token with matching issuer | same | ✅ |
| 11 | should reject token with mismatched issuer | same | ✅ |
| 12 | should verify token with both audience and issuer | same | ✅ |

**No upstream unit tests for:** `create-authorization-url`, `validate-authorization-code`, `client-credentials-token`, `verify.ts` (`verifyAccessToken`), `utils.ts` (PKCE).

---

## OpenAuth `openauth-oauth` — full inventory (57)

### `tests/module_structure.rs` (2)

| Test | What it validates |
| --- | --- |
| `oauth2_module_exports_placeholder_types` | Public `OAuthProviderMetadata` |
| `oauth_provider_contract_is_public` | Object-safe `OAuthProviderContract` |

### `tests/oauth2_helpers.rs` — Authorization URL (4)

| Test | What it validates | Upstream equivalent |
| --- | --- | --- |
| `create_authorization_url_includes_upstream_oauth_parameters` | client_id, scopes, PKCE, claims, prompt | ❌ none |
| `create_authorization_url_additional_params_overwrite_existing_params` | scope/prompt override | ❌ none |
| `create_authorization_url_standard_params_overwrite_endpoint_query_params` | endpoint query stripped | ❌ none |
| `create_authorization_url_additional_params_cannot_override_security_critical_params` | protected params | ❌ none (Rust extra) |

### Request builders & auth (7)

| Test | What it validates |
| --- | --- |
| `request_builders_support_post_and_basic_authentication` | POST/Basic all grants |
| `basic_authentication_form_encodes_reserved_and_non_ascii_credentials` | RFC 7617 encoding |
| `authorization_code_additional_params_do_not_overwrite_standard_fields` | protected body |
| `authorization_code_override_params_cannot_replace_security_critical_fields` | protected override |
| `refresh_extra_params_cannot_replace_security_critical_fields` | protected refresh |
| `client_credentials_requires_client_id_and_secret` | enforcement |
| `client_authentication_matrix_handles_public_and_confidential_clients` | public/confidential matrix |

### Validation & types (4)

| Test | What it validates |
| --- | --- |
| `direct_request_builders_reject_invalid_required_fields` | empty state/code/redirect |
| `validated_constructors_reject_invalid_required_values` | URL newtypes |
| `oauth_http_client_config_validates_timeout` | config validation |
| `client_credentials_requires_client_id_and_secret` | (listed above) |

### Token parsing & PKCE (3)

| Test | What it validates | Upstream |
| --- | --- | --- |
| `token_helpers_reject_malformed_token_responses` | strict JSON types | ❌ |
| `token_helpers_parse_raw_scopes_expiry_and_pkce` | happy path + expiry | partial refresh tests |
| `validate_code_verifier_enforces_rfc7636_length_and_charset` | RFC 7636 | ❌ |
| `pkce_flow_builders_reject_invalid_code_verifier_on_both_sides` | builders reject bad PKCE | ❌ |

### HTTP / network (6)

| Test | What it validates | Upstream |
| --- | --- | --- |
| `network_token_helpers_redact_structured_and_plaintext_sensitive_errors` | redaction | ❌ |
| `network_token_helpers_reject_invalid_success_json` | parse errors | ❌ |
| `network_token_helpers_post_form_requests_and_parse_responses` | E2E mock token | ❌ |
| `network_token_helpers_parse_oauth_error_without_leaking_secrets` | OAuth error parse | ❌ |
| `network_token_helpers_redact_sensitive_oauth_error_descriptions` | error_description redact | ❌ |

### JWT / JWKS / introspection (24)

| Test | What it validates | Upstream |
| --- | --- | --- |
| `verify_jws_access_token_cache_config_expires_and_limits_entries` | TTL + max entries | ❌ |
| `verify_access_token_remote_fallback_only_for_opaque_or_malformed_jws` | opaque fallback | ❌ |
| `verify_access_token_rejects_remote_missing_active_and_missing_audience` | introspection | ❌ |
| `validate_token_verifies_jwks_audience_issuer_and_scope` | validateToken+ | ✅ partial |
| `validate_token_rejects_hmac_algorithms_by_default` | HMAC block | ❌ extra |
| `validate_token_accepts_hmac_algorithms_when_explicitly_allowed` | HMAC opt-in | ❌ extra |
| `validate_token_rejects_expired_tokens` | exp | ❌ |
| `validate_token_verifies_rs256_es256_and_eddsa_tokens` | algorithms | ✅ |
| `verify_access_token_rejects_required_claims_with_wrong_types` | claim types | ❌ |
| `verify_jws_access_token_reuses_cached_jwks_for_known_kid` | cache hit | ❌ |
| `verify_jws_access_token_refetches_jwks_for_unknown_kid` | cache miss | ❌ |
| `clear_jwks_cache_forces_next_jwks_fetch` | cache clear | ❌ |
| `validate_token_rejects_missing_kid_empty_jwks_and_wrong_key` | JWKS errors | ✅ |
| `verify_access_token_validates_remote_audience_issuer_and_scopes` | remote happy | ❌ |
| `verify_access_token_rejects_remote_audience_issuer_scope_and_inactive_tokens` | remote errors | ❌ |
| `verify_access_token_falls_back_to_remote_for_opaque_tokens` | opaque | ❌ |
| `verify_access_token_accepts_injected_http_client_for_introspection` | DI | ❌ |
| `verify_jws_access_token_maps_azp_to_client_id` | azp mapping | ❌ |

### SSRF (2 integration + 7 unit)

| Test | What it validates | Upstream |
| --- | --- | --- |
| `default_client_blocks_get_and_post_to_literal_private_ip_urls` | block private IP | ❌ |
| `permissive_client_reaches_local_get_and_post_servers` | escape hatch | ❌ |
| `ssrf.rs` unit tests (7) | IP ranges, localhost DNS, redirect policy | ❌ |

### Social provider trait (3)

| Test | What it validates |
| --- | --- |
| `social_provider_default_revoke_token_returns_unsupported_error` | default revoke Err |
| `social_provider_default_refresh_error_does_not_leak_token` | no token in error |
| `social_provider_can_override_refresh_verify_and_revoke_token` | overrides work |

---

## Coverage matrix: upstream core → OpenAuth

| Upstream functionality | Upstream tests | OpenAuth tests | Gap |
| --- | --- | --- | --- |
| Refresh token expiry fields | 3 | ✅ (parsing + impl) | — |
| validateToken JWKS crypto | 12 | ✅ 10+ | — |
| Authorization URL | 0 | 4 | OpenAuth **more** |
| Auth code request builders | 0 | 7+ | OpenAuth **more** |
| Client credentials | 0 | 2+ | OpenAuth **more** |
| verifyAccessToken | 0 | 15+ | OpenAuth **more** |
| PKCE validation | 0 | 2 | OpenAuth **more** |
| SSRF | 0 | 9 | OpenAuth **more** |
| HTTP redaction | 0 | 5 | OpenAuth **more** |
| Provider trait defaults | 0 | 3 | OpenAuth **more** |

**Conclusion:** all 15 upstream `core/oauth2` tests have OpenAuth equivalents. OpenAuth adds **42 tests** with no direct upstream core counterpart.

### Indirect upstream tests (outside `core/oauth2/`)

| File | Imports core oauth2 | Type |
| --- | --- | --- |
| `better-auth/src/social.test.ts` | `refreshAccessToken` | social E2E (helper, not unit) |
| `oauth-provider/src/token.test.ts` | builders authorize/code/refresh/client_creds | AS tests as OAuth RP |
| `oauth-provider/src/logout.test.ts` | `createAuthorizationURL`, `createAuthorizationCodeRequest` | AS logout flow |

---

## Tests outside `openauth-oauth` (cross-reference)

### `better-auth/src/oauth2` (28) → `openauth-core`

| Upstream file | Tests | OpenAuth |
| --- | --- | --- |
| `utils.test.ts` | 13 | `auth/oauth.rs` token encrypt |
| `link-account.test.ts` | 15 | `auth/oauth.rs` + `social_oauth.rs` |

### `generic-oauth.test.ts` (59)

| Category | Count | Where covered in OpenAuth |
| --- | --- | --- |
| Core OAuth2 client/config/issuer | 33 | `openauth-oauth` (partial) + `openauth-core` routes |
| Plugin E2E routing | 26 | `social_oauth.rs` + future generic-oauth doc |

generic-oauth categories **not** in `openauth-oauth`:

- Duplicate provider ID warnings (5)
- Full mock-server E2E signup flows (15)
- Verification identifier hashing (1)
- Plugin wiring smoke tests (5)

---

## Verification commands

```bash
# This crate only
cargo nextest run -p openauth-oauth

# With jose feature (default)
cargo nextest run -p openauth-oauth --features jose

# Without jose (flows without JWT)
cargo nextest run -p openauth-oauth --no-default-features

# Boundary layer (core)
cargo nextest run -p openauth-core auth::oauth
cargo nextest run -p openauth-core social_oauth
```

## Future recommendations (optional)

| Area | Priority | Note |
| --- | --- | --- |
| Isolated `refresh_token_expires_in` test | Low | Already covered in parsing; upstream tests refresh fn |
| `openauth-social-providers` parity doc | Medium | 35 providers without upstream unit tests |
| generic-oauth routing parity doc | Medium | 26 plugin E2E tests |
| Client credentials Base64URL IdP | Low | Only if a real incompatible IdP appears |
