# OAuth Provider Upstream Test Mapping

Reference: `upstream/better-auth/1.6.9/repository/packages/oauth-provider`.

| Upstream area | Rust coverage | Notes |
| --- | --- | --- |
| Options/config defaults | `oauth_provider_uses_upstream_default_scopes_grants_and_expirations` | Covers default scopes, claims, expirations, grants, and storage mode. |
| Config validation | `oauth_provider_rejects_client_registration_scopes_not_in_server_scopes`, `oauth_provider_rejects_refresh_token_without_authorization_code_grant`, `oauth_provider_rejects_short_pairwise_secret`, `oauth_provider_rejects_hashed_client_secrets_without_jwt_plugin` | Rust errors are typed config errors instead of TS runtime exceptions. |
| Schema | `oauth_provider_contributes_plural_snake_case_schema` | Physical DB names intentionally use plural snake_case tables and snake_case fields. |
| Metadata | `metadata_endpoint_returns_oidc_server_metadata` | Covers OIDC discovery, core endpoint URLs, and upstream cache-control behavior. |
| Dynamic Client Registration | `dynamic_registration_creates_confidential_client_and_hashes_secret`, `dynamic_registration_cannot_enable_rp_initiated_logout` | DCR public JSON names stay OAuth-compatible. Stored secret is hashed/encrypted, not returned from DB. |
| Client credentials grant | `client_credentials_token_returns_bearer_token_and_persists_opaque_token` | Covers opaque access token persistence for server-to-server grant. |
| Authorization code grant | `authorization_code_flow_issues_access_and_refresh_tokens` | Covers authorize redirect, code exchange, access token, refresh token. |
| PKCE | `authorization_code_flow_enforces_pkce_s256_for_public_clients` | Public clients require S256 PKCE. Plain PKCE is rejected. |
| Refresh rotation | `refresh_token_grant_rotates_and_revokes_previous_refresh_token` | Covers refresh token rotation and revoked timestamp. |
| JWT/JWKS id_token | `openid_authorization_code_issues_signed_id_token_and_jwks` | Uses `openauth-plugins::jwt` when enabled. |
| JWT access token resource audience | `resource_parameter_issues_jwt_access_token_with_oauth_claims`, `resource_parameter_rejects_unconfigured_audience` | Covers `resource`, `aud`, `azp`, `scope`, and invalid audience rejection. |
| Pairwise subjects | `pairwise_subject_is_stable_by_sector_and_used_for_userinfo_and_introspection`, `pairwise_registration_requires_single_redirect_sector` | Covers stable per-sector subject, different subjects across sectors, and same-sector DCR validation including port. |
| Prompt handling | `authorize_prompt_none_returns_login_required_without_session`, `authorize_prompt_none_returns_consent_required_without_grant` | Covers upstream `prompt=none` redirect error behavior and state preservation. |
| Consent persistence | `consent_helpers_persist_update_delete_and_match_scopes`, `consent_endpoint_accepts_rejects_and_continue_resumes_pending_authorization`, `consent_management_endpoints_enforce_owner_session`, `update_consent_rejects_scopes_not_allowed_for_client`, `update_consent_without_scopes_preserves_existing_scopes` | Covers grant scope matching, upsert/delete, accept, reject, continue flow, ownership, allowed scope validation, and partial update preservation. |
| Introspection | `introspect_and_revoke_require_valid_client_authentication`, `pairwise_subject_is_stable_by_sector_and_used_for_userinfo_and_introspection` | Requires valid client auth and returns pairwise `sub` for opaque tokens. |
| Revocation | `introspect_and_revoke_require_valid_client_authentication` | Requires valid client auth and accepts `token_type_hint`. |
| Userinfo | `pairwise_subject_is_stable_by_sector_and_used_for_userinfo_and_introspection` | Covers bearer validation and scope-gated subject consistency. |
| RP-initiated logout | `rp_initiated_logout_rejects_invalid_id_token_hint`, `rp_initiated_logout_deletes_session_and_redirects_to_registered_uri` | Covers `id_token_hint`, session deletion, registered logout redirect, and state. |
| Client ownership/admin guardrails | `client_management_endpoints_reject_cross_user_ownership`, `rotate_secret_rejects_public_clients`, `update_client_preserves_omitted_fields`, `update_client_rejects_invalid_scope` | User-facing client management endpoints reject cross-user access, preserve partial updates, validate merged metadata, and prevent rotating secrets for public clients. |
| MCP server-side helpers | `mcp_helpers_return_metadata_challenge_and_validate_bearer_tokens` | Covers metadata, challenge header value, active bearer validation, and inactive invalid tokens. |
| Query serialization | `authorize_prompt_none_returns_login_required_without_session`, `authorize_prompt_none_returns_consent_required_without_grant`, `consent_endpoint_accepts_rejects_and_continue_resumes_pending_authorization` | Rust tests assert state preservation through redirects rather than porting TS `URLSearchParams` helper directly. |
| Timestamps | `authorization_code_flow_issues_access_and_refresh_tokens`, `refresh_token_grant_rotates_and_revokes_previous_refresh_token`, `consent_helpers_persist_update_delete_and_match_scopes` | Covers expiry/revocation/update timestamps through observable DB records. |
| Browser client plugin | Not applicable | `client.ts` and `oauthProviderClient` are intentionally out of scope for Rust server-only core. |
| Browser fetch redirect JSON behavior | Not applicable to core helper tests | OpenAuth Rust core exposes HTTP responses directly; browser SDK behavior should live in a future thin client. |
| TypeScript-only zod schemas | Covered by Rust types and endpoint parsing | Public payload names preserve OAuth JSON names where relevant; Rust structs remain idiomatic snake_case. |
