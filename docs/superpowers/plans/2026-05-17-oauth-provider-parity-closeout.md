# OAuth Provider Parity Closeout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the remaining server-side OAuth 2.1/OIDC provider parity gaps against `upstream/better-auth/1.6.9/repository/packages/oauth-provider` while keeping the Rust crate idiomatic, modular, and secure.

**Architecture:** Keep `crates/openauth-oauth-provider` split by behavior: options/schema/models are passive data, client/token/consent/authorize modules own domain behavior, and endpoints only adapt HTTP requests to those functions. Database table names stay plural snake_case physically, while public OAuth JSON remains OAuth/OIDC compatible.

**Tech Stack:** Rust, `openauth-core` `AuthRouter` and `DbAdapter`, `openauth-plugins::jwt`, `serde_json`, `time`, `http`, `url`, `sha2`, `hmac`, `subtle`, `data-encoding`, `josekit`, `tokio` tests.

---

## File Structure

- Modify: `crates/openauth-oauth-provider/src/lib.rs`
  - Public exports and plugin assembly only. Add module declarations when new focused modules are introduced.
- Modify: `crates/openauth-oauth-provider/src/client.rs`
  - Dynamic registration, client CRUD, redirect URI validation, client secret handling, pairwise sector validation.
- Modify: `crates/openauth-oauth-provider/src/endpoints.rs`
  - Thin HTTP adapter. It should parse requests, call focused domain helpers, and serialize OAuth-compatible responses.
- Create or modify: `crates/openauth-oauth-provider/src/authorize.rs`
  - Authorization request validation, prompt decisions, redirect error building, pending authorization state.
- Create or modify: `crates/openauth-oauth-provider/src/consent.rs`
  - `oauth_consents` helpers: find, create, update, delete, scope coverage checks, expiry checks.
- Modify: `crates/openauth-oauth-provider/src/token.rs`
  - Authorization code, refresh token, client credentials, PKCE, opaque/JWT token issuing, token lookup, revoke/introspect helpers.
- Modify: `crates/openauth-oauth-provider/src/mcp.rs`
  - Server-side MCP auth helpers and metadata/challenge behavior only.
- Modify: `crates/openauth-oauth-provider/tests/oauth_provider.rs`
  - Focused integration tests for observable endpoint behavior.
- Create: `crates/openauth-oauth-provider/tests/upstream_mapping.md`
  - Mapping of upstream OAuth provider tests to Rust server-only coverage and explicit non-applicable browser/client cases.

## Current Baseline

- [x] Modularized the crate into small files: `options`, `schema`, `models`, `metadata`, `client`, `token`, `endpoints`, `mcp`, `error`, `utils`.
- [x] Added schema contributions with physical tables `oauth_clients`, `oauth_refresh_tokens`, `oauth_access_tokens`, `oauth_consents`.
- [x] Added tests that assert plural snake_case tables and fields.
- [x] Implemented Dynamic Client Registration, client secret hashing/encryption, OAuth metadata, authorization code, client credentials, refresh rotation, PKCE S256, revoke, introspect, userinfo, logout, JWT/JWKS integration, HS256 fallback, JWT access tokens with `resource`, resource audience validation, and pairwise subject identifiers.
- [x] Verified current baseline with `cargo test -p openauth-oauth-provider`, `cargo test -p openauth-core`, `cargo test -p openauth-plugins`, and `cargo clippy --all-targets --all-features --locked -- -D warnings`.

### Task 1: Pairwise DCR Sector Validation

**Files:**
- Modify: `crates/openauth-oauth-provider/src/client.rs`
- Modify: `crates/openauth-oauth-provider/tests/oauth_provider.rs`

- [x] **Step 1: Write failing registration coverage**

Add a test named `pairwise_registration_requires_single_redirect_sector` that:

```rust
#[tokio::test]
async fn pairwise_registration_requires_single_redirect_sector() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            pairwise_secret: Some("pairwise-secret-12345678901234567890".to_owned()),
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/register",
            r#"{"redirect_uris":["https://rp.example/callback","https://other.example/callback"],"subject_type":"pairwise"}"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/register",
            r#"{"redirect_uris":["https://rp.example:443/callback","https://rp.example:8443/callback"],"subject_type":"pairwise"}"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/register",
            r#"{"redirect_uris":["https://rp.example/callback","https://rp.example/alt"],"subject_type":"pairwise"}"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    Ok(())
}
```

- [x] **Step 2: Run the focused test**

Run: `cargo test -p openauth-oauth-provider pairwise_registration_requires_single_redirect_sector`

Expected before implementation: FAIL on the `:443` versus `:8443` case if the implementation only compares host names without ports.

- [x] **Step 3: Include port in pairwise sector comparison**

In `client.rs`, replace host-only comparison with a helper equivalent to:

```rust
fn pairwise_sector(url: &url::Url) -> Option<String> {
    url.host_str().map(|host| match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    })
}
```

Then use `filter_map(|url| pairwise_sector(&url))` in pairwise client validation.

- [x] **Step 4: Verify the focused test passes**

Run: `cargo test -p openauth-oauth-provider pairwise_registration_requires_single_redirect_sector`

Expected: PASS.

- [x] **Step 5: Verify the provider suite**

Run: `cargo test -p openauth-oauth-provider`

Expected: PASS.

### Task 2: Consent Storage Helpers

**Files:**
- Create: `crates/openauth-oauth-provider/src/consent.rs`
- Modify: `crates/openauth-oauth-provider/src/lib.rs`
- Modify: `crates/openauth-oauth-provider/tests/oauth_provider.rs`

- [x] **Step 1: Write failing consent helper coverage**

Add tests that create a consent for `user_1`, `client_id`, and scope `openid email`, then assert:

```rust
assert!(has_granted_scopes(&consent, &["openid".to_owned()]));
assert!(has_granted_scopes(&consent, &["openid".to_owned(), "email".to_owned()]));
assert!(!has_granted_scopes(&consent, &["profile".to_owned()]));
```

- [x] **Step 2: Run focused consent tests**

Run: `cargo test -p openauth-oauth-provider consent`

Expected before implementation: FAIL because the helpers do not exist.

- [x] **Step 3: Implement consent helpers**

Create `consent.rs` with functions:

```rust
pub fn has_granted_scopes(consent: &SchemaConsent, requested: &[String]) -> bool
pub async fn find_consent(adapter: &dyn DbAdapter, user_id: &str, client_id: &str) -> Result<Option<SchemaConsent>, OpenAuthError>
pub async fn upsert_consent(adapter: &dyn DbAdapter, consent: ConsentGrantInput) -> Result<SchemaConsent, OpenAuthError>
pub async fn delete_consent(adapter: &dyn DbAdapter, user_id: &str, client_id: &str) -> Result<(), OpenAuthError>
```

Use `oauth_consents` model constants from `schema.rs`, split scopes with `utils::split_scope`, store timestamps with `utils::now`, and never use `unwrap()` in production code.

- [x] **Step 4: Verify consent tests**

Run: `cargo test -p openauth-oauth-provider consent`

Expected: PASS.

### Task 3: Authorize Prompt and Consent Decisions

**Files:**
- Create: `crates/openauth-oauth-provider/src/authorize.rs`
- Modify: `crates/openauth-oauth-provider/src/endpoints.rs`
- Modify: `crates/openauth-oauth-provider/src/lib.rs`
- Modify: `crates/openauth-oauth-provider/tests/oauth_provider.rs`

- [x] **Step 1: Write failing `prompt=none` tests**

Add tests for `/oauth2/authorize`:

```rust
// No authenticated session.
assert_eq!(redirect_error, "login_required");

// Authenticated session but missing consent for requested scope.
assert_eq!(redirect_error, "consent_required");
```

The redirect must preserve `state` when present.

- [x] **Step 2: Run focused authorize tests**

Run: `cargo test -p openauth-oauth-provider prompt`

Expected before implementation: FAIL because consent decisions are incomplete.

- [x] **Step 3: Implement prompt decision function**

Add a function with this shape:

```rust
pub enum AuthorizeDecision {
    IssueCode,
    RedirectToLogin,
    RedirectToConsent,
    RedirectError { error: &'static str, description: &'static str },
}

pub async fn decide_authorize(
    adapter: &dyn DbAdapter,
    client: &SchemaClient,
    session_user_id: Option<&str>,
    requested_scopes: &[String],
    prompt: Option<&str>,
) -> Result<AuthorizeDecision, OpenAuthError>
```

Rules:
- `prompt=login` always returns `RedirectToLogin`.
- Missing session returns `RedirectError(login_required)` for `prompt=none`, otherwise `RedirectToLogin`.
- Missing consent returns `RedirectError(consent_required)` for `prompt=none`, otherwise `RedirectToConsent`.
- `skip_consent=true` on the client allows `IssueCode` after session validation.
- Existing consent covering all requested scopes allows `IssueCode`.

- [x] **Step 4: Verify authorize prompt tests**

Run: `cargo test -p openauth-oauth-provider prompt`

Expected: PASS.

### Task 4: Consent and Continue Endpoints

**Files:**
- Modify: `crates/openauth-oauth-provider/src/authorize.rs`
- Modify: `crates/openauth-oauth-provider/src/consent.rs`
- Modify: `crates/openauth-oauth-provider/src/endpoints.rs`
- Modify: `crates/openauth-oauth-provider/tests/oauth_provider.rs`

- [x] **Step 1: Write failing endpoint tests**

Add tests for:
- `POST /oauth2/consent` with approval persists consent and redirects with an authorization code.
- `POST /oauth2/consent` with rejection redirects to the registered redirect URI with `error=access_denied`.
- `GET /oauth2/continue` resumes a valid pending authorization request.

- [x] **Step 2: Run focused endpoint tests**

Run: `cargo test -p openauth-oauth-provider consent_endpoint continue_endpoint`

Expected before implementation: FAIL because the endpoints are currently minimal.

- [x] **Step 3: Implement endpoint flow**

Use a pending authorization token stored server-side or encoded with existing secret-backed utilities. The stored payload must include `client_id`, `redirect_uri`, `scope`, `state`, `code_challenge`, `code_challenge_method`, `nonce`, `resource`, and authenticated `user_id`.

- [x] **Step 4: Verify endpoint tests**

Run: `cargo test -p openauth-oauth-provider consent_endpoint continue_endpoint`

Expected: PASS.

### Task 5: Introspection and Revocation Client Authentication

**Files:**
- Modify: `crates/openauth-oauth-provider/src/token.rs`
- Modify: `crates/openauth-oauth-provider/src/endpoints.rs`
- Modify: `crates/openauth-oauth-provider/tests/oauth_provider.rs`

- [x] **Step 1: Write failing auth tests**

Add tests proving:
- `/oauth2/introspect` returns `401 invalid_client` when called without valid client credentials for confidential clients.
- `/oauth2/revoke` returns `401 invalid_client` when the secret is wrong.
- `token_type_hint=access_token` and `token_type_hint=refresh_token` are accepted.

- [x] **Step 2: Run focused tests**

Run: `cargo test -p openauth-oauth-provider introspect revoke`

Expected before implementation: FAIL on missing auth checks.

- [x] **Step 3: Enforce client authentication**

Reuse the token endpoint client auth parser and secret verification. Confidential clients must authenticate. Public clients with `token_endpoint_auth_method=none` may use `client_id` without secret.

- [x] **Step 4: Verify focused tests**

Run: `cargo test -p openauth-oauth-provider introspect revoke`

Expected: PASS.

### Task 6: Client Ownership Guardrails

**Files:**
- Modify: `crates/openauth-oauth-provider/src/client.rs`
- Modify: `crates/openauth-oauth-provider/src/endpoints.rs`
- Modify: `crates/openauth-oauth-provider/tests/oauth_provider.rs`

- [x] **Step 1: Write failing ownership tests**

Add tests proving user `user_2` cannot call get/update/delete/rotate-secret on a client whose `user_id` is `user_1`.

- [x] **Step 2: Run focused ownership tests**

Run: `cargo test -p openauth-oauth-provider ownership`

Expected before implementation: FAIL where endpoints allow cross-user access.

- [x] **Step 3: Add ownership checks**

For user-facing client endpoints, compare the authenticated session user id with the stored client `user_id`. Return `403 access_denied` for mismatches. Keep unauthenticated public-client lookup endpoints read-only and limited to safe public metadata.

- [x] **Step 4: Verify ownership tests**

Run: `cargo test -p openauth-oauth-provider ownership`

Expected: PASS.

### Task 7: MCP Server-Side Parity Slice

**Files:**
- Modify: `crates/openauth-oauth-provider/src/mcp.rs`
- Modify: `crates/openauth-oauth-provider/tests/oauth_provider.rs`

- [x] **Step 1: Write failing MCP tests**

Add tests for:
- Bearer challenge metadata contains issuer, authorization endpoint, token endpoint, and supported scopes.
- A valid access token resolves to the expected subject and scopes.
- An invalid token returns an inactive/unauthorized result without leaking token hashes.

- [x] **Step 2: Run focused MCP tests**

Run: `cargo test -p openauth-oauth-provider mcp`

Expected before implementation: FAIL for missing parity behavior.

- [x] **Step 3: Implement MCP helpers**

Keep helpers server-only. Use existing introspection/token lookup functions rather than duplicating token validation logic.

- [x] **Step 4: Verify MCP tests**

Run: `cargo test -p openauth-oauth-provider mcp`

Expected: PASS.

### Task 8: Upstream Test Mapping and Final Verification

**Files:**
- Create: `crates/openauth-oauth-provider/tests/upstream_mapping.md`

- [x] **Step 1: Document mapping**

Create a table with columns:

```markdown
| Upstream area | Rust coverage | Notes |
| --- | --- | --- |
| options/config | `oauth_provider_uses_upstream_default_scopes_grants_and_expirations` | Server core parity. |
| schema | `oauth_provider_contributes_plural_snake_case_schema` | Physical names intentionally plural snake_case. |
| browser client plugin | Not applicable | Client TS/browser plugin is out of scope for server-only Rust core. |
```

Include all server-side areas already covered: metadata, DCR, client CRUD, authorize, token grants, PKCE, JWT/JWKS, pairwise, userinfo, introspect, revoke, logout, MCP, query serialization, timestamps.

- [x] **Step 2: Run full provider tests**

Run: `cargo test -p openauth-oauth-provider`

Expected: PASS.

- [x] **Step 3: Run related crate tests**

Run:

```bash
cargo test -p openauth-core
cargo test -p openauth-plugins
```

Expected: PASS.

- [x] **Step 4: Run lint gate**

Run: `cargo clippy --all-targets --all-features --locked -- -D warnings`

Expected: PASS with no warnings.

- [x] **Step 5: Update this checklist**

Mark every completed step with `[x]` and leave incomplete work unchecked with a short final status note in the assistant response.

### Task 9: Additional Upstream Guardrail Sweep

**Files:**
- Modify: `crates/openauth-oauth-provider/src/endpoints.rs`
- Modify: `crates/openauth-oauth-provider/src/consent.rs`
- Modify: `crates/openauth-oauth-provider/tests/oauth_provider.rs`
- Modify: `crates/openauth-oauth-provider/tests/upstream_mapping.md`

- [x] **Step 1: Consent management ownership**

Add and pass coverage that `/oauth2/get-consent`, `/oauth2/update-consent`, and `/oauth2/delete-consent` require a session and reject another user's consent.

- [x] **Step 2: Consent scope update validation**

Add and pass coverage that `/oauth2/update-consent` rejects scopes outside the owning client's allowed scopes and preserves existing scopes when `update.scopes` is omitted.

- [x] **Step 3: Client management update safety**

Add and pass coverage that `/oauth2/update-client` preserves omitted fields and rejects invalid scopes after merging the update with the stored client.

- [x] **Step 4: Public client secret rotation guard**

Add and pass coverage that `/oauth2/client/rotate-secret` rejects public clients or clients without a stored secret.

- [x] **Step 5: Metadata cache headers**

Add and pass coverage that OAuth/OIDC metadata responses include the upstream cache-control header.
