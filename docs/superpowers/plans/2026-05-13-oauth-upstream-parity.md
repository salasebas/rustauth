# OAuth Upstream Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Close the missing Better Auth OAuth helper parity in `openauth-oauth`, `openauth-core`, and the public `openauth` re-export surface.

**Architecture:** Keep OAuth2 primitives in `openauth-oauth`; keep server-side OAuth behavior that needs context, adapters, sessions, cookies, or secrets in `openauth-core::auth::oauth`; keep `openauth` as a re-export crate only. Tests must be adapted from upstream behavior where it applies to the Rust API, with security behavior tested before implementation.

**Tech Stack:** Rust 2021, Cargo workspace crates, `josekit`, `reqwest`, `serde_json`, `time`, `url`, in-crate integration tests using local `TcpListener` servers.

---

## File Structure

- Modify `crates/openauth-oauth/src/oauth2/validate_authorization_code.rs`: add JWT temporal claim validation and reusable claim validation helpers.
- Modify `crates/openauth-oauth/src/oauth2/verify.rs`: implement upstream remote introspection semantics, local-to-remote fallback for opaque tokens, `azp -> client_id`, and remote `aud`/`iss` validation.
- Modify `crates/openauth-oauth/src/oauth2/authorization_url.rs`: make `additional_params` overwrite existing authorization URL query keys instead of duplicating them.
- Modify `crates/openauth-oauth/src/oauth2/provider.rs`: replace metadata-only provider type with an idiomatic public provider contract.
- Modify `crates/openauth-oauth/src/oauth2/tokens.rs`: add provider option support that belongs in primitives without moving server-side callbacks into oauth primitives.
- Modify `crates/openauth-oauth/tests/oauth2_helpers.rs`: extend upstream parity tests for JWT algorithms, JWKS errors, expiry, remote introspection, and authorization params.
- Modify `crates/openauth-core/src/auth/oauth/account_linking.rs`: fix email verification updates, override user info behavior, and account cookie output.
- Modify `crates/openauth-core/src/auth/oauth/state.rs`: add state mismatch behavior and consumed database state cleanup if the verification store supports deletion.
- Modify `crates/openauth-core/src/options.rs`: add `skip_state_cookie_check` only if state security cookie behavior is implemented.
- Modify `crates/openauth-core/tests/auth/oauth.rs`: extend upstream account linking, state, and token utility tests.
- Modify `crates/openauth/src/lib.rs` and `crates/openauth/tests/public_api.rs`: keep public re-export checks current.

---

### Task 1: OAuth JWT Validation Parity

**Files:**
- Modify: `crates/openauth-oauth/src/oauth2/validate_authorization_code.rs`
- Test: `crates/openauth-oauth/tests/oauth2_helpers.rs`

- [x] **Step 1: Write failing tests for temporal claims and upstream algorithms**

Add tests that create HS256, RS256, ES256, and EdDSA tokens through `josekit`, then verify these cases:

```rust
#[tokio::test]
async fn validate_token_rejects_expired_tokens() {
    let (token, jwks_url) = signed_hs256_token_with_claims(json!({
        "sub": "user-123",
        "iss": "https://issuer.example.com",
        "aud": "client-id",
        "exp": OffsetDateTime::now_utc().unix_timestamp() - 60
    }));

    let result = validate_token(
        &token,
        &jwks_url,
        TokenValidationOptions {
            audience: vec!["client-id".to_owned()],
            issuer: vec!["https://issuer.example.com".to_owned()],
        },
    )
    .await;

    assert!(result.is_err());
}
```

Also add tests named:

```rust
#[tokio::test]
async fn validate_token_verifies_rs256_es256_and_eddsa_tokens() { /* full helper-backed assertions */ }

#[tokio::test]
async fn validate_token_rejects_missing_kid_empty_jwks_and_wrong_key() { /* wrong kid, empty keys */ }
```

- [x] **Step 2: Run RED verification**

Run:

```bash
cargo test -p openauth-oauth --test oauth2_helpers validate_token -- --nocapture
```

Expected: at least `validate_token_rejects_expired_tokens` fails because temporal claims are not validated.

- [x] **Step 3: Implement temporal claim validation**

In `validate_payload_claims`, validate these claims when present:

```rust
let now = OffsetDateTime::now_utc().unix_timestamp();
if let Some(exp) = numeric_claim(claims.get("exp")) {
    if exp <= now {
        return Err(OAuthError::TokenVerification("token expired".to_owned()));
    }
}
if let Some(nbf) = numeric_claim(claims.get("nbf")) {
    if nbf > now {
        return Err(OAuthError::TokenVerification("token not active".to_owned()));
    }
}
if let Some(iat) = numeric_claim(claims.get("iat")) {
    if iat > now + 60 {
        return Err(OAuthError::TokenVerification("token issued in the future".to_owned()));
    }
}
```

Add:

```rust
fn numeric_claim(value: Option<&Value>) -> Option<i64> {
    match value {
        Some(Value::Number(number)) => number.as_i64().or_else(|| number.as_u64().and_then(|v| i64::try_from(v).ok())),
        _ => None,
    }
}
```

- [x] **Step 4: Run GREEN verification**

Run:

```bash
cargo test -p openauth-oauth --test oauth2_helpers validate_token -- --nocapture
```

Expected: all `validate_token_*` tests pass.

---

### Task 2: Access Token Verification and Introspection Parity

**Files:**
- Modify: `crates/openauth-oauth/src/oauth2/verify.rs`
- Test: `crates/openauth-oauth/tests/oauth2_helpers.rs`

- [x] **Step 1: Write failing tests for remote introspection**

Add tests:

```rust
#[tokio::test]
async fn verify_access_token_validates_remote_audience_issuer_and_scopes() {
    let server = JsonServer::spawn(json!({
        "active": true,
        "sub": "user-123",
        "aud": "api-client",
        "iss": "https://issuer.example.com",
        "scope": "read write"
    }));

    let payload = verify_access_token(
        "opaque-token",
        VerifyAccessTokenOptions {
            verify_options: TokenValidationOptions {
                audience: vec!["api-client".to_owned()],
                issuer: vec!["https://issuer.example.com".to_owned()],
            },
            scopes: vec!["read".to_owned()],
            jwks_url: None,
            remote_verify: Some(VerifyAccessTokenRemote {
                introspect_url: server.url(),
                client_id: "client".to_owned(),
                client_secret: "secret".to_owned(),
                force: true,
            }),
        },
    )
    .await
    .expect("remote introspection should pass");

    assert_eq!(payload["sub"], "user-123");
}
```

Add companion tests for wrong audience, inactive token, missing scope, opaque-token fallback when local decode is invalid, and `azp` mapping:

```rust
#[tokio::test]
async fn verify_jws_access_token_maps_azp_to_client_id() { /* signed token with azp */ }
```

- [x] **Step 2: Run RED verification**

Run:

```bash
cargo test -p openauth-oauth --test oauth2_helpers verify_access_token -- --nocapture
```

Expected: remote wrong-audience test fails because remote payload claims are not validated.

- [x] **Step 3: Implement remote claim validation and fallback**

In `verify_access_token`:

```rust
let mut local_error = None;
if let Some(jwks_url) = &options.jwks_url {
    if !options.remote_verify.as_ref().is_some_and(|remote| remote.force) {
        match verify_jws_access_token(token, jwks_url, options.verify_options.clone()).await {
            Ok(result) => payload = Some(introspection_payload(result.payload)),
            Err(error) if options.remote_verify.is_some() && is_opaque_token_error(&error) => {
                local_error = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
}
```

After remote JSON parse:

```rust
validate_introspection_claims(&introspect, &options.verify_options)?;
payload = Some(introspect);
```

Implement helpers:

```rust
fn introspection_payload(mut payload: Value) -> Value {
    if let Some(azp) = payload.get("azp").cloned() {
        if let Some(object) = payload.as_object_mut() {
            object.insert("client_id".to_owned(), azp);
        }
    }
    payload
}
```

- [x] **Step 4: Run GREEN verification**

Run:

```bash
cargo test -p openauth-oauth --test oauth2_helpers verify_access_token -- --nocapture
```

Expected: all access token verification tests pass.

---

### Task 3: Authorization URL Param Overwrite Parity

**Files:**
- Modify: `crates/openauth-oauth/src/oauth2/authorization_url.rs`
- Test: `crates/openauth-oauth/tests/oauth2_helpers.rs`

- [x] **Step 1: Write failing test**

```rust
#[test]
fn create_authorization_url_additional_params_overwrite_existing_params() {
    let url = create_authorization_url(AuthorizationUrlRequest {
        options: ProviderOptions {
            client_id: Some(ClientId::Single("client-id".to_owned())),
            ..ProviderOptions::default()
        },
        authorization_endpoint: "https://auth.example.com/authorize".to_owned(),
        redirect_uri: "https://app.example.com/callback".to_owned(),
        state: "state".to_owned(),
        scopes: vec!["openid".to_owned()],
        additional_params: BTreeMap::from([
            ("scope".to_owned(), "profile email".to_owned()),
            ("prompt".to_owned(), "consent".to_owned()),
        ]),
        ..AuthorizationUrlRequest::default()
    })
    .expect("url should build");

    let scopes = url
        .query_pairs()
        .filter(|(key, _)| key == "scope")
        .map(|(_, value)| value.into_owned())
        .collect::<Vec<_>>();
    assert_eq!(scopes, vec!["profile email"]);
}
```

- [x] **Step 2: Run RED verification**

Run:

```bash
cargo test -p openauth-oauth --test oauth2_helpers create_authorization_url_additional_params_overwrite_existing_params -- --nocapture
```

Expected: FAIL because duplicate `scope` is appended.

- [x] **Step 3: Implement overwrite behavior**

Use `Url` query reconstruction for additional params:

```rust
let mut pairs = url.query_pairs().into_owned().collect::<Vec<_>>();
for (key, value) in input.additional_params {
    pairs.retain(|(existing, _)| existing != &key);
    pairs.push((key, value));
}
url.set_query(None);
for (key, value) in pairs {
    url.query_pairs_mut().append_pair(&key, &value);
}
```

- [x] **Step 4: Run GREEN verification**

Run:

```bash
cargo test -p openauth-oauth --test oauth2_helpers create_authorization_url_additional_params_overwrite_existing_params -- --nocapture
```

Expected: PASS.

---

### Task 4: Public OAuth Provider Contract

**Files:**
- Modify: `crates/openauth-oauth/src/oauth2/provider.rs`
- Modify: `crates/openauth-oauth/src/oauth2/mod.rs`
- Test: `crates/openauth-oauth/tests/module_structure.rs`

- [x] **Step 1: Write public API compile test**

```rust
#[test]
fn oauth_provider_contract_is_public() {
    fn assert_provider_contract<T: openauth_oauth::oauth2::OAuthProviderContract>() {}

    #[allow(dead_code)]
    struct TestProvider;

    impl openauth_oauth::oauth2::OAuthProviderContract for TestProvider {
        fn id(&self) -> &str { "test" }
        fn name(&self) -> &str { "Test" }
    }

    assert_provider_contract::<TestProvider>();
}
```

- [x] **Step 2: Run RED verification**

Run:

```bash
cargo test -p openauth-oauth --test module_structure oauth_provider_contract_is_public
```

Expected: FAIL because `OAuthProviderContract` is not defined.

- [x] **Step 3: Implement minimal provider contract**

Add:

```rust
pub trait OAuthProviderContract {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
}

impl OAuthProviderContract for OAuthProviderMetadata {
    fn id(&self) -> &str { self.id() }
    fn name(&self) -> &str { self.name() }
}
```

Re-export it from `oauth2::mod`.

- [x] **Step 4: Run GREEN verification**

Run:

```bash
cargo test -p openauth-oauth --test module_structure oauth_provider_contract_is_public
```

Expected: PASS.

---

### Task 5: Account Linking Email Verification Parity

**Files:**
- Modify: `crates/openauth-core/src/auth/oauth/account_linking.rs`
- Test: `crates/openauth-core/tests/auth/oauth.rs`

- [x] **Step 1: Write failing tests**

Add tests adapted from upstream `link-account.test.ts`:

```rust
#[tokio::test]
async fn handle_oauth_user_info_does_not_verify_email_when_provider_email_differs() {
    let adapter = MemoryAdapter::new();
    let context = test_context(AccountOptions::default()).unwrap();
    DbUserStore::new(&adapter)
        .create_user(CreateUserInput::new("Ada", "ada@example.com").id("user_1"))
        .await
        .unwrap();

    let result = handle_oauth_user_info(
        &context,
        &adapter,
        HandleOAuthUserInfoInput {
            user_info: oauth_user("github_ada", "other@example.com", true),
            account: oauth_account("github", "github_ada", None),
            is_trusted_provider: true,
            ..HandleOAuthUserInfoInput::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(result.error, Some(OAuthUserInfoError::AccountNotLinked));
}
```

Add separate tests for same-email verified linking, no trusted provider with verified email allowed, `disable_implicit_linking` blocking implicit linking, and provider-scoped account lookup.

- [x] **Step 2: Run RED verification**

Run:

```bash
cargo test -p openauth-core --test auth oauth -- --nocapture
```

Expected: new email mismatch/update tests fail against current behavior.

- [x] **Step 3: Implement same-email guard**

Add helper:

```rust
fn same_email(provider_email: &str, user_email: &str) -> bool {
    provider_email.eq_ignore_ascii_case(user_email)
}
```

Use it before updating `email_verified`:

```rust
if input.user_info.email_verified
    && !lookup.user.email_verified
    && same_email(&input.user_info.email, &lookup.user.email)
{
    user = users.update_user_email_verified(&lookup.user.id, true).await?.or(user);
}
```

- [x] **Step 4: Run GREEN verification**

Run:

```bash
cargo test -p openauth-core --test auth oauth -- --nocapture
```

Expected: PASS.

---

### Task 6: Override User Info Parity

**Files:**
- Modify: `crates/openauth-core/src/auth/oauth/account_linking.rs`
- Modify if needed: `crates/openauth-core/src/user.rs`
- Test: `crates/openauth-core/tests/auth/oauth.rs`

- [x] **Step 1: Write failing test**

```rust
#[tokio::test]
async fn handle_oauth_user_info_override_updates_email_and_verified_status() {
    let adapter = MemoryAdapter::new();
    let context = test_context(AccountOptions::default()).unwrap();
    let created = handle_oauth_user_info(
        &context,
        &adapter,
        HandleOAuthUserInfoInput {
            user_info: oauth_user("github_ada", "ada@example.com", false),
            account: oauth_account("github", "github_ada", None),
            ..HandleOAuthUserInfoInput::default()
        },
    )
    .await
    .unwrap();
    assert!(created.error.is_none());

    let updated = handle_oauth_user_info(
        &context,
        &adapter,
        HandleOAuthUserInfoInput {
            user_info: OAuthUserInfo {
                email: "ADA@EXAMPLE.COM".to_owned(),
                email_verified: true,
                name: "Ada Provider".to_owned(),
                ..oauth_user("github_ada", "ada@example.com", true)
            },
            account: oauth_account("github", "github_ada", None),
            override_user_info: true,
            ..HandleOAuthUserInfoInput::default()
        },
    )
    .await
    .unwrap();

    let user = updated.data.unwrap().user;
    assert_eq!(user.email, "ada@example.com");
    assert!(user.email_verified);
    assert_eq!(user.name, "Ada Provider");
}
```

- [x] **Step 2: Run RED verification**

Run:

```bash
cargo test -p openauth-core --test auth handle_oauth_user_info_override_updates_email_and_verified_status -- --nocapture
```

Expected: FAIL because override does not update email through the current helper.

- [x] **Step 3: Implement explicit override helper**

Add:

```rust
async fn override_user_info(
    users: &DbUserStore<'_>,
    existing: &User,
    provider: &OAuthUserInfo,
) -> Result<Option<User>, OpenAuthError> {
    let normalized_email = provider.email.to_lowercase();
    let email_verified = if normalized_email == existing.email {
        existing.email_verified || provider.email_verified
    } else {
        provider.email_verified
    };
    let mut update = UpdateUserInput::new()
        .name(provider.name.clone())
        .image(provider.image.clone());
    update = update.email(normalized_email).email_verified(email_verified);
    users.update_user(&existing.id, update).await
}
```

If `UpdateUserInput` does not support `email` and `email_verified`, add builder methods and adapter update support in `user.rs`.

- [x] **Step 4: Run GREEN verification**

Run:

```bash
cargo test -p openauth-core --test auth handle_oauth_user_info_override_updates_email_and_verified_status -- --nocapture
```

Expected: PASS.

---

### Task 7: OAuth State Security Parity Decision

**Files:**
- Modify: `crates/openauth-core/src/auth/oauth/state.rs`
- Modify if implemented: `crates/openauth-core/src/options.rs`
- Test: `crates/openauth-core/tests/auth/oauth.rs`

- [x] **Step 1: Write explicit state behavior tests**

Add tests for the behavior OpenAuth will support now:

```rust
#[tokio::test]
async fn parse_oauth_state_rejects_cookie_state_with_wrong_secret() {
    let context_a = test_context(AccountOptions::default()).unwrap();
    let context_b = create_auth_context(OpenAuthOptions {
        secret: Some("different-secret-at-least-32-chars!".to_owned()),
        ..OpenAuthOptions::default()
    })
    .unwrap();

    let state = generate_oauth_state(
        &context_a,
        None,
        OAuthStateInput {
            callback_url: "https://app.example.com/callback".to_owned(),
            ..OAuthStateInput::default()
        },
    )
    .await
    .unwrap();

    assert!(parse_oauth_state(&context_b, None, &state.state).await.is_err());
}
```

Add a database consumed-state test only if `DbVerificationStore` exposes deletion; otherwise document that consumed-state cleanup is not supported yet.

- [x] **Step 2: Run verification**

Run:

```bash
cargo test -p openauth-core --test auth oauth_state -- --nocapture
```

Expected: PASS for wrong-secret rejection. If consumed-state cleanup is implemented, the second parse must fail.

---

### Task 8: Public Re-Exports and Full Verification

**Files:**
- Modify: `crates/openauth/src/lib.rs`
- Modify: `crates/openauth/tests/public_api.rs`
- Test: `crates/openauth/tests/public_api.rs`

- [x] **Step 1: Write public API tests**

```rust
#[test]
fn oauth_public_reexports_include_core_and_oauth_helpers() {
    let _ = openauth::oauth::oauth2::ClientAuthentication::Basic;
    let _ = openauth::auth::oauth::OAuthUserInfo {
        id: "id".to_owned(),
        name: "name".to_owned(),
        email: "user@example.com".to_owned(),
        image: None,
        email_verified: true,
    };
}
```

- [x] **Step 2: Run public API test**

Run:

```bash
cargo test -p openauth --test public_api oauth_public_reexports_include_core_and_oauth_helpers
```

Expected: PASS; if it fails, re-export from `openauth/src/lib.rs` without adding OAuth logic to the aggregator.

- [x] **Step 3: Run focused package verification**

Run:

```bash
cargo test -p openauth-oauth
cargo test -p openauth-core --test auth
cargo test -p openauth
```

Expected: all pass.

- [x] **Step 4: Run workspace formatting**

Run:

```bash
cargo fmt
```

Expected: no output and no formatting errors.

---

## Self-Review

- Spec coverage: covers missing JWT temporal validation, upstream JWT algorithm tests, JWKS edge cases, remote introspection behavior, authorization URL overwrite behavior, provider public contract, account linking email verification safety, override user info, state security behavior, and public re-exports.
- Placeholder scan: no `TBD`, `TODO`, or undefined future-only tasks. The only conditional item is database consumed-state cleanup, tied to existing verification store capability.
- Type consistency: plan uses current public Rust names: `validate_token`, `verify_access_token`, `TokenValidationOptions`, `HandleOAuthUserInfoInput`, `OAuthUserInfo`, `OAuthAccountInput`, `AccountOptions`, and `OAuthStateInput`.
