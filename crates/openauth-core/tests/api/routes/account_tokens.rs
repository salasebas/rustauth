use super::*;
use openauth_oauth::oauth2::{
    OAuth2Tokens, OAuth2UserInfo, OAuthError, ProviderOptions, SocialAuthorizationCodeRequest,
    SocialAuthorizationUrlRequest, SocialOAuthProvider, SocialProviderFuture,
};
use std::sync::Arc;
use url::Url;

#[tokio::test]
async fn get_access_token_returns_current_user_provider_token(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    adapter
        .insert_account(oauth_account_record(
            now,
            Some("stored-access-token"),
            Some("stored-refresh-token"),
            Some(now + Duration::hours(1)),
        ))
        .await?;
    let router = token_router(adapter)?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/get-access-token",
            r#"{"providerId":"github"}"#,
            Some(&cookie),
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body["accessToken"], "stored-access-token");
    assert_eq!(
        body["scopes"],
        serde_json::json!(["read:user", "user:email"])
    );
    assert_eq!(body["idToken"], "stored-id-token");
    Ok(())
}

#[tokio::test]
async fn refresh_token_uses_provider_and_persists_new_tokens(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    adapter
        .insert_account(oauth_account_record(
            now,
            Some("old-access-token"),
            Some("stored-refresh-token"),
            Some(now - Duration::minutes(1)),
        ))
        .await?;
    let router = token_router(adapter.clone())?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/refresh-token",
            r#"{"providerId":"github","accountId":"github_ada"}"#,
            Some(&cookie),
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body["accessToken"], "new-access-token");
    assert_eq!(body["refreshToken"], "new-refresh-token");
    assert_eq!(body["providerId"], "github");
    assert_eq!(body["accountId"], "github_ada");

    let account = record_by_string(&adapter, "account", "id", "account_2")
        .await?
        .ok_or("missing account")?;
    assert_eq!(string_field(&account, "access_token")?, "new-access-token");
    assert_eq!(
        string_field(&account, "refresh_token")?,
        "new-refresh-token"
    );
    Ok(())
}

#[tokio::test]
async fn refresh_token_sets_account_cookie_when_enabled() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    adapter
        .insert_account(oauth_account_record(
            now,
            Some("old-access-token"),
            Some("stored-refresh-token"),
            Some(now - Duration::minutes(1)),
        ))
        .await?;
    let router = router_with_options(
        adapter,
        OpenAuthOptions {
            account: openauth_core::options::AccountOptions {
                store_account_cookie: true,
                ..openauth_core::options::AccountOptions::default()
            },
            social_providers: vec![Arc::new(TokenProvider)],
            ..OpenAuthOptions::default()
        },
    )?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/refresh-token",
            r#"{"providerId":"github","accountId":"github_ada"}"#,
            Some(&cookie),
        )?)
        .await?;
    let cookies = set_cookie_values(&response);

    assert_eq!(response.status(), StatusCode::OK);
    assert!(cookies
        .iter()
        .any(|value| value.starts_with("open-auth.account_data=")));
    Ok(())
}

#[tokio::test]
async fn get_access_token_auto_refresh_sets_account_cookie_when_enabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    adapter
        .insert_account(oauth_account_record(
            now,
            Some("old-access-token"),
            Some("stored-refresh-token"),
            Some(now - Duration::minutes(1)),
        ))
        .await?;
    let router = router_with_options(
        adapter,
        OpenAuthOptions {
            account: openauth_core::options::AccountOptions {
                store_account_cookie: true,
                ..openauth_core::options::AccountOptions::default()
            },
            social_providers: vec![Arc::new(TokenProvider)],
            ..OpenAuthOptions::default()
        },
    )?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/get-access-token",
            r#"{"providerId":"github","accountId":"github_ada"}"#,
            Some(&cookie),
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;
    let cookies = set_cookie_values(&response);

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body["accessToken"], "new-access-token");
    assert_eq!(body["idToken"], "new-id-token");
    assert!(cookies
        .iter()
        .any(|value| value.starts_with("open-auth.account_data=")));
    Ok(())
}

#[tokio::test]
async fn account_info_returns_provider_user_info_for_current_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    adapter
        .insert_account(oauth_account_record(
            now,
            Some("stored-access-token"),
            Some("stored-refresh-token"),
            Some(now + Duration::hours(1)),
        ))
        .await?;
    let router = token_router(adapter)?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/account-info?accountId=github_ada",
            "",
            Some(&cookie),
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body["user"]["id"], "github_ada");
    assert_eq!(body["user"]["email"], "ada@example.com");
    assert_eq!(body["data"]["provider"], "github");
    Ok(())
}

fn token_router(adapter: Arc<RouteAdapter>) -> Result<AuthRouter, OpenAuthError> {
    router_with_options(
        adapter,
        OpenAuthOptions {
            social_providers: vec![Arc::new(TokenProvider)],
            ..OpenAuthOptions::default()
        },
    )
}

fn oauth_account_record(
    now: OffsetDateTime,
    access_token: Option<&str>,
    refresh_token: Option<&str>,
    access_token_expires_at: Option<OffsetDateTime>,
) -> DbRecord {
    let mut record = linked_account_record(
        "account_2",
        "github",
        "github_ada",
        "user_1",
        Some("read:user,user:email"),
        now,
    );
    record.insert(
        "access_token".to_owned(),
        access_token
            .map(|value| DbValue::String(value.to_owned()))
            .unwrap_or(DbValue::Null),
    );
    record.insert(
        "refresh_token".to_owned(),
        refresh_token
            .map(|value| DbValue::String(value.to_owned()))
            .unwrap_or(DbValue::Null),
    );
    record.insert(
        "id_token".to_owned(),
        DbValue::String("stored-id-token".to_owned()),
    );
    record.insert(
        "access_token_expires_at".to_owned(),
        access_token_expires_at
            .map(DbValue::Timestamp)
            .unwrap_or(DbValue::Null),
    );
    record
}

#[derive(Debug)]
struct TokenProvider;

impl SocialOAuthProvider for TokenProvider {
    fn id(&self) -> &str {
        "github"
    }

    fn name(&self) -> &str {
        "GitHub"
    }

    fn provider_options(&self) -> ProviderOptions {
        ProviderOptions::default()
    }

    fn create_authorization_url(
        &self,
        _input: SocialAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        Url::parse("https://github.example.com/oauth").map_err(OAuthError::InvalidUrl)
    }

    fn validate_authorization_code(
        &self,
        _input: SocialAuthorizationCodeRequest,
    ) -> SocialProviderFuture<'_, OAuth2Tokens> {
        Box::pin(async { Ok(OAuth2Tokens::default()) })
    }

    fn get_user_info(
        &self,
        tokens: OAuth2Tokens,
        _provider_user: Option<Value>,
    ) -> SocialProviderFuture<'_, Option<OAuth2UserInfo>> {
        Box::pin(async move {
            if tokens.access_token.as_deref() != Some("stored-access-token")
                && tokens.access_token.as_deref() != Some("new-access-token")
            {
                return Ok(None);
            }
            Ok(Some(OAuth2UserInfo {
                id: "github_ada".to_owned(),
                name: Some("Ada Lovelace".to_owned()),
                email: Some("ada@example.com".to_owned()),
                image: None,
                email_verified: true,
            }))
        })
    }

    fn refresh_access_token(
        &self,
        refresh_token: String,
    ) -> SocialProviderFuture<'_, OAuth2Tokens> {
        Box::pin(async move {
            if refresh_token != "stored-refresh-token" {
                return Err(OAuthError::InvalidResponse("bad refresh token".to_owned()));
            }
            Ok(OAuth2Tokens {
                access_token: Some("new-access-token".to_owned()),
                refresh_token: Some("new-refresh-token".to_owned()),
                access_token_expires_at: Some(OffsetDateTime::now_utc() + Duration::hours(1)),
                refresh_token_expires_at: Some(OffsetDateTime::now_utc() + Duration::days(30)),
                scopes: vec!["read:user".to_owned()],
                id_token: Some("new-id-token".to_owned()),
                ..OAuth2Tokens::default()
            })
        })
    }
}

#[tokio::test]
async fn refresh_token_with_encryption_persists_encrypted_tokens_and_returns_plaintext(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    adapter
        .insert_account(encrypted_account_record(
            now,
            Some("old-access-token"),
            Some("stored-refresh-token"),
            Some("stored-id-token"),
            Some(now - Duration::minutes(1)),
        )?)
        .await?;
    let router = encrypting_token_router(adapter.clone())?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/refresh-token",
            r#"{"providerId":"github","accountId":"github_ada"}"#,
            Some(&cookie),
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::OK);
    // Responses are decrypted exactly once.
    assert_eq!(body["accessToken"], "new-access-token");
    assert_eq!(body["refreshToken"], "new-refresh-token");
    assert_eq!(body["idToken"], "new-id-token");

    // Every persisted token (including id_token) is ciphertext that decrypts
    // back to the plaintext in a single step.
    let account = record_by_string(&adapter, "account", "id", "account_2")
        .await?
        .ok_or("missing account")?;
    let stored_access = string_field(&account, "access_token")?;
    let stored_refresh = string_field(&account, "refresh_token")?;
    let stored_id = string_field(&account, "id_token")?;
    assert_ne!(stored_access, "new-access-token");
    assert_ne!(stored_refresh, "new-refresh-token");
    assert_ne!(stored_id, "new-id-token");
    assert_eq!(decrypt_token(stored_access)?, "new-access-token");
    assert_eq!(decrypt_token(stored_refresh)?, "new-refresh-token");
    assert_eq!(decrypt_token(stored_id)?, "new-id-token");
    Ok(())
}

#[tokio::test]
async fn get_access_token_with_encryption_decrypts_stored_tokens_for_response(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    adapter
        .insert_account(encrypted_account_record(
            now,
            Some("stored-access-token"),
            Some("stored-refresh-token"),
            Some("stored-id-token"),
            Some(now + Duration::hours(1)),
        )?)
        .await?;
    let router = encrypting_token_router(adapter)?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/get-access-token",
            r#"{"providerId":"github"}"#,
            Some(&cookie),
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body["accessToken"], "stored-access-token");
    assert_eq!(body["idToken"], "stored-id-token");
    Ok(())
}

#[tokio::test]
async fn account_info_with_encryption_uses_decrypted_access_token(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    adapter
        .insert_account(encrypted_account_record(
            now,
            Some("stored-access-token"),
            Some("stored-refresh-token"),
            Some("stored-id-token"),
            Some(now + Duration::hours(1)),
        )?)
        .await?;
    let router = encrypting_token_router(adapter)?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/account-info?accountId=github_ada",
            "",
            Some(&cookie),
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    // The provider only returns user info when handed the decrypted access
    // token, so a 200 proves the read path decrypts stored tokens.
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body["user"]["id"], "github_ada");
    assert_eq!(body["data"]["provider"], "github");
    Ok(())
}

#[tokio::test]
async fn get_access_token_tolerates_legacy_plaintext_tokens_when_encryption_enabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    // Tokens stored before encryption was enabled are plaintext.
    adapter
        .insert_account(oauth_account_record(
            now,
            Some("stored-access-token"),
            Some("stored-refresh-token"),
            Some(now + Duration::hours(1)),
        ))
        .await?;
    let router = encrypting_token_router(adapter)?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/get-access-token",
            r#"{"providerId":"github"}"#,
            Some(&cookie),
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body["accessToken"], "stored-access-token");
    assert_eq!(body["idToken"], "stored-id-token");
    Ok(())
}

fn encrypting_token_router(adapter: Arc<RouteAdapter>) -> Result<AuthRouter, OpenAuthError> {
    router_with_options(
        adapter,
        OpenAuthOptions {
            account: openauth_core::options::AccountOptions {
                encrypt_oauth_tokens: true,
                ..openauth_core::options::AccountOptions::default()
            },
            social_providers: vec![Arc::new(TokenProvider)],
            ..OpenAuthOptions::default()
        },
    )
}

fn encryption_context() -> Result<openauth_core::context::AuthContext, OpenAuthError> {
    create_auth_context(OpenAuthOptions {
        secret: Some(secret().to_owned()),
        account: openauth_core::options::AccountOptions {
            encrypt_oauth_tokens: true,
            ..openauth_core::options::AccountOptions::default()
        },
        ..OpenAuthOptions::default()
    })
}

fn encrypt_token(value: &str) -> Result<String, OpenAuthError> {
    let context = encryption_context()?;
    openauth_core::auth::oauth::set_token_util(Some(value), &context)?
        .ok_or_else(|| OpenAuthError::Adapter("missing encrypted token".to_owned()))
}

fn decrypt_token(value: &str) -> Result<String, OpenAuthError> {
    let context = encryption_context()?;
    openauth_core::auth::oauth::decrypt_oauth_token(value, &context)
}

fn encrypted_account_record(
    now: OffsetDateTime,
    access_token: Option<&str>,
    refresh_token: Option<&str>,
    id_token: Option<&str>,
    access_token_expires_at: Option<OffsetDateTime>,
) -> Result<DbRecord, OpenAuthError> {
    let mut record = linked_account_record(
        "account_2",
        "github",
        "github_ada",
        "user_1",
        Some("read:user,user:email"),
        now,
    );
    for (field, value) in [
        ("access_token", access_token),
        ("refresh_token", refresh_token),
        ("id_token", id_token),
    ] {
        let stored = match value {
            Some(value) => DbValue::String(encrypt_token(value)?),
            None => DbValue::Null,
        };
        record.insert(field.to_owned(), stored);
    }
    record.insert(
        "access_token_expires_at".to_owned(),
        access_token_expires_at
            .map(DbValue::Timestamp)
            .unwrap_or(DbValue::Null),
    );
    Ok(record)
}
