use super::*;
use openauth_oauth::oauth2::{
    OAuth2Tokens, OAuth2UserInfo, OAuthError, ProviderOptions, SocialAuthorizationCodeRequest,
    SocialAuthorizationUrlRequest, SocialIdTokenRequest, SocialOAuthProvider, SocialProviderFuture,
};
use std::sync::Arc;
use url::Url;

#[tokio::test]
async fn sign_in_social_returns_authorization_url_and_location_header(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let router = router_with_options(
        adapter,
        OpenAuthOptions {
            base_url: Some("http://localhost:3000/api/auth".to_owned()),
            social_providers: vec![Arc::new(FakeProvider::new("github"))],
            ..OpenAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/social",
            r#"{"provider":"github","callbackURL":"/dashboard"}"#,
            None,
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body["redirect"], true);
    assert!(body["url"].as_str().unwrap_or_default().contains("state="));
    assert!(response.headers().contains_key(header::LOCATION));
    Ok(())
}

#[tokio::test]
async fn sign_in_oauth2_returns_authorization_url_and_location_header(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let router = router_with_options(
        adapter,
        OpenAuthOptions {
            base_url: Some("http://localhost:3000/api/auth".to_owned()),
            social_providers: vec![Arc::new(FakeProvider::new("github"))],
            ..OpenAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/oauth2",
            r#"{"provider":"github","callbackURL":"/dashboard"}"#,
            None,
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body["redirect"], true);
    assert!(body["url"].as_str().unwrap_or_default().contains("state="));
    assert!(response.headers().contains_key(header::LOCATION));
    Ok(())
}

#[tokio::test]
async fn callback_oauth_creates_user_account_session_and_redirects(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let router = router_with_options(
        adapter.clone(),
        OpenAuthOptions {
            base_url: Some("http://localhost:3000/api/auth".to_owned()),
            social_providers: vec![Arc::new(FakeProvider::new("github"))],
            ..OpenAuthOptions::default()
        },
    )?;
    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/social",
            r#"{"provider":"github","callbackURL":"/dashboard","newUserCallbackURL":"/welcome"}"#,
            None,
        )?)
        .await?;
    let body: Value = serde_json::from_slice(sign_in.body())?;
    let state =
        query_value(body["url"].as_str().ok_or("missing url")?, "state").ok_or("missing state")?;

    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("/api/auth/callback/github?code=ok&state={state}"),
            "",
            None,
        )?)
        .await?;

    assert_eq!(callback.status(), StatusCode::FOUND);
    assert_eq!(
        callback
            .headers()
            .get(header::LOCATION)
            .ok_or("missing location")?,
        "/welcome"
    );
    assert!(set_cookie_values(&callback)
        .iter()
        .any(|value| value.starts_with("open-auth.session_token=")));
    assert_eq!(adapter.len("user").await, 1);
    assert_eq!(adapter.len("account").await, 1);
    assert_eq!(adapter.len("session").await, 1);
    Ok(())
}

#[tokio::test]
async fn link_social_requires_session_and_generates_link_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    adapter.insert_user(user(OffsetDateTime::now_utc())).await;
    adapter
        .insert_session(session(
            OffsetDateTime::now_utc(),
            OffsetDateTime::now_utc() + Duration::hours(1),
        ))
        .await;
    let router = router_with_options(
        adapter,
        OpenAuthOptions {
            base_url: Some("http://localhost:3000/api/auth".to_owned()),
            social_providers: vec![Arc::new(FakeProvider::new("github"))],
            ..OpenAuthOptions::default()
        },
    )?;
    let cookie = signed_session_cookie("token_1")?;

    let unauthenticated = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/link-social",
            r#"{"provider":"github","callbackURL":"/settings"}"#,
            None,
        )?)
        .await?;
    let linked = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/link-social",
            r#"{"provider":"github","callbackURL":"/settings"}"#,
            Some(&cookie),
        )?)
        .await?;
    let body: Value = serde_json::from_slice(linked.body())?;

    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(linked.status(), StatusCode::OK);
    assert_eq!(body["redirect"], true);
    assert!(body["url"].as_str().unwrap_or_default().contains("state="));
    Ok(())
}

#[tokio::test]
async fn link_social_callback_rejects_account_owned_by_different_user(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_user(User {
            id: "user_2".to_owned(),
            email: "grace@example.com".to_owned(),
            ..user(now)
        })
        .await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    adapter
        .insert_account(oauth_account_record(
            "account_2",
            "user_2",
            "github",
            "github_ada",
            "old-access",
            now,
        ))
        .await?;
    let router = router_with_options(
        adapter.clone(),
        OpenAuthOptions {
            base_url: Some("http://localhost:3000/api/auth".to_owned()),
            social_providers: vec![Arc::new(FakeProvider::new("github"))],
            ..OpenAuthOptions::default()
        },
    )?;
    let cookie = signed_session_cookie("token_1")?;
    let linked = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/link-social",
            r#"{"provider":"github","callbackURL":"/settings","errorCallbackURL":"/oauth-error"}"#,
            Some(&cookie),
        )?)
        .await?;
    let body: Value = serde_json::from_slice(linked.body())?;
    let state =
        query_value(body["url"].as_str().ok_or("missing url")?, "state").ok_or("missing state")?;

    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("/api/auth/callback/github?code=ok&state={state}"),
            "",
            None,
        )?)
        .await?;

    assert_eq!(callback.status(), StatusCode::FOUND);
    assert_eq!(
        callback
            .headers()
            .get(header::LOCATION)
            .ok_or("missing location")?,
        "/oauth-error?error=account_already_linked_to_different_user"
    );
    let accounts = adapter.records("account").await;
    assert_eq!(accounts.len(), 1);
    assert!(accounts.iter().any(|record| {
        record.get("id") == Some(&DbValue::String("account_2".to_owned()))
            && record.get("user_id") == Some(&DbValue::String("user_2".to_owned()))
            && record.get("access_token") == Some(&DbValue::String("old-access".to_owned()))
    }));
    Ok(())
}

#[tokio::test]
async fn sign_in_social_id_token_flow_returns_session_payload(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let router = router_with_options(
        adapter,
        OpenAuthOptions {
            social_providers: vec![Arc::new(FakeProvider::new("google"))],
            ..OpenAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/social",
            r#"{"provider":"google","idToken":{"token":"valid-id-token"}}"#,
            None,
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body["redirect"], false);
    assert!(body["token"].is_string());
    assert_eq!(body["user"]["email"], "ada@example.com");
    Ok(())
}

fn query_value(url: &str, key: &str) -> Option<String> {
    let query = url.split_once('?')?.1;
    query.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name == key).then(|| value.to_owned())
    })
}

fn oauth_account_record(
    id: &str,
    user_id: &str,
    provider_id: &str,
    account_id: &str,
    access_token: &str,
    now: OffsetDateTime,
) -> DbRecord {
    DbRecord::from([
        ("id".to_owned(), DbValue::String(id.to_owned())),
        ("user_id".to_owned(), DbValue::String(user_id.to_owned())),
        (
            "provider_id".to_owned(),
            DbValue::String(provider_id.to_owned()),
        ),
        (
            "account_id".to_owned(),
            DbValue::String(account_id.to_owned()),
        ),
        (
            "access_token".to_owned(),
            DbValue::String(access_token.to_owned()),
        ),
        ("refresh_token".to_owned(), DbValue::Null),
        ("id_token".to_owned(), DbValue::Null),
        ("access_token_expires_at".to_owned(), DbValue::Null),
        ("refresh_token_expires_at".to_owned(), DbValue::Null),
        ("scope".to_owned(), DbValue::Null),
        ("created_at".to_owned(), DbValue::Timestamp(now)),
        ("updated_at".to_owned(), DbValue::Timestamp(now)),
    ])
}

#[derive(Debug)]
struct FakeProvider {
    id: String,
    options: ProviderOptions,
}

impl FakeProvider {
    fn new(id: &str) -> Self {
        Self {
            id: id.to_owned(),
            options: ProviderOptions {
                client_id: Some("client-id".into()),
                client_secret: Some("client-secret".to_owned()),
                ..ProviderOptions::default()
            },
        }
    }
}

impl SocialOAuthProvider for FakeProvider {
    fn id(&self) -> &str {
        &self.id
    }

    fn name(&self) -> &str {
        "Fake Provider"
    }

    fn provider_options(&self) -> ProviderOptions {
        self.options.clone()
    }

    fn create_authorization_url(
        &self,
        input: SocialAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        Url::parse(&format!(
            "https://provider.example.com/oauth?state={}&redirect_uri={}",
            input.state, input.redirect_uri
        ))
        .map_err(OAuthError::InvalidUrl)
    }

    fn validate_authorization_code(
        &self,
        _input: SocialAuthorizationCodeRequest,
    ) -> SocialProviderFuture<'_, OAuth2Tokens> {
        Box::pin(async {
            Ok(OAuth2Tokens {
                access_token: Some("access-token".to_owned()),
                refresh_token: Some("refresh-token".to_owned()),
                scopes: vec!["profile".to_owned()],
                ..OAuth2Tokens::default()
            })
        })
    }

    fn get_user_info(
        &self,
        _tokens: OAuth2Tokens,
        _provider_user: Option<serde_json::Value>,
    ) -> SocialProviderFuture<'_, Option<OAuth2UserInfo>> {
        let id = format!("{}_ada", self.id);
        Box::pin(async move {
            Ok(Some(OAuth2UserInfo {
                id,
                name: Some("Ada Lovelace".to_owned()),
                email: Some("ada@example.com".to_owned()),
                image: None,
                email_verified: true,
            }))
        })
    }

    fn verify_id_token(&self, input: SocialIdTokenRequest) -> SocialProviderFuture<'_, bool> {
        Box::pin(async move { Ok(input.token == "valid-id-token") })
    }
}
