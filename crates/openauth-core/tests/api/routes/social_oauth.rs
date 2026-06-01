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
async fn callback_oauth_rejects_unverified_existing_email_when_provider_is_not_trusted(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    adapter.insert_user(user(OffsetDateTime::now_utc())).await;
    let router = router_with_options(
        adapter.clone(),
        OpenAuthOptions {
            base_url: Some("http://localhost:3000/api/auth".to_owned()),
            social_providers: vec![Arc::new(FakeProvider::new("github").email_verified(false))],
            ..OpenAuthOptions::default()
        },
    )?;
    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/social",
            r#"{"provider":"github","callbackURL":"/dashboard"}"#,
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
        "http://localhost:3000/api/auth/error?error=account_not_linked"
    );
    assert_eq!(adapter.len("account").await, 0);
    assert_eq!(adapter.len("session").await, 0);
    Ok(())
}

#[tokio::test]
async fn callback_oauth_links_unverified_existing_email_when_provider_is_trusted(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    adapter.insert_user(user(OffsetDateTime::now_utc())).await;
    let router = router_with_options(
        adapter.clone(),
        OpenAuthOptions {
            base_url: Some("http://localhost:3000/api/auth".to_owned()),
            social_providers: vec![Arc::new(FakeProvider::new("github").email_verified(false))],
            account: openauth_core::options::AccountOptions {
                account_linking: openauth_core::options::AccountLinkingOptions::default()
                    .trusted_provider("github"),
                ..openauth_core::options::AccountOptions::default()
            },
            ..OpenAuthOptions::default()
        },
    )?;
    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/social",
            r#"{"provider":"github","callbackURL":"/dashboard"}"#,
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
        "/dashboard"
    );
    assert_eq!(adapter.len("account").await, 1);
    assert_eq!(adapter.len("session").await, 1);
    Ok(())
}

#[tokio::test]
async fn callback_oauth_sets_account_cookie_when_enabled() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(RouteAdapter::default());
    let router = router_with_options(
        adapter,
        OpenAuthOptions {
            base_url: Some("http://localhost:3000/api/auth".to_owned()),
            account: openauth_core::options::AccountOptions {
                store_account_cookie: true,
                ..openauth_core::options::AccountOptions::default()
            },
            social_providers: vec![Arc::new(FakeProvider::new("github"))],
            ..OpenAuthOptions::default()
        },
    )?;
    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/social",
            r#"{"provider":"github","callbackURL":"/dashboard"}"#,
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
    let cookies = set_cookie_values(&callback);

    assert_eq!(callback.status(), StatusCode::FOUND);
    assert!(cookies
        .iter()
        .any(|value| value.starts_with("open-auth.session_token=")));
    assert!(cookies
        .iter()
        .any(|value| value.starts_with("open-auth.account_data=")));
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
    let mut account =
        linked_account_record("account_2", "github", "github_ada", "user_2", None, now);
    account.insert(
        "access_token".to_owned(),
        DbValue::String("old-access".to_owned()),
    );
    adapter.insert_account(account).await?;
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

#[tokio::test]
async fn sign_in_social_id_token_rejects_unverified_existing_email_when_provider_is_not_trusted(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    adapter.insert_user(user(OffsetDateTime::now_utc())).await;
    let router = router_with_options(
        adapter.clone(),
        OpenAuthOptions {
            social_providers: vec![Arc::new(FakeProvider::new("google").email_verified(false))],
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

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "OAUTH_LINK_ERROR");
    assert_eq!(body["message"], "account_not_linked");
    assert_eq!(adapter.len("account").await, 0);
    assert_eq!(adapter.len("session").await, 0);
    Ok(())
}

#[tokio::test]
async fn sign_in_social_id_token_links_unverified_existing_email_when_provider_is_trusted(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    adapter.insert_user(user(OffsetDateTime::now_utc())).await;
    let router = router_with_options(
        adapter.clone(),
        OpenAuthOptions {
            social_providers: vec![Arc::new(FakeProvider::new("google").email_verified(false))],
            account: openauth_core::options::AccountOptions {
                account_linking: openauth_core::options::AccountLinkingOptions::default()
                    .trusted_provider("google"),
                ..openauth_core::options::AccountOptions::default()
            },
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
    assert_eq!(body["user"]["email"], "ada@example.com");
    assert_eq!(adapter.len("account").await, 1);
    assert_eq!(adapter.len("session").await, 1);
    Ok(())
}

#[tokio::test]
async fn link_social_id_token_rejects_when_account_linking_disabled(
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
            account: openauth_core::options::AccountOptions {
                account_linking: openauth_core::options::AccountLinkingOptions {
                    enabled: false,
                    ..openauth_core::options::AccountLinkingOptions::default()
                },
                ..openauth_core::options::AccountOptions::default()
            },
            social_providers: vec![Arc::new(FakeProvider::new("github"))],
            ..OpenAuthOptions::default()
        },
    )?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/link-social",
            r#"{"provider":"github","idToken":{"token":"valid-id-token"}}"#,
            Some(&cookie),
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "LINKING_NOT_ALLOWED");
    Ok(())
}

#[tokio::test]
async fn link_social_id_token_allows_already_linked_account_when_linking_disabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let now = OffsetDateTime::now_utc();
    let adapter = Arc::new(RouteAdapter::default());
    adapter.insert_user(user(now)).await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    adapter
        .insert_account(linked_account_record(
            "account_1",
            "github",
            "github_ada",
            "user_1",
            None,
            now,
        ))
        .await?;
    let router = router_with_options(
        adapter,
        OpenAuthOptions {
            account: openauth_core::options::AccountOptions {
                account_linking: openauth_core::options::AccountLinkingOptions {
                    enabled: false,
                    ..openauth_core::options::AccountLinkingOptions::default()
                },
                ..openauth_core::options::AccountOptions::default()
            },
            social_providers: vec![Arc::new(FakeProvider::new("github"))],
            ..OpenAuthOptions::default()
        },
    )?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/link-social",
            r#"{"provider":"github","idToken":{"token":"valid-id-token"}}"#,
            Some(&cookie),
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body["status"], true);
    Ok(())
}

#[tokio::test]
async fn link_social_id_token_rejects_untrusted_unverified_provider(
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
            social_providers: vec![Arc::new(FakeProvider::new("github").email_verified(false))],
            ..OpenAuthOptions::default()
        },
    )?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/link-social",
            r#"{"provider":"github","idToken":{"token":"valid-id-token"}}"#,
            Some(&cookie),
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "LINKING_NOT_ALLOWED");
    Ok(())
}

#[tokio::test]
async fn link_social_id_token_rejects_account_linked_to_different_user(
) -> Result<(), Box<dyn std::error::Error>> {
    let now = OffsetDateTime::now_utc();
    let adapter = Arc::new(RouteAdapter::default());
    adapter.insert_user(user(now)).await;
    let mut other = user(now);
    other.id = "user_2".to_owned();
    other.email = "other@example.com".to_owned();
    adapter.insert_user(other).await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    adapter
        .insert_account(linked_account_record(
            "account_1",
            "github",
            "github_ada",
            "user_2",
            None,
            now,
        ))
        .await?;
    let router = router_with_options(
        adapter,
        OpenAuthOptions {
            social_providers: vec![Arc::new(FakeProvider::new("github"))],
            ..OpenAuthOptions::default()
        },
    )?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/link-social",
            r#"{"provider":"github","idToken":{"token":"valid-id-token"}}"#,
            Some(&cookie),
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::EXPECTATION_FAILED);
    assert_eq!(body["code"], "LINKING_FAILED");
    Ok(())
}

#[tokio::test]
async fn link_social_id_token_updates_user_info_when_enabled(
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
        adapter.clone(),
        OpenAuthOptions {
            account: openauth_core::options::AccountOptions {
                account_linking: openauth_core::options::AccountLinkingOptions {
                    update_user_info_on_link: true,
                    ..openauth_core::options::AccountLinkingOptions::default()
                },
                ..openauth_core::options::AccountOptions::default()
            },
            social_providers: vec![Arc::new(
                FakeProvider::new("github")
                    .name("Ada Lovelace")
                    .image(Some("https://img.example.com/ada.png")),
            )],
            ..OpenAuthOptions::default()
        },
    )?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/link-social",
            r#"{"provider":"github","idToken":{"token":"valid-id-token"}}"#,
            Some(&cookie),
        )?)
        .await?;
    let updated = record_by_string(&adapter, "user", "id", "user_1")
        .await?
        .ok_or("missing user")?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(string_field(&updated, "name")?, "Ada Lovelace");
    assert_eq!(
        string_field(&updated, "image")?,
        "https://img.example.com/ada.png"
    );
    Ok(())
}

#[tokio::test]
async fn callback_link_social_updates_existing_account_tokens(
) -> Result<(), Box<dyn std::error::Error>> {
    let now = OffsetDateTime::now_utc();
    let adapter = Arc::new(RouteAdapter::default());
    adapter.insert_user(user(now)).await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    adapter
        .insert_account(linked_account_record(
            "account_1",
            "github",
            "github_ada",
            "user_1",
            None,
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
    let link = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/link-social",
            r#"{"provider":"github","callbackURL":"/settings"}"#,
            Some(&cookie),
        )?)
        .await?;
    let body: Value = serde_json::from_slice(link.body())?;
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
    let account = record_by_string(&adapter, "account", "id", "account_1")
        .await?
        .ok_or("missing account")?;

    assert_eq!(callback.status(), StatusCode::FOUND);
    assert_eq!(string_field(&account, "access_token")?, "access-token");
    assert_eq!(string_field(&account, "refresh_token")?, "refresh-token");
    Ok(())
}

#[tokio::test]
async fn callback_link_social_redirects_when_account_belongs_to_different_user(
) -> Result<(), Box<dyn std::error::Error>> {
    let now = OffsetDateTime::now_utc();
    let adapter = Arc::new(RouteAdapter::default());
    adapter.insert_user(user(now)).await;
    let mut other = user(now);
    other.id = "user_2".to_owned();
    other.email = "other@example.com".to_owned();
    adapter.insert_user(other).await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    adapter
        .insert_account(linked_account_record(
            "account_1",
            "github",
            "github_ada",
            "user_2",
            None,
            now,
        ))
        .await?;
    let router = router_with_options(
        adapter,
        OpenAuthOptions {
            base_url: Some("http://localhost:3000/api/auth".to_owned()),
            social_providers: vec![Arc::new(FakeProvider::new("github"))],
            ..OpenAuthOptions::default()
        },
    )?;
    let cookie = signed_session_cookie("token_1")?;
    let link = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/link-social",
            r#"{"provider":"github","callbackURL":"/settings","errorCallbackURL":"/link-error"}"#,
            Some(&cookie),
        )?)
        .await?;
    let body: Value = serde_json::from_slice(link.body())?;
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
        "/link-error?error=account_already_linked_to_different_user"
    );
    Ok(())
}

#[tokio::test]
async fn callback_link_social_redirects_when_provider_is_untrusted_and_unverified(
) -> Result<(), Box<dyn std::error::Error>> {
    let now = OffsetDateTime::now_utc();
    let adapter = Arc::new(RouteAdapter::default());
    adapter.insert_user(user(now)).await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    let router = router_with_options(
        adapter,
        OpenAuthOptions {
            base_url: Some("http://localhost:3000/api/auth".to_owned()),
            social_providers: vec![Arc::new(FakeProvider::new("github").email_verified(false))],
            ..OpenAuthOptions::default()
        },
    )?;
    let cookie = signed_session_cookie("token_1")?;
    let link = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/link-social",
            r#"{"provider":"github","callbackURL":"/settings","errorCallbackURL":"/link-error"}"#,
            Some(&cookie),
        )?)
        .await?;
    let body: Value = serde_json::from_slice(link.body())?;
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
        "/link-error?error=unable_to_link_account"
    );
    Ok(())
}

#[tokio::test]
async fn callback_oauth_post_allows_cross_site_form_post_navigation(
) -> Result<(), Box<dyn std::error::Error>> {
    // Build the router with origin/CSRF checks enabled (the shared helper
    // disables them) so we exercise the real `form_post` navigation path.
    let adapter = Arc::new(RouteAdapter::default());
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some(secret().to_owned()),
            base_url: Some("http://localhost:3000/api/auth".to_owned()),
            social_providers: vec![Arc::new(FakeProvider::new("apple"))],
            ..OpenAuthOptions::default()
        },
        adapter.clone(),
    )?;
    let router =
        AuthRouter::with_async_endpoints(context, Vec::new(), core_auth_async_endpoints(adapter))?;

    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/callback/apple")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("sec-fetch-site", "cross-site")
        .header("sec-fetch-mode", "navigate")
        .body(b"code=auth-code&state=state-value".to_vec())?;
    let response = router.handle_async(request).await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response
        .headers()
        .get(header::LOCATION)
        .ok_or("missing location")?
        .to_str()?;
    assert!(location.starts_with("http://localhost:3000/api/auth/callback/apple?"));
    assert!(location.contains("code=auth-code"));
    assert!(location.contains("state=state-value"));
    Ok(())
}

fn query_value(url: &str, key: &str) -> Option<String> {
    let query = url.split_once('?')?.1;
    query.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name == key).then(|| value.to_owned())
    })
}

#[derive(Debug)]
struct FakeProvider {
    id: String,
    name: Option<String>,
    image: Option<String>,
    email_verified: bool,
    options: ProviderOptions,
}

impl FakeProvider {
    fn new(id: &str) -> Self {
        Self {
            id: id.to_owned(),
            name: Some("Ada Lovelace".to_owned()),
            image: None,
            email_verified: true,
            options: ProviderOptions {
                client_id: Some("client-id".into()),
                client_secret: Some("client-secret".to_owned()),
                ..ProviderOptions::default()
            },
        }
    }

    fn name(mut self, name: &str) -> Self {
        self.name = Some(name.to_owned());
        self
    }

    fn image(mut self, image: Option<&str>) -> Self {
        self.image = image.map(str::to_owned);
        self
    }

    fn email_verified(mut self, email_verified: bool) -> Self {
        self.email_verified = email_verified;
        self
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
        let name = self.name.clone();
        let image = self.image.clone();
        let email_verified = self.email_verified;
        Box::pin(async move {
            Ok(Some(OAuth2UserInfo {
                id,
                name,
                email: Some("ada@example.com".to_owned()),
                image,
                email_verified,
            }))
        })
    }

    fn verify_id_token(&self, input: SocialIdTokenRequest) -> SocialProviderFuture<'_, bool> {
        Box::pin(async move { Ok(input.token == "valid-id-token") })
    }
}
