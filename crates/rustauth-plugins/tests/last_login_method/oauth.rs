use std::sync::Arc;

use http::{header, Method, StatusCode};
use rustauth_core::db::{DbValue, MemoryAdapter};
use rustauth_core::options::RustAuthOptions;
use serde_json::Value;

use super::helpers::{
    find_user_by_email, json_request, router_with_plugin_options, set_cookie_values, FakeProvider,
};
use rustauth_plugins::last_login_method::{LastLoginMethodOptions, DEFAULT_COOKIE_NAME};

#[tokio::test]
async fn oauth_callback_persists_provider_id_and_sets_last_method_cookie(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router_with_plugin_options(
        adapter.clone(),
        LastLoginMethodOptions::default(),
        RustAuthOptions {
            base_url: Some("http://localhost:3000/api/auth".to_owned()),
            social_providers: vec![Arc::new(FakeProvider::new("github"))],
            ..RustAuthOptions::default()
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
    let oauth_state_cookie = oauth_state_cookie_header(&sign_in)?;

    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("/api/auth/callback/github?code=ok&state={state}"),
            "",
            Some(&oauth_state_cookie),
        )?)
        .await?;

    assert_eq!(callback.status(), StatusCode::FOUND);
    assert!(set_cookie_values(&callback)
        .iter()
        .any(|cookie| cookie.starts_with(&format!("{DEFAULT_COOKIE_NAME}=github"))));
    let user = find_user_by_email(adapter.as_ref(), "ada.oauth@example.com")
        .await?
        .ok_or("missing OAuth user")?;
    assert_eq!(
        user.get("last_login_method"),
        Some(&DbValue::String("github".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn failed_oauth_callback_does_not_persist_or_set_cookie(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router_with_plugin_options(
        adapter.clone(),
        LastLoginMethodOptions::default(),
        RustAuthOptions {
            base_url: Some("http://localhost:3000/api/auth".to_owned()),
            social_providers: vec![Arc::new(FakeProvider::new("github"))],
            ..RustAuthOptions::default()
        },
    )?;
    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/social",
            r#"{"provider":"github","callbackURL":"/dashboard","errorCallbackURL":"/error"}"#,
            None,
        )?)
        .await?;
    let body: Value = serde_json::from_slice(sign_in.body())?;
    let state =
        query_value(body["url"].as_str().ok_or("missing url")?, "state").ok_or("missing state")?;
    let oauth_state_cookie = oauth_state_cookie_header(&sign_in)?;

    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("/api/auth/callback/github?error=access_denied&state={state}"),
            "",
            Some(&oauth_state_cookie),
        )?)
        .await?;

    assert_eq!(callback.status(), StatusCode::FOUND);
    assert!(set_cookie_values(&callback)
        .iter()
        .all(|cookie| !cookie.starts_with(DEFAULT_COOKIE_NAME)));
    assert_eq!(
        callback
            .headers()
            .get(header::LOCATION)
            .ok_or("missing location")?,
        "/error?error=access_denied"
    );
    assert!(
        find_user_by_email(adapter.as_ref(), "ada.oauth@example.com")
            .await?
            .is_none()
    );
    Ok(())
}

fn query_value(url: &str, key: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()?
        .query_pairs()
        .find_map(|(name, value)| (name == key).then(|| value.into_owned()))
}

fn oauth_state_cookie_header(
    response: &http::Response<Vec<u8>>,
) -> Result<String, Box<dyn std::error::Error>> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|cookie| {
            let (name, rest) = cookie.split_once('=')?;
            (name == "rustauth.oauth_state" || name == "__Secure-rustauth.oauth_state").then(|| {
                let value = rest.split(';').next().unwrap_or_default();
                format!("{name}={value}")
            })
        })
        .ok_or_else(|| "missing oauth_state cookie".into())
}
