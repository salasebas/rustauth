mod common;

use axum::http::{header, Method, StatusCode};
use common::*;
use openauth::{MemoryAdapter, OpenAuthOptions};
use openauth_axum::{router, router_with_options, OpenAuthAxumOptions};
use tower::ServiceExt;

#[tokio::test]
async fn social_sign_in_oauth2_and_callback_routes_work_over_axum(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    let app = router(auth_with_adapter(
        adapter.clone(),
        OpenAuthOptions::default()
            .base_url("http://localhost:3000/api/auth")
            .social_provider(FakeProvider::new("github")),
    )?)?;

    for path in ["/api/auth/sign-in/social", "/api/auth/sign-in/oauth2"] {
        let sign_in = app
            .clone()
            .oneshot(json_request(
                Method::POST,
                path,
                r#"{"provider":"github","callbackURL":"/dashboard","newUserCallbackURL":"/welcome"}"#,
                None,
            )?)
            .await?;
        assert_eq!(sign_in.status(), StatusCode::OK);
        let sign_in_body = body_json(sign_in).await?;
        let auth_url = sign_in_body["url"].as_str().ok_or("missing auth url")?;
        assert!(query_value(auth_url, "state").is_some());
    }

    let sign_in = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/api/auth/sign-in/social",
            r#"{"provider":"github","callbackURL":"/dashboard","newUserCallbackURL":"/welcome"}"#,
            None,
        )?)
        .await?;
    let sign_in_body = body_json(sign_in).await?;
    let auth_url = sign_in_body["url"].as_str().ok_or("missing auth url")?;
    let state = query_value(auth_url, "state").ok_or("missing oauth state")?;

    let callback = app
        .clone()
        .oneshot(request(
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
            .ok_or("missing callback location")?,
        "/welcome"
    );
    assert!(cookie_header(&callback).is_some());
    assert_eq!(adapter.len("account").await, 1);

    let callback_post = app
        .oneshot(json_request(
            Method::POST,
            "/api/auth/callback/github",
            r#"{"code":"ok","state":"missing"}"#,
            None,
        )?)
        .await?;
    assert_eq!(callback_post.status(), StatusCode::FOUND);
    Ok(())
}

#[tokio::test]
async fn social_sign_in_infers_base_url_from_host_when_unconfigured(
) -> Result<(), Box<dyn std::error::Error>> {
    let app = router(auth_with_adapter(
        MemoryAdapter::new(),
        OpenAuthOptions::default().social_provider(FakeProvider::new("github")),
    )?)?;

    let sign_in = app
        .oneshot(
            json_request(
                Method::POST,
                "/api/auth/sign-in/social",
                r#"{"provider":"github","callbackURL":"/dashboard"}"#,
                None,
            )?
            .with_header(header::HOST, "app.example.com")?,
        )
        .await?;

    assert_eq!(sign_in.status(), StatusCode::OK);
    let body = body_json(sign_in).await?;
    let auth_url = body["url"].as_str().ok_or("missing auth url")?;
    assert_eq!(
        query_value(auth_url, "redirect_uri"),
        Some("https://app.example.com/api/auth/callback/github".to_owned())
    );
    Ok(())
}

#[tokio::test]
async fn social_sign_in_uses_trusted_proxy_headers_only_when_enabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = || {
        auth_with_adapter(
            MemoryAdapter::new(),
            OpenAuthOptions::default().social_provider(FakeProvider::new("github")),
        )
    };

    let default_app = router(auth()?)?;
    let default_response = default_app
        .oneshot(
            json_request(
                Method::POST,
                "/api/auth/sign-in/social",
                r#"{"provider":"github","callbackURL":"/dashboard"}"#,
                None,
            )?
            .with_header(header::HOST, "internal.localhost")?
            .with_header(
                header::HeaderName::from_static("x-forwarded-host"),
                "public.example.com",
            )?
            .with_header(
                header::HeaderName::from_static("x-forwarded-proto"),
                "https",
            )?,
        )
        .await?;
    let default_body = body_json(default_response).await?;
    let default_url = default_body["url"].as_str().ok_or("missing auth url")?;
    assert_eq!(
        query_value(default_url, "redirect_uri"),
        Some("http://internal.localhost/api/auth/callback/github".to_owned())
    );

    let trusted_app = router_with_options(
        auth()?,
        OpenAuthAxumOptions::new().trust_proxy_headers_for_base_url(true),
    )?;
    let trusted_response = trusted_app
        .oneshot(
            json_request(
                Method::POST,
                "/api/auth/sign-in/social",
                r#"{"provider":"github","callbackURL":"/dashboard"}"#,
                None,
            )?
            .with_header(header::HOST, "internal.localhost")?
            .with_header(
                header::HeaderName::from_static("x-forwarded-host"),
                "public.example.com",
            )?
            .with_header(
                header::HeaderName::from_static("x-forwarded-proto"),
                "https",
            )?,
        )
        .await?;
    let trusted_body = body_json(trusted_response).await?;
    let trusted_url = trusted_body["url"].as_str().ok_or("missing auth url")?;
    assert_eq!(
        query_value(trusted_url, "redirect_uri"),
        Some("https://public.example.com/api/auth/callback/github".to_owned())
    );
    Ok(())
}
