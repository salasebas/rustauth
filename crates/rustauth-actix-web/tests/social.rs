mod common;

use std::sync::Arc;

use actix_web::http::{header, Method, StatusCode};
use actix_web::test;
use common::*;
use rustauth::db::MemoryAdapter;
use rustauth::options::{RustAuthOptions, TrustedOriginOptions};
use rustauth_actix_web::RustAuthActixWebOptions;

#[tokio::test]
async fn social_sign_in_and_callback_routes_work_over_actix_web(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    let auth = Arc::new(
        auth_with_adapter(
            adapter.clone(),
            RustAuthOptions::default()
                .base_url("http://localhost:3000/api/auth")
                .social_provider(FakeProvider::new("github")),
        )
        .await?,
    );
    let app = mounted_app!(auth, RustAuthActixWebOptions::default());

    let sign_in = test::call_service(
        &app,
        json_test_request(
            Method::POST,
            "/api/auth/sign-in/social",
            r#"{"provider":"github","callbackURL":"/dashboard","newUserCallbackURL":"/welcome"}"#,
            None,
        )
        .to_request(),
    )
    .await;
    let oauth_state_cookie = cookie_header(&sign_in).ok_or("missing oauth state cookie")?;
    let sign_in_body = body_json(sign_in).await?;
    let auth_url = sign_in_body["url"].as_str().ok_or("missing auth url")?;
    let state = query_value(auth_url, "state").ok_or("missing oauth state")?;

    let callback = test::call_service(
        &app,
        test_request(
            Method::GET,
            &format!("/api/auth/callback/github?code=ok&state={state}"),
            "",
            Some(&oauth_state_cookie),
        )
        .to_request(),
    )
    .await;
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

    let callback_post = test::call_service(
        &app,
        json_test_request(
            Method::POST,
            "/api/auth/callback/github",
            r#"{"code":"ok","state":"missing"}"#,
            None,
        )
        .to_request(),
    )
    .await;
    assert_eq!(callback_post.status(), StatusCode::FOUND);
    Ok(())
}

#[tokio::test]
async fn social_sign_in_infers_base_url_from_host_when_unconfigured(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(
        auth_with_adapter(
            MemoryAdapter::new(),
            RustAuthOptions::default()
                .trusted_origins(TrustedOriginOptions::Static(vec![
                    "https://app.example.com".to_owned(),
                ]))
                .social_provider(FakeProvider::new("github")),
        )
        .await?,
    );
    let app = mounted_app!(
        auth,
        RustAuthActixWebOptions::new().infer_base_url_from_request(true),
    );

    let sign_in = test::call_service(
        &app,
        json_test_request(
            Method::POST,
            "/api/auth/sign-in/social",
            r#"{"provider":"github","callbackURL":"/dashboard"}"#,
            None,
        )
        .insert_header((header::HOST, "app.example.com"))
        .to_request(),
    )
    .await;

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
async fn social_sign_in_rejects_host_origin_callback_by_default(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(
        auth_with_adapter(
            MemoryAdapter::new(),
            RustAuthOptions::default().social_provider(FakeProvider::new("github")),
        )
        .await?,
    );
    let app = mounted_app!(auth, RustAuthActixWebOptions::default());

    let response = test::call_service(
        &app,
        json_test_request(
            Method::POST,
            "/api/auth/sign-in/social",
            r#"{"provider":"github","callbackURL":"https://evil.example.com/dashboard"}"#,
            None,
        )
        .insert_header((header::HOST, "evil.example.com"))
        .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = body_json(response).await?;
    assert_eq!(body["code"], "INVALID_CALLBACK_URL");
    Ok(())
}

#[tokio::test]
async fn social_sign_in_uses_trusted_proxy_headers_only_when_enabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth_options = || {
        RustAuthOptions::default()
            .trusted_origins(TrustedOriginOptions::Static(vec![
                "http://internal.localhost".to_owned(),
                "https://public.example.com".to_owned(),
            ]))
            .social_provider(FakeProvider::new("github"))
    };

    let default_auth = Arc::new(auth_with_adapter(MemoryAdapter::new(), auth_options()).await?);
    let default_app = mounted_app!(
        default_auth,
        RustAuthActixWebOptions::new().infer_base_url_from_request(true),
    );
    let default_response = test::call_service(
        &default_app,
        json_test_request(
            Method::POST,
            "/api/auth/sign-in/social",
            r#"{"provider":"github","callbackURL":"/dashboard"}"#,
            None,
        )
        .insert_header((header::HOST, "internal.localhost"))
        .insert_header((
            header::HeaderName::from_static("x-forwarded-host"),
            "public.example.com",
        ))
        .insert_header((
            header::HeaderName::from_static("x-forwarded-proto"),
            "https",
        ))
        .to_request(),
    )
    .await;
    let default_body = body_json(default_response).await?;
    let default_url = default_body["url"].as_str().ok_or("missing auth url")?;
    assert_eq!(
        query_value(default_url, "redirect_uri"),
        Some("http://internal.localhost/api/auth/callback/github".to_owned())
    );

    let trusted_auth = Arc::new(auth_with_adapter(MemoryAdapter::new(), auth_options()).await?);
    let trusted_app = mounted_app!(
        trusted_auth,
        RustAuthActixWebOptions::new()
            .infer_base_url_from_request(true)
            .trust_proxy_headers_for_base_url(true),
    );
    let trusted_response = test::call_service(
        &trusted_app,
        json_test_request(
            Method::POST,
            "/api/auth/sign-in/social",
            r#"{"provider":"github","callbackURL":"/dashboard"}"#,
            None,
        )
        .insert_header((header::HOST, "internal.localhost"))
        .insert_header((
            header::HeaderName::from_static("x-forwarded-host"),
            "public.example.com",
        ))
        .insert_header((
            header::HeaderName::from_static("x-forwarded-proto"),
            "https",
        ))
        .to_request(),
    )
    .await;
    let trusted_body = body_json(trusted_response).await?;
    let trusted_url = trusted_body["url"].as_str().ok_or("missing auth url")?;
    assert_eq!(
        query_value(trusted_url, "redirect_uri"),
        Some("https://public.example.com/api/auth/callback/github".to_owned())
    );
    Ok(())
}
