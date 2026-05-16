mod common;

use axum::http::{header, Method, StatusCode};
use common::*;
use openauth::{MemoryAdapter, OpenAuthOptions};
use openauth_axum::router;
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
