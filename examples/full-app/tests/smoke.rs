use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use tower::ServiceExt;

#[tokio::test]
async fn home_page_responds_ok() -> Result<(), Box<dyn std::error::Error>> {
    let response = openauth_example_full_app::app()
        .oneshot(Request::builder().uri("/").body(Body::empty())?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn dynamic_profile_sign_up_uses_selected_auth_path() -> Result<(), Box<dyn std::error::Error>>
{
    let app = openauth_example_full_app::app();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/example/auth/memory/memory/sign-up/email")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"name":"Test User","email":"profile@example.com","password":"password123456"}"#,
                ))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .any(|value| value
            .to_str()
            .is_ok_and(|cookie| cookie.starts_with("open-auth-memory.session_token="))));

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/example/auth/memory/memory/sign-in/email")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"email":"profile@example.com","password":"password123456"}"#,
                ))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn home_page_exposes_profile_selectors() -> Result<(), Box<dyn std::error::Error>> {
    let response = openauth_example_full_app::app()
        .oneshot(Request::builder().uri("/").body(Body::empty())?)
        .await?;
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
    let html = String::from_utf8(body.to_vec())?;

    assert!(html.contains(r#"id="profile-db""#));
    assert!(html.contains(r#"id="profile-rate-limit""#));
    assert!(html.contains(r#"data-tab="database""#));
    assert!(html.contains(r#"id="rate-settings-form""#));
    assert!(html.contains(r#"data-auth-root="/api/example/auth""#));
    Ok(())
}

#[tokio::test]
async fn database_viewer_reads_and_drops_memory_rows() -> Result<(), Box<dyn std::error::Error>> {
    let app = openauth_example_full_app::app();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/example/auth/memory/memory/sign-up/email")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"name":"Table User","email":"table@example.com","password":"password123456"}"#,
                ))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/example/table?db=memory&table=user&page_size=50")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
    let json: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(json["total"], 1);
    assert_eq!(json["rows"][0]["email"], "table@example.com");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/example/database/drop?db=memory")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/example/table?db=memory&table=user&page_size=50")
                .body(Body::empty())?,
        )
        .await?;
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
    let json: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(json["total"], 0);
    Ok(())
}

#[tokio::test]
async fn rate_limit_settings_apply_to_dynamic_memory_profile(
) -> Result<(), Box<dyn std::error::Error>> {
    let app = openauth_example_full_app::app();
    let request = || {
        Request::builder()
            .uri("/api/example/auth/memory/memory/ok")
            .header("x-openauth-example-rate-enabled", "true")
            .header("x-openauth-example-rate-window", "60")
            .header("x-openauth-example-rate-max", "2")
            .body(Body::empty())
    };

    assert_eq!(
        app.clone().oneshot(request()?).await?.status(),
        StatusCode::OK
    );
    assert_eq!(
        app.clone().oneshot(request()?).await?.status(),
        StatusCode::OK
    );
    assert_eq!(
        app.oneshot(request()?).await?.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    Ok(())
}

#[tokio::test]
async fn hardened_mode_rejects_database_control_endpoints() -> Result<(), Box<dyn std::error::Error>>
{
    let app = openauth_example_full_app::app_hardened();

    let viewer = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/example/table?db=memory&table=user&page_size=50")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(viewer.status(), StatusCode::FORBIDDEN);

    let tables = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/example/tables?db=memory")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(tables.status(), StatusCode::FORBIDDEN);

    let drop = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/example/database/drop?db=memory")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(drop.status(), StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn hardened_mode_ignores_rate_limit_override_headers(
) -> Result<(), Box<dyn std::error::Error>> {
    let app = openauth_example_full_app::app_hardened();
    // A public caller tries to shrink the limit to 1; hardened mode must ignore
    // these headers and keep the configured default (max 120), so repeated
    // probes stay successful instead of returning 429.
    let request = || {
        Request::builder()
            .uri("/api/example/auth/memory/memory/ok")
            .header("x-openauth-example-rate-enabled", "true")
            .header("x-openauth-example-rate-window", "60")
            .header("x-openauth-example-rate-max", "1")
            .body(Body::empty())
    };

    assert_eq!(
        app.clone().oneshot(request()?).await?.status(),
        StatusCode::OK
    );
    assert_eq!(
        app.clone().oneshot(request()?).await?.status(),
        StatusCode::OK
    );
    assert_eq!(app.oneshot(request()?).await?.status(), StatusCode::OK);
    Ok(())
}
