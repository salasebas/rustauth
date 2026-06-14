mod common;

use axum::http::{header, Method, StatusCode};
use common::*;
use rustauth::db::MemoryAdapter;
use rustauth::options::RustAuthOptions;
use rustauth_axum::{RustAuthAxumExt, RustAuthAxumOptions};
use tower::ServiceExt;

#[tokio::test]
async fn fetch_metadata_blocks_cross_site_navigation_without_cookies(
) -> Result<(), Box<dyn std::error::Error>> {
    let app = auth_with_adapter(
        MemoryAdapter::new(),
        RustAuthOptions::default().base_url("http://localhost:3000/api/auth"),
    )
    .await?
    .mount_at_base_path(RustAuthAxumOptions::default())?;

    let response = app
        .oneshot(
            json_request(
                Method::POST,
                "/api/auth/sign-in/email",
                r#"{"email":"ada@example.com","password":"secret123"}"#,
                None,
            )?
            .with_header(
                header::HeaderName::from_static("sec-fetch-site"),
                "cross-site",
            )?
            .with_header(
                header::HeaderName::from_static("sec-fetch-mode"),
                "navigate",
            )?
            .with_header(header::ORIGIN, "https://evil.example.com")?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = body_json(response).await?;
    assert_eq!(body["code"], "CROSS_SITE_NAVIGATION_LOGIN_BLOCKED");
    Ok(())
}

#[tokio::test]
async fn fetch_metadata_allows_same_origin_navigation() -> Result<(), Box<dyn std::error::Error>> {
    let app = auth_with_adapter(
        MemoryAdapter::new(),
        RustAuthOptions::default().base_url("http://localhost:3000/api/auth"),
    )
    .await?
    .mount_at_base_path(RustAuthAxumOptions::default())?;

    let response = app
        .oneshot(
            json_request(
                Method::POST,
                "/api/auth/sign-in/email",
                r#"{"email":"ada@example.com","password":"secret123"}"#,
                None,
            )?
            .with_header(
                header::HeaderName::from_static("sec-fetch-site"),
                "same-origin",
            )?
            .with_header(
                header::HeaderName::from_static("sec-fetch-mode"),
                "navigate",
            )?
            .with_header(header::ORIGIN, "http://localhost:3000")?,
        )
        .await?;

    assert_ne!(response.status(), StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn fetch_metadata_allows_same_origin_cors_requests() -> Result<(), Box<dyn std::error::Error>>
{
    let app = auth_with_adapter(
        MemoryAdapter::new(),
        RustAuthOptions::default().base_url("http://localhost:3000/api/auth"),
    )
    .await?
    .mount_at_base_path(RustAuthAxumOptions::default())?;

    let response = app
        .oneshot(
            json_request(
                Method::POST,
                "/api/auth/sign-up/email",
                r#"{"name":"Ada Lovelace","email":"cors@example.com","password":"secret123"}"#,
                None,
            )?
            .with_header(
                header::HeaderName::from_static("sec-fetch-site"),
                "same-origin",
            )?
            .with_header(header::HeaderName::from_static("sec-fetch-mode"), "cors")?
            .with_header(header::HeaderName::from_static("sec-fetch-dest"), "empty")?
            .with_header(header::ORIGIN, "http://localhost:3000")?,
        )
        .await?;

    assert_ne!(response.status(), StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn fetch_metadata_with_cookies_uses_origin_validation(
) -> Result<(), Box<dyn std::error::Error>> {
    let app = auth_with_adapter(
        MemoryAdapter::new(),
        RustAuthOptions::default().base_url("http://localhost:3000/api/auth"),
    )
    .await?
    .mount_at_base_path(RustAuthAxumOptions::default())?;

    let response = app
        .oneshot(
            json_request(
                Method::POST,
                "/api/auth/sign-in/email",
                r#"{"email":"ada@example.com","password":"secret123"}"#,
                Some("better-auth.session_token=signed"),
            )?
            .with_header(
                header::HeaderName::from_static("sec-fetch-site"),
                "cross-site",
            )?
            .with_header(
                header::HeaderName::from_static("sec-fetch-mode"),
                "navigate",
            )?
            .with_header(header::ORIGIN, "http://localhost:3000")?,
        )
        .await?;

    assert_ne!(response.status(), StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn form_urlencoded_sign_up_and_sign_in_work_over_axum(
) -> Result<(), Box<dyn std::error::Error>> {
    let app = auth_with_adapter(
        MemoryAdapter::new(),
        RustAuthOptions::default().base_url("http://localhost:3000/api/auth"),
    )
    .await?
    .mount_at_base_path(RustAuthAxumOptions::default())?;

    let sign_up = app
        .clone()
        .oneshot(
            request(
                Method::POST,
                "/api/auth/sign-up/email",
                "name=Ada+Lovelace&email=ada%40example.com&password=secret123",
                None,
            )?
            .with_header(
                header::CONTENT_TYPE,
                "application/x-www-form-urlencoded; charset=utf-8",
            )?,
        )
        .await?;
    assert_eq!(sign_up.status(), StatusCode::OK);

    let sign_in = app
        .oneshot(
            request(
                Method::POST,
                "/api/auth/sign-in/email",
                "email=ada%40example.com&password=secret123",
                None,
            )?
            .with_header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")?,
        )
        .await?;

    assert_eq!(sign_in.status(), StatusCode::OK);
    let body = body_json(sign_in).await?;
    assert_eq!(body["user"]["email"], "ada@example.com");
    Ok(())
}

#[tokio::test]
async fn form_urlencoded_cross_site_navigation_is_blocked() -> Result<(), Box<dyn std::error::Error>>
{
    let app = auth_with_adapter(
        MemoryAdapter::new(),
        RustAuthOptions::default().base_url("http://localhost:3000/api/auth"),
    )
    .await?
    .mount_at_base_path(RustAuthAxumOptions::default())?;

    let response = app
        .oneshot(
            request(
                Method::POST,
                "/api/auth/sign-up/email",
                "name=Victim&email=victim%40example.com&password=secret123",
                None,
            )?
            .with_header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")?
            .with_header(
                header::HeaderName::from_static("sec-fetch-site"),
                "cross-site",
            )?
            .with_header(
                header::HeaderName::from_static("sec-fetch-mode"),
                "navigate",
            )?
            .with_header(
                header::HeaderName::from_static("sec-fetch-dest"),
                "document",
            )?
            .with_header(header::ORIGIN, "https://evil.example.com")?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = body_json(response).await?;
    assert_eq!(body["code"], "CROSS_SITE_NAVIGATION_LOGIN_BLOCKED");
    Ok(())
}

#[tokio::test]
async fn form_urlencoded_same_site_navigation_from_trusted_origin_is_allowed(
) -> Result<(), Box<dyn std::error::Error>> {
    let app = auth_with_adapter(
        MemoryAdapter::new(),
        RustAuthOptions::default().base_url("http://localhost:3000/api/auth"),
    )
    .await?
    .mount_at_base_path(RustAuthAxumOptions::default())?;

    let response = app
        .oneshot(
            request(
                Method::POST,
                "/api/auth/sign-up/email",
                "name=Same+Site&email=samesite%40example.com&password=secret123",
                None,
            )?
            .with_header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")?
            .with_header(
                header::HeaderName::from_static("sec-fetch-site"),
                "same-site",
            )?
            .with_header(
                header::HeaderName::from_static("sec-fetch-mode"),
                "navigate",
            )?
            .with_header(
                header::HeaderName::from_static("sec-fetch-dest"),
                "document",
            )?
            .with_header(header::ORIGIN, "http://localhost:3000")?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn callback_and_redirect_urls_are_validated_from_body_and_query(
) -> Result<(), Box<dyn std::error::Error>> {
    let app = auth_with_adapter(
        MemoryAdapter::new(),
        RustAuthOptions::default().base_url("http://localhost:3000/api/auth"),
    )
    .await?
    .mount_at_base_path(RustAuthAxumOptions::default())?;

    let body_rejection = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"secret123","callbackURL":"https://evil.example.com/cb"}"#,
            None,
        )?)
        .await?;
    assert_eq!(body_rejection.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(body_rejection).await?["code"],
        "INVALID_CALLBACK_URL"
    );

    let query_rejection = app
        .oneshot(json_request(
            Method::POST,
            "/api/auth/sign-in/email?callbackURL=https%3A%2F%2Fevil.example.com%2Freset",
            r#"{"email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    assert_eq!(query_rejection.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(query_rejection).await?["code"],
        "INVALID_CALLBACK_URL"
    );
    Ok(())
}
