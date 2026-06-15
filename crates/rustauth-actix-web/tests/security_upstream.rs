mod common;

use std::sync::Arc;

use actix_web::http::{header, Method, StatusCode};
use actix_web::test;
use common::*;
use rustauth::db::MemoryAdapter;
use rustauth::options::RustAuthOptions;
use rustauth_actix_web::RustAuthActixWebOptions;

#[tokio::test]
async fn fetch_metadata_blocks_cross_site_navigation_without_cookies(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(
        auth_with_adapter(
            MemoryAdapter::new(),
            RustAuthOptions::default().base_url("http://localhost:3000/api/auth"),
        )
        .await?,
    );
    let app = mounted_app!(auth, RustAuthActixWebOptions::default());

    let response = test::call_service(
        &app,
        json_test_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"secret123"}"#,
            None,
        )
        .insert_header((
            header::HeaderName::from_static("sec-fetch-site"),
            "cross-site",
        ))
        .insert_header((
            header::HeaderName::from_static("sec-fetch-mode"),
            "navigate",
        ))
        .insert_header((header::ORIGIN, "https://evil.example.com"))
        .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = body_json(response).await?;
    assert_eq!(body["code"], "CROSS_SITE_NAVIGATION_LOGIN_BLOCKED");
    Ok(())
}

#[tokio::test]
async fn fetch_metadata_allows_same_origin_navigation() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(
        auth_with_adapter(
            MemoryAdapter::new(),
            RustAuthOptions::default().base_url("http://localhost:3000/api/auth"),
        )
        .await?,
    );
    let app = mounted_app!(auth, RustAuthActixWebOptions::default());

    let response = test::call_service(
        &app,
        json_test_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"secret123"}"#,
            None,
        )
        .insert_header((
            header::HeaderName::from_static("sec-fetch-site"),
            "same-origin",
        ))
        .insert_header((
            header::HeaderName::from_static("sec-fetch-mode"),
            "navigate",
        ))
        .insert_header((header::ORIGIN, "http://localhost:3000"))
        .to_request(),
    )
    .await;

    assert_ne!(response.status(), StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn fetch_metadata_allows_same_origin_cors_requests() -> Result<(), Box<dyn std::error::Error>>
{
    let auth = Arc::new(
        auth_with_adapter(
            MemoryAdapter::new(),
            RustAuthOptions::default().base_url("http://localhost:3000/api/auth"),
        )
        .await?,
    );
    let app = mounted_app!(auth, RustAuthActixWebOptions::default());

    let response = test::call_service(
        &app,
        json_test_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada Lovelace","email":"cors@example.com","password":"secret123"}"#,
            None,
        )
        .insert_header((
            header::HeaderName::from_static("sec-fetch-site"),
            "same-origin",
        ))
        .insert_header((header::HeaderName::from_static("sec-fetch-mode"), "cors"))
        .insert_header((header::HeaderName::from_static("sec-fetch-dest"), "empty"))
        .insert_header((header::ORIGIN, "http://localhost:3000"))
        .to_request(),
    )
    .await;

    assert_ne!(response.status(), StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn fetch_metadata_with_cookies_uses_origin_validation(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(
        auth_with_adapter(
            MemoryAdapter::new(),
            RustAuthOptions::default().base_url("http://localhost:3000/api/auth"),
        )
        .await?,
    );
    let app = mounted_app!(auth, RustAuthActixWebOptions::default());

    let response = test::call_service(
        &app,
        json_test_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"secret123"}"#,
            Some("better-auth.session_token=signed"),
        )
        .insert_header((
            header::HeaderName::from_static("sec-fetch-site"),
            "cross-site",
        ))
        .insert_header((
            header::HeaderName::from_static("sec-fetch-mode"),
            "navigate",
        ))
        .insert_header((header::ORIGIN, "http://localhost:3000"))
        .to_request(),
    )
    .await;

    assert_ne!(response.status(), StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn form_urlencoded_sign_up_and_sign_in_work_over_actix_web(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(
        auth_with_adapter(
            MemoryAdapter::new(),
            RustAuthOptions::default().base_url("http://localhost:3000/api/auth"),
        )
        .await?,
    );
    let app = mounted_app!(auth, RustAuthActixWebOptions::default());

    let sign_up = test::call_service(
        &app,
        test_request(
            Method::POST,
            "/api/auth/sign-up/email",
            "name=Ada+Lovelace&email=ada%40example.com&password=secret123",
            None,
        )
        .insert_header((
            header::CONTENT_TYPE,
            "application/x-www-form-urlencoded; charset=utf-8",
        ))
        .to_request(),
    )
    .await;
    assert_eq!(sign_up.status(), StatusCode::OK);

    let sign_in = test::call_service(
        &app,
        test_request(
            Method::POST,
            "/api/auth/sign-in/email",
            "email=ada%40example.com&password=secret123",
            None,
        )
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_request(),
    )
    .await;

    assert_eq!(sign_in.status(), StatusCode::OK);
    let body = body_json(sign_in).await?;
    assert_eq!(body["user"]["email"], "ada@example.com");
    Ok(())
}

#[tokio::test]
async fn form_urlencoded_cross_site_navigation_is_blocked() -> Result<(), Box<dyn std::error::Error>>
{
    let auth = Arc::new(
        auth_with_adapter(
            MemoryAdapter::new(),
            RustAuthOptions::default().base_url("http://localhost:3000/api/auth"),
        )
        .await?,
    );
    let app = mounted_app!(auth, RustAuthActixWebOptions::default());

    let response = test::call_service(
        &app,
        test_request(
            Method::POST,
            "/api/auth/sign-up/email",
            "name=Victim&email=victim%40example.com&password=secret123",
            None,
        )
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .insert_header((
            header::HeaderName::from_static("sec-fetch-site"),
            "cross-site",
        ))
        .insert_header((
            header::HeaderName::from_static("sec-fetch-mode"),
            "navigate",
        ))
        .insert_header((
            header::HeaderName::from_static("sec-fetch-dest"),
            "document",
        ))
        .insert_header((header::ORIGIN, "https://evil.example.com"))
        .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = body_json(response).await?;
    assert_eq!(body["code"], "CROSS_SITE_NAVIGATION_LOGIN_BLOCKED");
    Ok(())
}

#[tokio::test]
async fn form_urlencoded_same_site_navigation_from_trusted_origin_is_allowed(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(
        auth_with_adapter(
            MemoryAdapter::new(),
            RustAuthOptions::default().base_url("http://localhost:3000/api/auth"),
        )
        .await?,
    );
    let app = mounted_app!(auth, RustAuthActixWebOptions::default());

    let response = test::call_service(
        &app,
        test_request(
            Method::POST,
            "/api/auth/sign-up/email",
            "name=Same+Site&email=samesite%40example.com&password=secret123",
            None,
        )
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .insert_header((
            header::HeaderName::from_static("sec-fetch-site"),
            "same-site",
        ))
        .insert_header((
            header::HeaderName::from_static("sec-fetch-mode"),
            "navigate",
        ))
        .insert_header((
            header::HeaderName::from_static("sec-fetch-dest"),
            "document",
        ))
        .insert_header((header::ORIGIN, "http://localhost:3000"))
        .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn callback_and_redirect_urls_are_validated_from_body_and_query(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(
        auth_with_adapter(
            MemoryAdapter::new(),
            RustAuthOptions::default().base_url("http://localhost:3000/api/auth"),
        )
        .await?,
    );
    let app = mounted_app!(auth, RustAuthActixWebOptions::default());

    let body_rejection = test::call_service(
        &app,
        json_test_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"secret123","callbackURL":"https://evil.example.com/cb"}"#,
            None,
        )
        .to_request(),
    )
    .await;
    assert_eq!(body_rejection.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(body_rejection).await?["code"],
        "INVALID_CALLBACK_URL"
    );

    let query_rejection = test::call_service(
        &app,
        json_test_request(
            Method::POST,
            "/api/auth/sign-in/email?callbackURL=https%3A%2F%2Fevil.example.com%2Freset",
            r#"{"email":"ada@example.com","password":"secret123"}"#,
            None,
        )
        .to_request(),
    )
    .await;
    assert_eq!(query_rejection.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(query_rejection).await?["code"],
        "INVALID_CALLBACK_URL"
    );
    Ok(())
}
