mod common;

use std::sync::Arc;

use actix_web::http::{header, Method, StatusCode};
use actix_web::test;
use common::*;
use rustauth::db::MemoryAdapter;
use rustauth::options::RustAuthOptions;
use rustauth_actix_web::RustAuthActixWebOptions;

#[tokio::test]
async fn email_password_session_lifecycle_works_over_actix_web(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    let auth = Arc::new(
        auth_with_adapter(
            adapter.clone(),
            RustAuthOptions::default().base_url("http://localhost:3000/api/auth"),
        )
        .await?,
    );
    let app = mounted_app!(auth, RustAuthActixWebOptions::default());

    let sign_up = test::call_service(
        &app,
        json_test_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )
        .to_request(),
    )
    .await;
    assert_eq!(sign_up.status(), StatusCode::OK);
    let cookie = cookie_header(&sign_up).ok_or("missing sign-up cookie")?;
    let sign_up_body = body_json(sign_up).await?;
    assert!(sign_up_body["token"].is_string());
    assert_eq!(adapter.len("user").await, 1);
    assert_eq!(adapter.len("session").await, 1);

    let get_session = test::call_service(
        &app,
        test_request(Method::GET, "/api/auth/get-session", "", Some(&cookie)).to_request(),
    )
    .await;
    assert_eq!(get_session.status(), StatusCode::OK);
    let session_body = body_json(get_session).await?;
    assert_eq!(session_body["user"]["email"], "ada@example.com");

    let sign_out = test::call_service(
        &app,
        json_test_request(Method::POST, "/api/auth/sign-out", "{}", Some(&cookie))
            .insert_header((header::ORIGIN, "http://localhost:3000"))
            .to_request(),
    )
    .await;
    assert_eq!(sign_out.status(), StatusCode::OK);
    assert!(cookie_header(&sign_out).is_some());

    let sign_in = test::call_service(
        &app,
        json_test_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"secret123"}"#,
            None,
        )
        .to_request(),
    )
    .await;
    assert_eq!(sign_in.status(), StatusCode::OK);
    let sign_in_body = body_json(sign_in).await?;
    assert_eq!(sign_in_body["user"]["email"], "ada@example.com");
    Ok(())
}
