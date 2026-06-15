mod common;

use std::sync::Arc;

use actix_web::http::{header, Method, StatusCode};
use actix_web::test;
use common::*;
use rustauth::db::DbFieldType;
use rustauth::db::MemoryAdapter;
use rustauth::options::{RustAuthOptions, SessionAdditionalField, SessionOptions};
use rustauth_actix_web::RustAuthActixWebOptions;

#[tokio::test]
async fn update_session_additional_fields_work_over_actix_web(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    let auth =
        Arc::new(
            auth_with_adapter(
                adapter,
                RustAuthOptions::default()
                    .base_url("http://localhost:3000/api/auth")
                    .session(SessionOptions::default().additional_field(
                        "theme",
                        SessionAdditionalField::new(DbFieldType::String),
                    )),
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

    let update = test::call_service(
        &app,
        json_test_request(
            Method::POST,
            "/api/auth/update-session",
            r#"{"theme":"dark"}"#,
            Some(&cookie),
        )
        .insert_header((header::ORIGIN, "http://localhost:3000"))
        .to_request(),
    )
    .await;
    assert_eq!(update.status(), StatusCode::OK);
    let update_body = body_json(update).await?;
    assert_eq!(update_body["session"]["theme"], "dark");

    let get_session = test::call_service(
        &app,
        test_request(Method::GET, "/api/auth/get-session", "", Some(&cookie)).to_request(),
    )
    .await;
    assert_eq!(get_session.status(), StatusCode::OK);
    let session_body = body_json(get_session).await?;
    assert_eq!(session_body["session"]["theme"], "dark");
    Ok(())
}
