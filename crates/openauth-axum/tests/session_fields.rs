mod common;

use axum::http::{header, Method, StatusCode};
use common::*;
use openauth::db::DbFieldType;
use openauth::{MemoryAdapter, OpenAuthOptions, SessionAdditionalField, SessionOptions};
use openauth_axum::router;
use tower::ServiceExt;

#[tokio::test]
async fn update_session_additional_fields_work_over_axum() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = MemoryAdapter::new();
    let app = router(auth_with_adapter(
        adapter,
        OpenAuthOptions::default()
            .base_url("http://localhost:3000/api/auth")
            .session(
                SessionOptions::default()
                    .additional_field("theme", SessionAdditionalField::new(DbFieldType::String)),
            ),
    )?)?;

    let sign_up = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    assert_eq!(sign_up.status(), StatusCode::OK);
    let cookie = cookie_header(&sign_up).ok_or("missing sign-up cookie")?;

    let update = app
        .clone()
        .oneshot(
            json_request(
                Method::POST,
                "/api/auth/update-session",
                r#"{"theme":"dark"}"#,
                Some(&cookie),
            )?
            .with_header(header::ORIGIN, "http://localhost:3000")?,
        )
        .await?;
    assert_eq!(update.status(), StatusCode::OK);
    let update_body = body_json(update).await?;
    assert_eq!(update_body["session"]["theme"], "dark");

    let get_session = app
        .oneshot(request(
            Method::GET,
            "/api/auth/get-session",
            "",
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(get_session.status(), StatusCode::OK);
    let session_body = body_json(get_session).await?;
    assert_eq!(session_body["session"]["theme"], "dark");
    Ok(())
}
