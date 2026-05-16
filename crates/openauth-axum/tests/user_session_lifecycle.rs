mod common;

use axum::http::{header, Method, StatusCode};
use common::*;
use openauth::{DeleteUserOptions, MemoryAdapter, OpenAuthOptions, UserOptions};
use openauth_axum::router;
use tower::ServiceExt;

#[tokio::test]
async fn session_and_user_management_routes_work_over_axum(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    let app = router(auth_with_adapter(
        adapter.clone(),
        OpenAuthOptions::default().base_url("http://localhost:3000/api/auth"),
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
    let first_cookie = cookie_header(&sign_up).ok_or("missing sign-up cookie")?;

    let second_sign_in = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    assert_eq!(second_sign_in.status(), StatusCode::OK);
    let second_cookie = cookie_header(&second_sign_in).ok_or("missing sign-in cookie")?;
    let second_body = body_json(second_sign_in).await?;
    let second_token = second_body["token"]
        .as_str()
        .ok_or("missing second session token")?;

    let list_sessions = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/api/auth/list-sessions",
            "",
            Some(&first_cookie),
        )?)
        .await?;
    assert_eq!(list_sessions.status(), StatusCode::OK);
    let sessions = body_json(list_sessions).await?;
    assert_eq!(sessions.as_array().map(Vec::len), Some(2));

    let update_user = app
        .clone()
        .oneshot(
            json_request(
                Method::POST,
                "/api/auth/update-user",
                r#"{"name":"Grace","image":"https://example.com/grace.png"}"#,
                Some(&first_cookie),
            )?
            .with_header(header::ORIGIN, "http://localhost:3000")?,
        )
        .await?;
    assert_eq!(update_user.status(), StatusCode::OK);

    let get_session = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/api/auth/get-session",
            "",
            Some(&first_cookie),
        )?)
        .await?;
    assert_eq!(get_session.status(), StatusCode::OK);
    let session_body = body_json(get_session).await?;
    assert_eq!(session_body["user"]["name"], "Grace");

    let revoke_session = app
        .clone()
        .oneshot(
            json_request(
                Method::POST,
                "/api/auth/revoke-session",
                &format!(r#"{{"token":"{second_token}"}}"#),
                Some(&first_cookie),
            )?
            .with_header(header::ORIGIN, "http://localhost:3000")?,
        )
        .await?;
    assert_eq!(revoke_session.status(), StatusCode::OK);

    let second_session = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/api/auth/get-session",
            "",
            Some(&second_cookie),
        )?)
        .await?;
    let second_session_body = body_json(second_session).await?;
    assert!(second_session_body.is_null());

    let change_password = app
        .clone()
        .oneshot(
            json_request(
                Method::POST,
                "/api/auth/change-password",
                r#"{"currentPassword":"secret123","newPassword":"changed123"}"#,
                Some(&first_cookie),
            )?
            .with_header(header::ORIGIN, "http://localhost:3000")?,
        )
        .await?;
    assert_eq!(change_password.status(), StatusCode::OK);

    let sign_in_changed = app
        .oneshot(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"changed123"}"#,
            None,
        )?)
        .await?;
    assert_eq!(sign_in_changed.status(), StatusCode::OK);
    assert_eq!(adapter.len("user").await, 1);
    Ok(())
}

#[tokio::test]
async fn delete_user_route_works_over_axum() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    let app = router(auth_with_adapter(
        adapter.clone(),
        OpenAuthOptions::default()
            .base_url("http://localhost:3000/api/auth")
            .user(UserOptions::default().delete_user(DeleteUserOptions::default().enabled(true))),
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

    let delete_user = app
        .oneshot(
            json_request(
                Method::POST,
                "/api/auth/delete-user",
                r#"{"password":"secret123"}"#,
                Some(&cookie),
            )?
            .with_header(header::ORIGIN, "http://localhost:3000")?,
        )
        .await?;

    assert_eq!(delete_user.status(), StatusCode::OK);
    let body = body_json(delete_user).await?;
    assert_eq!(body["success"], true);
    assert_eq!(adapter.len("user").await, 0);
    assert_eq!(adapter.len("session").await, 0);
    Ok(())
}
