use super::*;

use openauth_core::options::{DeleteUserOptions, UserOptions};

#[tokio::test]
async fn delete_user_route_deletes_user_accounts_and_sessions_with_password(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_account(credential_account_record(
            "user_1",
            &hash_password("secret123")?,
            now,
        ))
        .await?;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    adapter
        .insert_session(Session {
            id: "session_2".to_owned(),
            token: "token_2".to_owned(),
            ..session(now, now + Duration::hours(1))
        })
        .await;
    let router = router_with_options(
        adapter.clone(),
        OpenAuthOptions {
            user: UserOptions {
                delete_user: DeleteUserOptions { enabled: true },
                ..UserOptions::default()
            },
            ..OpenAuthOptions::default()
        },
    )?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/delete-user",
            r#"{"password":"secret123"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["success"], true);
    assert_eq!(body["message"], "User deleted");
    assert!(adapter.is_empty("user").await);
    assert!(adapter.is_empty("account").await);
    assert!(adapter.is_empty("session").await);
    assert!(set_cookie_values(&response)
        .iter()
        .any(|cookie| cookie.starts_with("better-auth.session_token=;")
            && cookie.contains("Max-Age=0")));
    Ok(())
}

#[tokio::test]
async fn delete_user_route_rejects_wrong_password() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_account(credential_account_record(
            "user_1",
            &hash_password("secret123")?,
            now,
        ))
        .await?;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    let router = router_with_options(
        adapter.clone(),
        OpenAuthOptions {
            user: UserOptions {
                delete_user: DeleteUserOptions { enabled: true },
                ..UserOptions::default()
            },
            ..OpenAuthOptions::default()
        },
    )?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/delete-user",
            r#"{"password":"wrong-password"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "INVALID_PASSWORD");
    assert!(contains_record_string(&adapter, "user", "email", "ada@example.com").await?);
    Ok(())
}
