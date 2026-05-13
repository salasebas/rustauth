use super::*;

use openauth_core::options::{DeleteUserOptions, UserOptions};

#[tokio::test]
async fn delete_user_callback_route_deletes_user_for_valid_token(
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
        .create(
            Create::new("verification")
                .data("id", DbValue::String("verification_1".to_owned()))
                .data(
                    "identifier",
                    DbValue::String("delete-account-delete_token".to_owned()),
                )
                .data("value", DbValue::String("user_1".to_owned()))
                .data("expires_at", DbValue::Timestamp(now + Duration::hours(1)))
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Timestamp(now)),
        )
        .await?;
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
            Method::GET,
            "/api/auth/delete-user/callback?token=delete_token",
            "",
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["success"], true);
    assert!(adapter.is_empty("user").await);
    assert!(adapter.is_empty("account").await);
    assert!(adapter.is_empty("session").await);
    assert!(adapter.is_empty("verification").await);
    Ok(())
}
