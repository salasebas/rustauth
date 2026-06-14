use super::*;
use time::Duration;

#[tokio::test]
async fn list_accounts_route_returns_current_user_accounts(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    adapter
        .insert_account(credential_account_record(
            "user_1",
            &fast_hash_password("secret123")?,
            now,
        ))
        .await?;
    adapter
        .insert_account(linked_account_record(
            "account_2",
            "github",
            "github_ada",
            "user_1",
            Some("read:user,user:email"),
            now,
        ))
        .await?;
    let router = router(adapter)?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/list-accounts",
            "",
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body.as_array().map(Vec::len), Some(2));
    assert_eq!(body[0]["userId"], "user_1");
    assert!(body
        .as_array()
        .into_iter()
        .flatten()
        .any(|account| account["providerId"] == "github"
            && account["scopes"] == serde_json::json!(["read:user", "user:email"])));
    Ok(())
}
