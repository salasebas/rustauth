use super::*;
use time::Duration;

#[tokio::test]
async fn unlink_account_route_deletes_matching_account_when_multiple_linked(
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
            None,
            now,
        ))
        .await?;
    let router = router(adapter.clone())?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/unlink-account",
            r#"{"providerId":"github","accountId":"github_ada"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["status"], true);
    assert!(!contains_record_string(&adapter, "account", "id", "account_2").await?);
    assert!(contains_record_string(&adapter, "account", "id", "account_1").await?);
    Ok(())
}

#[tokio::test]
async fn unlink_account_route_rejects_last_account() -> Result<(), Box<dyn std::error::Error>> {
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
    let router = router(adapter.clone())?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/unlink-account",
            r#"{"providerId":"credential","accountId":"user_1"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "FAILED_TO_UNLINK_LAST_ACCOUNT");
    assert!(contains_record_string(&adapter, "account", "id", "account_1").await?);
    Ok(())
}

#[tokio::test]
async fn unlink_account_route_allows_last_account_when_enabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    adapter
        .insert_account(linked_account_record(
            "account_2",
            "github",
            "github_ada",
            "user_1",
            None,
            now,
        ))
        .await?;
    let router = router_with_options(
        adapter.clone(),
        RustAuthOptions {
            account: rustauth_core::options::AccountOptions {
                account_linking: rustauth_core::options::AccountLinkingOptions {
                    allow_unlinking_all: true,
                    ..rustauth_core::options::AccountLinkingOptions::default()
                },
                ..rustauth_core::options::AccountOptions::default()
            },
            ..RustAuthOptions::default()
        },
    )?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/unlink-account",
            r#"{"providerId":"github","accountId":"github_ada"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(!contains_record_string(&adapter, "account", "id", "account_2").await?);
    Ok(())
}
