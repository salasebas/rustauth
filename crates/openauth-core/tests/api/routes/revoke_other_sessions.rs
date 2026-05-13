use super::*;

#[tokio::test]
async fn revoke_other_sessions_route_keeps_current_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    adapter
        .insert_session(Session {
            id: "session_2".to_owned(),
            token: "token_2".to_owned(),
            ..session(now, now + Duration::hours(2))
        })
        .await;
    let router = router(adapter.clone())?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/revoke-other-sessions",
            "{}",
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(contains_record_string(&adapter, "session", "token", "token_1").await?);
    assert!(!contains_record_string(&adapter, "session", "token", "token_2").await?);
    Ok(())
}
