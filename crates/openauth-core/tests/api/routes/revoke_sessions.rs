use super::*;

#[tokio::test]
async fn revoke_sessions_route_deletes_all_current_user_sessions(
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
    adapter
        .insert_session(Session {
            id: "session_3".to_owned(),
            user_id: "user_2".to_owned(),
            token: "token_3".to_owned(),
            ..session(now, now + Duration::hours(2))
        })
        .await;
    let router = router(adapter.clone())?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/revoke-sessions",
            "{}",
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(!contains_record_string(&adapter, "session", "token", "token_1").await?);
    assert!(!contains_record_string(&adapter, "session", "token", "token_2").await?);
    assert!(contains_record_string(&adapter, "session", "token", "token_3").await?);
    Ok(())
}
