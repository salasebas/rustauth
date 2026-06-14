use super::*;
use time::Duration;

#[tokio::test]
async fn list_sessions_route_returns_active_user_sessions() -> Result<(), Box<dyn std::error::Error>>
{
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
            Method::GET,
            "/api/auth/list-sessions",
            "",
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body.as_array().map(Vec::len), Some(2));
    assert_eq!(body[0]["userId"], "user_1");
    Ok(())
}
