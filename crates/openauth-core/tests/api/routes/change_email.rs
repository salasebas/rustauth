use super::*;

use openauth_core::options::{ChangeEmailOptions, UserOptions};

#[tokio::test]
async fn change_email_route_updates_unverified_user_when_allowed(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter
        .insert_user(User {
            email_verified: false,
            ..user(now)
        })
        .await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    let router = router_with_options(
        adapter.clone(),
        OpenAuthOptions {
            user: UserOptions {
                change_email: ChangeEmailOptions {
                    enabled: true,
                    update_email_without_verification: true,
                },
                ..UserOptions::default()
            },
            ..OpenAuthOptions::default()
        },
    )?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/change-email",
            r#"{"newEmail":"new@example.com"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["status"], true);
    assert_eq!(body["message"], "Email updated");
    assert!(!contains_record_string(&adapter, "user", "email", "ada@example.com").await?);
    let updated = record_by_string(&adapter, "user", "email", "new@example.com")
        .await?
        .ok_or("missing updated user")?;
    assert_eq!(
        updated.get("email"),
        Some(&DbValue::String("new@example.com".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn change_email_route_hides_existing_email() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter
        .insert_user(User {
            email_verified: false,
            ..user(now)
        })
        .await;
    adapter
        .insert_user(User {
            id: "user_2".to_owned(),
            email: "taken@example.com".to_owned(),
            ..user(now)
        })
        .await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    let router = router_with_options(
        adapter.clone(),
        OpenAuthOptions {
            user: UserOptions {
                change_email: ChangeEmailOptions {
                    enabled: true,
                    update_email_without_verification: true,
                },
                ..UserOptions::default()
            },
            ..OpenAuthOptions::default()
        },
    )?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/change-email",
            r#"{"newEmail":"taken@example.com"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["status"], true);
    assert!(contains_record_string(&adapter, "user", "email", "ada@example.com").await?);
    Ok(())
}
