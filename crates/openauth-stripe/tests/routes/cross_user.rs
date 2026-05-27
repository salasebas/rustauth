#![allow(clippy::unwrap_used)]

use super::*;
use crate::common::harness::{
    create_user, json_post_request, plugin_endpoint, session_cookie_for_user, stripe_plugin,
};

#[tokio::test]
async fn cross_user_subscription_operations_reject_foreign_subscription_id(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let plugin = stripe_plugin(Arc::clone(&transport) as Arc<dyn StripeTransport>);
    let upgrade = plugin_endpoint(&plugin, "/subscription/upgrade").ok_or("upgrade endpoint")?;
    let cancel = plugin_endpoint(&plugin, "/subscription/cancel").ok_or("cancel endpoint")?;
    let restore = plugin_endpoint(&plugin, "/subscription/restore").ok_or("restore endpoint")?;
    let (context, adapter, _user_a_cookie) = authenticated_context().await?;
    create_subscription_record(&adapter, "sub_user_a", "user_1", "active", Some("cus_a")).await?;
    openauth_core::db::DbAdapter::update(
        &adapter,
        openauth_core::db::Update::new("subscription")
            .where_clause(openauth_core::db::Where::new(
                "id",
                DbValue::String("sub_user_a".to_owned()),
            ))
            .data(
                "stripe_subscription_id",
                DbValue::String("stripe_sub_user_a".to_owned()),
            ),
    )
    .await?;
    let user_b = create_user(&adapter, "user_2", "user-b@example.com").await?;
    let user_b_cookie =
        session_cookie_for_user(&context, &adapter, &user_b, "session_token_2").await?;

    let upgrade_request = json_post_request(
        "/subscription/upgrade",
        &user_b_cookie,
        br#"{"plan":"pro","subscriptionId":"stripe_sub_user_a","successUrl":"/ok","cancelUrl":"/pricing"}"#,
    )?;
    let upgrade_response = (upgrade.handler)(&context, upgrade_request).await?;
    assert_eq!(upgrade_response.status(), StatusCode::BAD_REQUEST);
    let upgrade_body: Value = serde_json::from_slice(upgrade_response.body())?;
    assert_eq!(upgrade_body["code"], "SUBSCRIPTION_NOT_FOUND");

    let cancel_request = json_post_request(
        "/subscription/cancel",
        &user_b_cookie,
        br#"{"subscriptionId":"stripe_sub_user_a","returnUrl":"/account"}"#,
    )?;
    let cancel_response = (cancel.handler)(&context, cancel_request).await?;
    assert_eq!(cancel_response.status(), StatusCode::BAD_REQUEST);
    let cancel_body: Value = serde_json::from_slice(cancel_response.body())?;
    assert_eq!(cancel_body["code"], "SUBSCRIPTION_NOT_FOUND");

    let restore_request = json_post_request(
        "/subscription/restore",
        &user_b_cookie,
        br#"{"subscriptionId":"stripe_sub_user_a"}"#,
    )?;
    let restore_response = (restore.handler)(&context, restore_request).await?;
    assert_eq!(restore_response.status(), StatusCode::BAD_REQUEST);
    let restore_body: Value = serde_json::from_slice(restore_response.body())?;
    assert_eq!(restore_body["code"], "SUBSCRIPTION_NOT_FOUND");

    assert!(transport.requests()?.is_empty());
    Ok(())
}
