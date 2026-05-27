#![allow(clippy::unwrap_used)]

use super::*;
use crate::common::harness::{
    authenticated_context, plugin_endpoint, stripe_plugin, upgrade_request,
};
use openauth_core::db::{DbValue, FindOne, Where};

#[tokio::test]
async fn upgrade_reuses_existing_incomplete_subscription_row(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let plugin = stripe_plugin(transport);
    let endpoint = plugin_endpoint(&plugin, "/subscription/upgrade").ok_or("upgrade endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    adapter
        .create(
            openauth_core::db::Create::new("subscription")
                .data("id", DbValue::String("sub_incomplete".to_owned()))
                .data("plan", DbValue::String("basic".to_owned()))
                .data("reference_id", DbValue::String("user_1".to_owned()))
                .data("status", DbValue::String("incomplete".to_owned()))
                .data("seats", DbValue::Number(1))
                .data("billing_interval", DbValue::String("month".to_owned()))
                .force_allow_id(),
        )
        .await?;
    let request = upgrade_request(
        &cookie_header,
        br#"{"plan":"pro","successUrl":"/ok","cancelUrl":"/pricing"}"#,
    )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), http::StatusCode::OK);
    let updated = adapter
        .find_one(FindOne::new("subscription").where_clause(Where::new(
            "id",
            DbValue::String("sub_incomplete".to_owned()),
        )))
        .await?
        .ok_or("incomplete subscription")?;
    assert_eq!(
        updated.get("plan").and_then(|value| match value {
            DbValue::String(plan) => Some(plan.as_str()),
            _ => None,
        }),
        Some("pro")
    );
    let count = adapter
        .find_many(openauth_core::db::FindMany::new("subscription"))
        .await?
        .len();
    assert_eq!(count, 1, "should not create a second incomplete row");
    Ok(())
}
