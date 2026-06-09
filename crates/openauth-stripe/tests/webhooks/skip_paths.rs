#![allow(clippy::unwrap_used)]

use crate::common::webhook::signed_webhook_request;
use http::StatusCode;
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::db::{Create, DbAdapter, DbValue, FindMany, MemoryAdapter, Where};
use openauth_core::options::OpenAuthOptions;
use openauth_stripe::options::{StripeOptions, StripePlan, SubscriptionOptions};
use openauth_stripe::stripe;
use openauth_stripe::stripe_api::StripeClient;
use std::sync::Arc;

async fn webhook_context() -> Result<
    (
        openauth_core::context::AuthContext,
        MemoryAdapter,
        openauth_core::plugin::AuthPlugin,
    ),
    Box<dyn std::error::Error>,
> {
    let plugin = stripe(
        StripeOptions::new(StripeClient::new("sk_test"), "whsec_test").subscription(
            SubscriptionOptions::enabled(vec![StripePlan::new("pro").price_id("price_pro")]),
        ),
    )
    .unwrap();
    let adapter = MemoryAdapter::new();
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            ..OpenAuthOptions::default()
        },
        Arc::new(adapter.clone()) as Arc<dyn DbAdapter>,
    )?;
    Ok((context, adapter, plugin))
}

#[tokio::test]
async fn subscription_created_webhook_skips_when_local_record_already_exists(
) -> Result<(), Box<dyn std::error::Error>> {
    let (context, adapter, plugin) = webhook_context().await?;
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/stripe/webhook")
        .ok_or("webhook endpoint")?;
    adapter
        .create(
            Create::new("subscription")
                .data("id", DbValue::String("sub_existing".to_owned()))
                .data("plan", DbValue::String("pro".to_owned()))
                .data("reference_id", DbValue::String("user_1".to_owned()))
                .data(
                    "stripe_subscription_id",
                    DbValue::String("stripe_sub_existing".to_owned()),
                )
                .data("status", DbValue::String("active".to_owned()))
                .force_allow_id(),
        )
        .await?;
    let payload = br#"{"id":"evt_existing","type":"customer.subscription.created","data":{"object":{"id":"stripe_sub_existing","customer":"cus_123","status":"active","metadata":{"subscriptionId":"sub_existing"},"cancel_at_period_end":false,"items":{"data":[{"id":"si_existing","price":{"id":"price_pro","recurring":{"interval":"month","usage_type":"licensed"}},"quantity":1,"current_period_start":1700000000,"current_period_end":1702592000}]}}}}"#;
    let request = signed_webhook_request("whsec_test", payload)?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(adapter.records("subscription").await.len(), 1);
    Ok(())
}

#[tokio::test]
async fn subscription_created_webhook_skips_without_customer_id(
) -> Result<(), Box<dyn std::error::Error>> {
    let (context, adapter, plugin) = webhook_context().await?;
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/stripe/webhook")
        .ok_or("webhook endpoint")?;
    let payload = br#"{"id":"evt_no_customer","type":"customer.subscription.created","data":{"object":{"id":"stripe_sub_orphan","status":"active","metadata":{},"cancel_at_period_end":false,"items":{"data":[{"id":"si_orphan","price":{"id":"price_pro","recurring":{"interval":"month","usage_type":"licensed"}},"quantity":1}]}}}}"#;
    let request = signed_webhook_request("whsec_test", payload)?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(adapter.records("subscription").await.is_empty());
    Ok(())
}

#[tokio::test]
async fn subscription_created_webhook_skips_when_customer_is_unknown(
) -> Result<(), Box<dyn std::error::Error>> {
    let (context, adapter, plugin) = webhook_context().await?;
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/stripe/webhook")
        .ok_or("webhook endpoint")?;
    let payload = br#"{"id":"evt_unknown_customer","type":"customer.subscription.created","data":{"object":{"id":"stripe_sub_unknown","customer":"cus_unknown","status":"active","metadata":{},"cancel_at_period_end":false,"items":{"data":[{"id":"si_unknown","price":{"id":"price_pro","recurring":{"interval":"month","usage_type":"licensed"}},"quantity":1,"current_period_start":1700000000,"current_period_end":1702592000}]}}}}"#;
    let request = signed_webhook_request("whsec_test", payload)?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let records = adapter
        .find_many(FindMany::new("subscription").where_clause(Where::new(
            "stripe_subscription_id",
            DbValue::String("stripe_sub_unknown".to_owned()),
        )))
        .await?;
    assert!(records.is_empty());
    Ok(())
}
