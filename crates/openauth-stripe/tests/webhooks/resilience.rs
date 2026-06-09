#![allow(clippy::unwrap_used)]

use crate::common::webhook::signed_webhook_request;
use http::StatusCode;
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::db::{Create, DbAdapter, DbValue, MemoryAdapter};
use openauth_core::options::OpenAuthOptions;
use openauth_stripe::options::{StripeOptions, StripePlan, SubscriptionOptions};
use openauth_stripe::stripe;
use openauth_stripe::stripe_api::{
    StripeClient, StripeRequest, StripeResponse, StripeTransport, StripeTransportFuture,
};
use serde_json::json;
use std::sync::{Arc, Mutex};

struct FailingRetrieveSubscriptionTransport {
    requests: Mutex<Vec<StripeRequest>>,
}

impl StripeTransport for FailingRetrieveSubscriptionTransport {
    fn send<'a>(&'a self, request: StripeRequest) -> StripeTransportFuture<'a> {
        let _ = self
            .requests
            .lock()
            .map(|mut requests| requests.push(request.clone()));
        let response = if request.path.starts_with("/v1/subscriptions/") {
            StripeResponse {
                status: 404,
                body: json!({ "error": { "message": "No such subscription" } }),
            }
        } else {
            StripeResponse {
                status: 200,
                body: json!({ "id": "ok" }),
            }
        };
        Box::pin(async move { Ok(response) })
    }
}

#[tokio::test]
async fn checkout_completed_webhook_releases_claim_when_subscription_retrieve_fails(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(FailingRetrieveSubscriptionTransport {
        requests: Mutex::new(Vec::new()),
    });
    let plugin = stripe(
        StripeOptions::new(
            StripeClient::with_transport(
                "sk_test",
                Arc::clone(&transport) as Arc<dyn StripeTransport>,
            ),
            "whsec_test",
        )
        .subscription(SubscriptionOptions::enabled(vec![
            StripePlan::new("pro").price_id("price_pro")
        ])),
    )
    .unwrap();
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/stripe/webhook")
        .ok_or("webhook endpoint")?;
    let adapter = MemoryAdapter::new();
    adapter
        .create(
            Create::new("subscription")
                .data("id", DbValue::String("sub_local".to_owned()))
                .data("plan", DbValue::String("pro".to_owned()))
                .data("reference_id", DbValue::String("user_1".to_owned()))
                .data("status", DbValue::String("incomplete".to_owned()))
                .force_allow_id(),
        )
        .await?;
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            ..OpenAuthOptions::default()
        },
        Arc::new(adapter.clone()) as Arc<dyn DbAdapter>,
    )?;
    let payload = br#"{"id":"evt_checkout_fail","type":"checkout.session.completed","data":{"object":{"id":"cs_fail","mode":"subscription","customer":"cus_123","subscription":"stripe_sub_missing","metadata":{"userId":"user_1","referenceId":"user_1","subscriptionId":"sub_local"}}}}"#;
    let request = signed_webhook_request("whsec_test", payload)?;

    let response = (endpoint.handler)(&context, request).await?;

    // OPE-46: the retrieve failure must surface as a retryable webhook error,
    // must not partially update local state, and must release the idempotency
    // claim so a Stripe retry can re-run the handler.
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(adapter.len("stripe_webhook_event").await, 0);
    let subscription = adapter.records("subscription").await;
    assert_eq!(
        subscription[0].get("status"),
        Some(&DbValue::String("incomplete".to_owned()))
    );
    Ok(())
}
