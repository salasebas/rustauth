#![allow(clippy::unwrap_used)]

use crate::common::webhook::signed_webhook_request;
use http::StatusCode;
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::db::{Create, DbAdapter, DbValue, FindOne, MemoryAdapter, Where};
use openauth_core::error::OpenAuthError;
use openauth_core::options::OpenAuthOptions;
use openauth_stripe::options::{StripeOptions, StripePlan, SubscriptionOptions};
use openauth_stripe::stripe;
use openauth_stripe::stripe_api::{
    StripeApiError, StripeClient, StripeRequest, StripeResponse, StripeTransport,
    StripeTransportFuture,
};
use serde_json::json;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

struct NoopTransport;

impl StripeTransport for NoopTransport {
    fn send<'a>(&'a self, _request: StripeRequest) -> StripeTransportFuture<'a> {
        Box::pin(async move {
            Ok(StripeResponse {
                status: 200,
                body: json!({ "id": "ok" }),
            })
        })
    }
}

async fn context() -> Result<AuthContextAndAdapter, Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            ..OpenAuthOptions::default()
        },
        Arc::new(adapter.clone()) as Arc<dyn DbAdapter>,
    )?;
    Ok((context, adapter))
}

type AuthContextAndAdapter = (openauth_core::context::AuthContext, MemoryAdapter);

const PAYLOAD: &[u8] =
    br#"{"id":"evt_idem_1","type":"customer.created","data":{"object":{"id":"cus_1"}}}"#;

#[tokio::test]
async fn duplicate_event_runs_side_effects_only_once() -> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_for_hook = Arc::clone(&calls);
    let plugin = stripe(
        StripeOptions::new(
            StripeClient::with_transport("sk_test", Arc::new(NoopTransport)),
            "whsec_test",
        )
        .on_event(move |_event| {
            let calls = Arc::clone(&calls_for_hook);
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        }),
    )
    .unwrap();
    let (context, adapter) = context().await?;
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/stripe/webhook")
        .ok_or("webhook endpoint")?;

    let first =
        (endpoint.handler)(&context, signed_webhook_request("whsec_test", PAYLOAD)?).await?;
    let second =
        (endpoint.handler)(&context, signed_webhook_request("whsec_test", PAYLOAD)?).await?;

    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(second.status(), StatusCode::OK);
    // on_event (and every other side effect) runs once despite two deliveries.
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(adapter.len("stripe_webhook_event").await, 1);
    Ok(())
}

#[tokio::test]
async fn failed_on_event_is_not_marked_processed_and_can_be_retried(
) -> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_for_hook = Arc::clone(&calls);
    let plugin = stripe(
        StripeOptions::new(
            StripeClient::with_transport("sk_test", Arc::new(NoopTransport)),
            "whsec_test",
        )
        .on_event(move |_event| {
            let calls = Arc::clone(&calls_for_hook);
            Box::pin(async move {
                // Fail only the first delivery; the Stripe retry succeeds.
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err(OpenAuthError::Api("on_event failed".to_owned()))
                } else {
                    Ok(())
                }
            })
        }),
    )
    .unwrap();
    let (context, adapter) = context().await?;
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/stripe/webhook")
        .ok_or("webhook endpoint")?;

    let first =
        (endpoint.handler)(&context, signed_webhook_request("whsec_test", PAYLOAD)?).await?;
    assert_eq!(first.status(), StatusCode::BAD_REQUEST);
    // A failed delivery must not leave a processed-event row behind.
    assert_eq!(adapter.len("stripe_webhook_event").await, 0);

    let retry =
        (endpoint.handler)(&context, signed_webhook_request("whsec_test", PAYLOAD)?).await?;
    assert_eq!(retry.status(), StatusCode::OK);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(adapter.len("stripe_webhook_event").await, 1);
    Ok(())
}

/// Fails the first Stripe API call (the `retrieve_subscription` during
/// `checkout.session.completed`) and succeeds afterwards, modelling a transient
/// upstream failure that a Stripe retry recovers from.
#[derive(Default)]
struct FlakyCheckoutTransport {
    calls: AtomicUsize,
}

impl StripeTransport for FlakyCheckoutTransport {
    fn send<'a>(&'a self, _request: StripeRequest) -> StripeTransportFuture<'a> {
        let attempt = self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if attempt == 0 {
                return Err(StripeApiError::Transport(
                    "temporary upstream failure".to_owned(),
                ));
            }
            Ok(StripeResponse {
                status: 200,
                body: json!({
                    "id": "stripe_sub_123",
                    "object": "subscription",
                    "customer": "cus_123",
                    "status": "active",
                    "cancel_at_period_end": false,
                    "items": {
                        "data": [{
                            "id": "si_123",
                            "price": {
                                "id": "price_pro",
                                "recurring": { "interval": "month", "usage_type": "licensed" }
                            },
                            "quantity": 2,
                            "current_period_start": 1_700_000_000,
                            "current_period_end": 1_702_592_000
                        }]
                    }
                }),
            })
        })
    }
}

#[tokio::test]
async fn failed_built_in_handler_is_not_marked_processed_and_can_be_retried(
) -> Result<(), Box<dyn std::error::Error>> {
    let client_transport: Arc<dyn StripeTransport> = Arc::new(FlakyCheckoutTransport::default());
    let plugin = stripe(
        StripeOptions::new(
            StripeClient::with_transport("sk_test", client_transport),
            "whsec_test",
        )
        .subscription(SubscriptionOptions::enabled(vec![
            StripePlan::new("pro").price_id("price_pro")
        ])),
    )
    .unwrap();
    let adapter = MemoryAdapter::new();
    adapter
        .create(
            Create::new("subscription")
                .data("id", DbValue::String("sub_local".to_owned()))
                .data("plan", DbValue::String("pro".to_owned()))
                .data("reference_id", DbValue::String("user_1".to_owned()))
                .data("stripe_customer_id", DbValue::Null)
                .data("stripe_subscription_id", DbValue::Null)
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
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/stripe/webhook")
        .ok_or("webhook endpoint")?;
    let payload = br#"{"id":"evt_checkout_retry","type":"checkout.session.completed","data":{"object":{"id":"cs_123","mode":"subscription","customer":"cus_123","subscription":"stripe_sub_123","client_reference_id":"user_1","metadata":{"userId":"user_1","referenceId":"user_1","subscriptionId":"sub_local"}}}}"#;

    // First delivery fails inside retrieve_subscription.
    let first =
        (endpoint.handler)(&context, signed_webhook_request("whsec_test", payload)?).await?;
    assert_eq!(first.status(), StatusCode::BAD_REQUEST);
    // The failed delivery must not leave a processed-event row behind.
    assert_eq!(adapter.len("stripe_webhook_event").await, 0);

    // Stripe retries the same signed event; the second Stripe call succeeds.
    let retry =
        (endpoint.handler)(&context, signed_webhook_request("whsec_test", payload)?).await?;
    assert_eq!(retry.status(), StatusCode::OK);
    assert_eq!(adapter.len("stripe_webhook_event").await, 1);

    // The retry re-ran the built-in handler and synced local billing state.
    let subscription = adapter
        .find_one(
            FindOne::new("subscription")
                .where_clause(Where::new("id", DbValue::String("sub_local".to_owned()))),
        )
        .await?
        .ok_or("subscription")?;
    assert_eq!(
        subscription.get("stripe_subscription_id"),
        Some(&DbValue::String("stripe_sub_123".to_owned()))
    );
    assert_eq!(
        subscription.get("status"),
        Some(&DbValue::String("active".to_owned()))
    );
    Ok(())
}
