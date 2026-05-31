#![allow(clippy::unwrap_used)]

use crate::common::webhook::signed_webhook_request;
use http::StatusCode;
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::db::{DbAdapter, MemoryAdapter};
use openauth_core::error::OpenAuthError;
use openauth_core::options::OpenAuthOptions;
use openauth_stripe::options::StripeOptions;
use openauth_stripe::stripe;
use openauth_stripe::stripe_api::{
    StripeClient, StripeRequest, StripeResponse, StripeTransport, StripeTransportFuture,
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
    );
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
    assert_eq!(adapter.len("stripeWebhookEvent").await, 1);
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
    );
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
    assert_eq!(adapter.len("stripeWebhookEvent").await, 0);

    let retry =
        (endpoint.handler)(&context, signed_webhook_request("whsec_test", PAYLOAD)?).await?;
    assert_eq!(retry.status(), StatusCode::OK);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(adapter.len("stripeWebhookEvent").await, 1);
    Ok(())
}
