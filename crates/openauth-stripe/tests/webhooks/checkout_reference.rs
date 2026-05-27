use http::{Method, Request, StatusCode};
use openauth_core::db::{Create, DbAdapter, DbValue, Where};
use openauth_stripe::options::{StripeOptions, StripePlan, SubscriptionOptions};
use openauth_stripe::stripe;
use openauth_stripe::stripe_api::{StripeClient, StripeRequest, StripeResponse, StripeTransport};
use serde_json::json;
use std::sync::{Arc, Mutex};

use crate::common::webhook::sign_webhook_payload;

#[derive(Default)]
struct CheckoutWebhookTransport {
    requests: Mutex<Vec<StripeRequest>>,
}

impl StripeTransport for CheckoutWebhookTransport {
    fn send<'a>(
        &'a self,
        request: StripeRequest,
    ) -> openauth_stripe::stripe_api::StripeTransportFuture<'a> {
        let body = match request.path.as_str() {
            "/v1/subscriptions/stripe_sub_checkout" => json!({
                "id": "stripe_sub_checkout",
                "object": "subscription",
                "status": "active",
                "customer": "cus_123",
                "items": {
                    "data": [{
                        "id": "si_checkout",
                        "price": {
                            "id": "price_pro",
                            "recurring": { "interval": "month" }
                        },
                        "quantity": 1,
                        "current_period_start": 1700000000,
                        "current_period_end": 1702592000
                    }]
                }
            }),
            _ => json!({ "id": "ok" }),
        };
        if let Err(error) = self
            .requests
            .lock()
            .map(|mut requests| requests.push(request))
        {
            let message = error.to_string();
            return Box::pin(async move {
                Err(openauth_stripe::stripe_api::StripeApiError::Transport(
                    message,
                ))
            });
        }
        Box::pin(async move { Ok(StripeResponse { status: 200, body }) })
    }
}

#[tokio::test]
async fn completes_without_subscription_id_metadata_when_client_reference_set(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CheckoutWebhookTransport::default());
    let secret = "whsec_test".to_owned();
    let options = StripeOptions::new(
        StripeClient::with_transport("sk_test", transport),
        secret.clone(),
    )
    .subscription(SubscriptionOptions::enabled(vec![
        StripePlan::new("pro").price_id("price_pro")
    ]));
    let plugin = stripe(options);
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/stripe/webhook")
        .ok_or("webhook endpoint")?;
    let adapter = openauth_core::db::MemoryAdapter::new();
    adapter
        .create(
            Create::new("subscription")
                .data("id", DbValue::String("sub_local".to_owned()))
                .data("plan", DbValue::String("pro".to_owned()))
                .data("reference_id", DbValue::String("user_1".to_owned()))
                .data("status", DbValue::String("incomplete".to_owned()))
                .data("stripe_customer_id", DbValue::Null)
                .data("stripe_subscription_id", DbValue::Null)
                .data("cancel_at_period_end", DbValue::Boolean(false))
                .data("seats", DbValue::Number(1))
                .data("billing_interval", DbValue::String("month".to_owned()))
                .force_allow_id(),
        )
        .await?;
    let adapter_arc: Arc<dyn openauth_core::db::DbAdapter> = Arc::new(adapter.clone());
    let context = openauth_core::context::create_auth_context_with_adapter(
        openauth_core::options::OpenAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            base_url: Some("http://localhost:3000".to_owned()),
            ..openauth_core::options::OpenAuthOptions::default()
        },
        adapter_arc,
    )?;
    let payload = br#"{"id":"evt_checkout_ref","type":"checkout.session.completed","data":{"object":{"id":"cs_ref","mode":"subscription","customer":"cus_123","subscription":"stripe_sub_checkout","client_reference_id":"user_1","metadata":{"userId":"user_1","referenceId":"user_1"}}}}"#;
    let timestamp = time::OffsetDateTime::now_utc().unix_timestamp();
    let signature = sign_webhook_payload(&secret, payload, timestamp)?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/stripe/webhook")
        .header("stripe-signature", signature)
        .body(payload.to_vec())?;

    let response = (endpoint.handler)(&context, request).await?;
    assert_eq!(response.status(), StatusCode::OK);

    let subscription = adapter
        .find_one(
            openauth_core::db::FindOne::new("subscription")
                .where_clause(Where::new("id", DbValue::String("sub_local".to_owned()))),
        )
        .await?
        .ok_or("subscription")?;
    assert_eq!(
        subscription.get("stripe_subscription_id"),
        Some(&DbValue::String("stripe_sub_checkout".to_owned()))
    );
    assert_eq!(
        subscription.get("status"),
        Some(&DbValue::String("active".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn no_op_when_neither_metadata_nor_reference() -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CheckoutWebhookTransport::default());
    let secret = "whsec_test".to_owned();
    let options = StripeOptions::new(
        StripeClient::with_transport("sk_test", transport),
        secret.clone(),
    )
    .subscription(SubscriptionOptions::enabled(vec![
        StripePlan::new("pro").price_id("price_pro")
    ]));
    let plugin = stripe(options);
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/stripe/webhook")
        .ok_or("webhook endpoint")?;
    let adapter = openauth_core::db::MemoryAdapter::new();
    let adapter_arc: Arc<dyn openauth_core::db::DbAdapter> = Arc::new(adapter);
    let context = openauth_core::context::create_auth_context_with_adapter(
        openauth_core::options::OpenAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            base_url: Some("http://localhost:3000".to_owned()),
            ..openauth_core::options::OpenAuthOptions::default()
        },
        adapter_arc,
    )?;
    let payload = br#"{"id":"evt_noop","type":"checkout.session.completed","data":{"object":{"id":"cs_noop","mode":"subscription","customer":"cus_123","subscription":"stripe_sub_checkout","metadata":{}}}}"#;
    let timestamp = time::OffsetDateTime::now_utc().unix_timestamp();
    let signature = sign_webhook_payload(&secret, payload, timestamp)?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/stripe/webhook")
        .header("stripe-signature", signature)
        .body(payload.to_vec())?;

    let response = (endpoint.handler)(&context, request).await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}
