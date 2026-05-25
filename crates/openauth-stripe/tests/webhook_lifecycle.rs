use hmac::{Hmac, Mac};
use http::{Method, Request, StatusCode};
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::db::{Create, DbAdapter, DbValue, FindOne, MemoryAdapter, Where};
use openauth_core::error::OpenAuthError;
use openauth_core::options::OpenAuthOptions;
use openauth_stripe::options::{
    OrganizationStripeOptions, StripeOptions, StripePlan, SubscriptionOptions,
};
use openauth_stripe::stripe;
use openauth_stripe::stripe_api::{
    StripeClient, StripeRequest, StripeResponse, StripeTransport, StripeTransportFuture,
};
use serde_json::json;
use sha2::Sha256;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use time::OffsetDateTime;

#[derive(Default)]
struct WebhookTransport {
    requests: Mutex<Vec<StripeRequest>>,
}

impl StripeTransport for WebhookTransport {
    fn send<'a>(&'a self, request: StripeRequest) -> StripeTransportFuture<'a> {
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
        Box::pin(async {
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
async fn checkout_completed_webhook_updates_local_subscription(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(WebhookTransport::default());
    let client_transport: Arc<dyn StripeTransport> = transport;
    let plugin = stripe(
        StripeOptions::new(
            StripeClient::with_transport("sk_test", client_transport),
            "whsec_test",
        )
        .subscription(SubscriptionOptions::enabled(vec![
            StripePlan::new("pro").price_id("price_pro")
        ])),
    );
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
                .data("stripe_customer_id", DbValue::Null)
                .data("stripe_subscription_id", DbValue::Null)
                .data("status", DbValue::String("incomplete".to_owned()))
                .force_allow_id(),
        )
        .await?;
    let adapter_arc: Arc<dyn DbAdapter> = Arc::new(adapter.clone());
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            ..OpenAuthOptions::default()
        },
        adapter_arc,
    )?;
    let payload = br#"{"id":"evt_123","type":"checkout.session.completed","data":{"object":{"id":"cs_123","mode":"subscription","customer":"cus_123","subscription":"stripe_sub_123","client_reference_id":"user_1","metadata":{"userId":"user_1","referenceId":"user_1","subscriptionId":"sub_local"}}}}"#;
    let timestamp = time::OffsetDateTime::now_utc().unix_timestamp();
    let mut mac = Hmac::<Sha256>::new_from_slice(b"whsec_test")?;
    mac.update(format!("{timestamp}.").as_bytes());
    mac.update(payload);
    let signature = hex::encode(mac.finalize().into_bytes());
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/stripe/webhook")
        .header("stripe-signature", format!("t={timestamp},v1={signature}"))
        .body(payload.to_vec())?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let subscription = adapter
        .find_one(
            FindOne::new("subscription")
                .where_clause(Where::new("id", DbValue::String("sub_local".to_owned()))),
        )
        .await?
        .ok_or("subscription")?;
    assert_eq!(
        subscription.get("stripe_customer_id"),
        Some(&DbValue::String("cus_123".to_owned()))
    );
    assert_eq!(
        subscription.get("stripe_subscription_id"),
        Some(&DbValue::String("stripe_sub_123".to_owned()))
    );
    assert_eq!(
        subscription.get("status"),
        Some(&DbValue::String("active".to_owned()))
    );
    assert_eq!(subscription.get("seats"), Some(&DbValue::Number(2)));
    assert_eq!(
        subscription.get("billing_interval"),
        Some(&DbValue::String("month".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn subscription_created_webhook_creates_local_subscription_for_customer(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin = stripe(
        StripeOptions::new(StripeClient::new("sk_test"), "whsec_test").subscription(
            SubscriptionOptions::enabled(vec![StripePlan::new("pro").price_id("price_pro")]),
        ),
    );
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/stripe/webhook")
        .ok_or("webhook endpoint")?;
    let adapter = MemoryAdapter::new();
    let now = OffsetDateTime::now_utc();
    adapter
        .create(
            Create::new("user")
                .data("id", DbValue::String("user_1".to_owned()))
                .data("name", DbValue::String("Ada Lovelace".to_owned()))
                .data("email", DbValue::String("ada@example.com".to_owned()))
                .data("email_verified", DbValue::Boolean(true))
                .data("image", DbValue::Null)
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Timestamp(now))
                .data("stripe_customer_id", DbValue::String("cus_123".to_owned()))
                .force_allow_id(),
        )
        .await?;
    let adapter_arc: Arc<dyn DbAdapter> = Arc::new(adapter.clone());
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            ..OpenAuthOptions::default()
        },
        adapter_arc,
    )?;
    let payload = br#"{"id":"evt_456","type":"customer.subscription.created","data":{"object":{"id":"stripe_sub_dashboard","customer":"cus_123","status":"trialing","metadata":{},"cancel_at_period_end":false,"trial_start":1700000000,"trial_end":1700604800,"items":{"data":[{"id":"si_456","price":{"id":"price_pro","recurring":{"interval":"month","usage_type":"licensed"}},"quantity":3,"current_period_start":1700000000,"current_period_end":1702592000}]}}}}"#;
    let request = signed_webhook_request(payload)?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let subscription = adapter
        .find_one(FindOne::new("subscription").where_clause(Where::new(
            "stripe_subscription_id",
            DbValue::String("stripe_sub_dashboard".to_owned()),
        )))
        .await?
        .ok_or("created subscription")?;
    assert_eq!(
        subscription.get("reference_id"),
        Some(&DbValue::String("user_1".to_owned()))
    );
    assert_eq!(
        subscription.get("stripe_customer_id"),
        Some(&DbValue::String("cus_123".to_owned()))
    );
    assert_eq!(
        subscription.get("status"),
        Some(&DbValue::String("trialing".to_owned()))
    );
    assert_eq!(
        subscription.get("plan"),
        Some(&DbValue::String("pro".to_owned()))
    );
    assert_eq!(subscription.get("seats"), Some(&DbValue::Number(3)));
    Ok(())
}

#[tokio::test]
async fn subscription_webhook_wraps_dynamic_plan_provider_failure(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin = stripe(
        StripeOptions::new(StripeClient::new("sk_test"), "whsec_test").subscription(
            SubscriptionOptions::enabled_dynamic(|| {
                Box::pin(async {
                    Err::<Vec<StripePlan>, _>(OpenAuthError::Api("plans failed".to_owned()))
                })
            }),
        ),
    );
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/stripe/webhook")
        .ok_or("webhook endpoint")?;
    let adapter = MemoryAdapter::new();
    let adapter_arc: Arc<dyn DbAdapter> = Arc::new(adapter);
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            ..OpenAuthOptions::default()
        },
        adapter_arc,
    )?;
    let payload = br#"{"id":"evt_dynamic_fail","type":"customer.subscription.updated","data":{"object":{"id":"stripe_sub_123","customer":"cus_123","status":"active","metadata":{},"cancel_at_period_end":false,"items":{"data":[{"id":"si_123","price":{"id":"price_pro","recurring":{"interval":"month","usage_type":"licensed"}},"quantity":1}]}}}}"#;
    let request = signed_webhook_request(payload)?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "STRIPE_WEBHOOK_ERROR");
    Ok(())
}

#[tokio::test]
async fn subscription_created_webhook_resolves_dynamic_plans(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin = stripe(
        StripeOptions::new(StripeClient::new("sk_test"), "whsec_test").subscription(
            SubscriptionOptions::enabled_dynamic(|| {
                Box::pin(async { Ok(vec![StripePlan::new("dynamic-pro").price_id("price_pro")]) })
            }),
        ),
    );
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/stripe/webhook")
        .ok_or("webhook endpoint")?;
    let adapter = MemoryAdapter::new();
    let now = OffsetDateTime::now_utc();
    adapter
        .create(
            Create::new("user")
                .data("id", DbValue::String("user_1".to_owned()))
                .data("name", DbValue::String("Ada Lovelace".to_owned()))
                .data("email", DbValue::String("ada@example.com".to_owned()))
                .data("email_verified", DbValue::Boolean(true))
                .data("image", DbValue::Null)
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Timestamp(now))
                .data("stripe_customer_id", DbValue::String("cus_123".to_owned()))
                .force_allow_id(),
        )
        .await?;
    let adapter_arc: Arc<dyn DbAdapter> = Arc::new(adapter.clone());
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            ..OpenAuthOptions::default()
        },
        adapter_arc,
    )?;
    let payload = br#"{"id":"evt_dynamic_created","type":"customer.subscription.created","data":{"object":{"id":"stripe_sub_dynamic","customer":"cus_123","status":"active","metadata":{},"cancel_at_period_end":false,"items":{"data":[{"id":"si_dynamic","price":{"id":"price_pro","recurring":{"interval":"month","usage_type":"licensed"}},"quantity":2}]}}}}"#;
    let request = signed_webhook_request(payload)?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let subscription = adapter
        .find_one(FindOne::new("subscription").where_clause(Where::new(
            "stripe_subscription_id",
            DbValue::String("stripe_sub_dynamic".to_owned()),
        )))
        .await?
        .ok_or("created subscription")?;
    assert_eq!(
        subscription.get("plan"),
        Some(&DbValue::String("dynamic-pro".to_owned()))
    );
    assert_eq!(subscription.get("seats"), Some(&DbValue::Number(2)));
    Ok(())
}

#[tokio::test]
async fn subscription_created_webhook_prefers_organization_customer_when_enabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin = stripe(
        StripeOptions::new(StripeClient::new("sk_test"), "whsec_test")
            .organization(OrganizationStripeOptions::enabled())
            .subscription(SubscriptionOptions::enabled(vec![
                StripePlan::new("pro").price_id("price_pro")
            ])),
    );
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/stripe/webhook")
        .ok_or("webhook endpoint")?;
    let adapter = MemoryAdapter::new();
    let now = OffsetDateTime::now_utc();
    adapter
        .create(
            Create::new("organization")
                .data("id", DbValue::String("org_1".to_owned()))
                .data("name", DbValue::String("Acme".to_owned()))
                .data("slug", DbValue::String("acme".to_owned()))
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Timestamp(now))
                .data("stripe_customer_id", DbValue::String("cus_org".to_owned()))
                .force_allow_id(),
        )
        .await?;
    adapter
        .create(
            Create::new("user")
                .data("id", DbValue::String("user_1".to_owned()))
                .data("name", DbValue::String("Ada Lovelace".to_owned()))
                .data("email", DbValue::String("ada@example.com".to_owned()))
                .data("email_verified", DbValue::Boolean(true))
                .data("image", DbValue::Null)
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Timestamp(now))
                .data("stripe_customer_id", DbValue::String("cus_org".to_owned()))
                .force_allow_id(),
        )
        .await?;
    let adapter_arc: Arc<dyn DbAdapter> = Arc::new(adapter.clone());
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            ..OpenAuthOptions::default()
        },
        adapter_arc,
    )?;
    let payload = br#"{"id":"evt_org_created","type":"customer.subscription.created","data":{"object":{"id":"stripe_sub_org","customer":"cus_org","status":"active","metadata":{},"cancel_at_period_end":false,"items":{"data":[{"id":"si_org","price":{"id":"price_pro","recurring":{"interval":"month","usage_type":"licensed"}},"quantity":5,"current_period_start":1700000000,"current_period_end":1702592000}]}}}}"#;
    let request = signed_webhook_request(payload)?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let subscription = adapter
        .find_one(FindOne::new("subscription").where_clause(Where::new(
            "stripe_subscription_id",
            DbValue::String("stripe_sub_org".to_owned()),
        )))
        .await?
        .ok_or("created subscription")?;
    assert_eq!(
        subscription.get("reference_id"),
        Some(&DbValue::String("org_1".to_owned()))
    );
    assert_eq!(subscription.get("seats"), Some(&DbValue::Number(5)));
    Ok(())
}

#[tokio::test]
async fn subscription_updated_webhook_updates_existing_local_subscription(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin = stripe(
        StripeOptions::new(StripeClient::new("sk_test"), "whsec_test").subscription(
            SubscriptionOptions::enabled(vec![StripePlan::new("pro").price_id("price_pro")]),
        ),
    );
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
                .data("plan", DbValue::String("starter".to_owned()))
                .data("reference_id", DbValue::String("user_1".to_owned()))
                .data("stripe_customer_id", DbValue::String("cus_123".to_owned()))
                .data(
                    "stripe_subscription_id",
                    DbValue::String("stripe_sub_123".to_owned()),
                )
                .data("status", DbValue::String("active".to_owned()))
                .data("cancel_at_period_end", DbValue::Boolean(false))
                .force_allow_id(),
        )
        .await?;
    let adapter_arc: Arc<dyn DbAdapter> = Arc::new(adapter.clone());
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            ..OpenAuthOptions::default()
        },
        adapter_arc,
    )?;
    let payload = br#"{"id":"evt_789","type":"customer.subscription.updated","data":{"object":{"id":"stripe_sub_123","customer":"cus_123","status":"past_due","metadata":{},"cancel_at_period_end":true,"cancel_at":1702592000,"canceled_at":1700100000,"items":{"data":[{"id":"si_789","price":{"id":"price_pro","recurring":{"interval":"year","usage_type":"licensed"}},"quantity":4,"current_period_start":1700000000,"current_period_end":1731622400}]}}}}"#;
    let request = signed_webhook_request(payload)?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let subscription = adapter
        .find_one(
            FindOne::new("subscription")
                .where_clause(Where::new("id", DbValue::String("sub_local".to_owned()))),
        )
        .await?
        .ok_or("updated subscription")?;
    assert_eq!(
        subscription.get("status"),
        Some(&DbValue::String("past_due".to_owned()))
    );
    assert_eq!(
        subscription.get("plan"),
        Some(&DbValue::String("pro".to_owned()))
    );
    assert_eq!(
        subscription.get("cancel_at_period_end"),
        Some(&DbValue::Boolean(true))
    );
    assert_eq!(subscription.get("seats"), Some(&DbValue::Number(4)));
    assert_eq!(
        subscription.get("billing_interval"),
        Some(&DbValue::String("year".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn subscription_updated_webhook_falls_back_to_active_customer_subscription(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin = stripe(
        StripeOptions::new(StripeClient::new("sk_test"), "whsec_test").subscription(
            SubscriptionOptions::enabled(vec![StripePlan::new("pro").price_id("price_pro")]),
        ),
    );
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/stripe/webhook")
        .ok_or("webhook endpoint")?;
    let adapter = MemoryAdapter::new();
    adapter
        .create(
            Create::new("subscription")
                .data("id", DbValue::String("sub_canceled".to_owned()))
                .data("plan", DbValue::String("starter".to_owned()))
                .data("reference_id", DbValue::String("user_1".to_owned()))
                .data("stripe_customer_id", DbValue::String("cus_123".to_owned()))
                .data(
                    "stripe_subscription_id",
                    DbValue::String("stripe_sub_old".to_owned()),
                )
                .data("status", DbValue::String("canceled".to_owned()))
                .force_allow_id(),
        )
        .await?;
    adapter
        .create(
            Create::new("subscription")
                .data("id", DbValue::String("sub_active".to_owned()))
                .data("plan", DbValue::String("starter".to_owned()))
                .data("reference_id", DbValue::String("user_1".to_owned()))
                .data("stripe_customer_id", DbValue::String("cus_123".to_owned()))
                .data("stripe_subscription_id", DbValue::Null)
                .data("status", DbValue::String("active".to_owned()))
                .force_allow_id(),
        )
        .await?;
    let adapter_arc: Arc<dyn DbAdapter> = Arc::new(adapter.clone());
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            ..OpenAuthOptions::default()
        },
        adapter_arc,
    )?;
    let payload = br#"{"id":"evt_fallback","type":"customer.subscription.updated","data":{"object":{"id":"stripe_sub_dashboard","customer":"cus_123","status":"active","metadata":{},"cancel_at_period_end":false,"items":{"data":[{"id":"si_dashboard","price":{"id":"price_pro","recurring":{"interval":"month","usage_type":"licensed"}},"quantity":3,"current_period_start":1700000000,"current_period_end":1702592000}]}}}}"#;
    let request = signed_webhook_request(payload)?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let subscription = adapter
        .find_one(
            FindOne::new("subscription")
                .where_clause(Where::new("id", DbValue::String("sub_active".to_owned()))),
        )
        .await?
        .ok_or("updated subscription")?;
    assert_eq!(
        subscription.get("stripe_subscription_id"),
        Some(&DbValue::String("stripe_sub_dashboard".to_owned()))
    );
    assert_eq!(subscription.get("seats"), Some(&DbValue::Number(3)));
    assert_eq!(
        subscription.get("plan"),
        Some(&DbValue::String("pro".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn subscription_updated_webhook_resolves_dynamic_plans(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin = stripe(
        StripeOptions::new(StripeClient::new("sk_test"), "whsec_test").subscription(
            SubscriptionOptions::enabled_dynamic(|| {
                Box::pin(async { Ok(vec![StripePlan::new("dynamic-pro").price_id("price_pro")]) })
            }),
        ),
    );
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
                .data("plan", DbValue::String("starter".to_owned()))
                .data("reference_id", DbValue::String("user_1".to_owned()))
                .data("stripe_customer_id", DbValue::String("cus_123".to_owned()))
                .data(
                    "stripe_subscription_id",
                    DbValue::String("stripe_sub_dynamic_update".to_owned()),
                )
                .data("status", DbValue::String("active".to_owned()))
                .force_allow_id(),
        )
        .await?;
    let adapter_arc: Arc<dyn DbAdapter> = Arc::new(adapter.clone());
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            ..OpenAuthOptions::default()
        },
        adapter_arc,
    )?;
    let payload = br#"{"id":"evt_dynamic_update","type":"customer.subscription.updated","data":{"object":{"id":"stripe_sub_dynamic_update","customer":"cus_123","status":"active","metadata":{},"cancel_at_period_end":false,"items":{"data":[{"id":"si_dynamic","price":{"id":"price_pro","recurring":{"interval":"month","usage_type":"licensed"}},"quantity":2,"current_period_start":1700000000,"current_period_end":1702592000}]}}}}"#;
    let request = signed_webhook_request(payload)?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let subscription = adapter
        .find_one(
            FindOne::new("subscription")
                .where_clause(Where::new("id", DbValue::String("sub_local".to_owned()))),
        )
        .await?
        .ok_or("updated subscription")?;
    assert_eq!(
        subscription.get("plan"),
        Some(&DbValue::String("dynamic-pro".to_owned()))
    );
    assert_eq!(subscription.get("seats"), Some(&DbValue::Number(2)));
    Ok(())
}

#[tokio::test]
async fn subscription_update_hook_runs_without_failing_webhook(
) -> Result<(), Box<dyn std::error::Error>> {
    let hook_calls = Arc::new(AtomicUsize::new(0));
    let hook_calls_for_options = Arc::clone(&hook_calls);
    let plugin = stripe(
        StripeOptions::new(StripeClient::new("sk_test"), "whsec_test").subscription(
            SubscriptionOptions::enabled(vec![StripePlan::new("pro").price_id("price_pro")])
                .on_subscription_update(move |input| {
                    let hook_calls = Arc::clone(&hook_calls_for_options);
                    Box::pin(async move {
                        assert_eq!(input.event.event_type, "customer.subscription.updated");
                        assert_eq!(input.subscription.id, "sub_local");
                        hook_calls.fetch_add(1, Ordering::SeqCst);
                        Err(openauth_core::error::OpenAuthError::Api(
                            "hook failed".to_owned(),
                        ))
                    })
                }),
        ),
    );
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
                .data("plan", DbValue::String("starter".to_owned()))
                .data("reference_id", DbValue::String("user_1".to_owned()))
                .data("stripe_customer_id", DbValue::String("cus_123".to_owned()))
                .data(
                    "stripe_subscription_id",
                    DbValue::String("stripe_sub_123".to_owned()),
                )
                .data("status", DbValue::String("active".to_owned()))
                .force_allow_id(),
        )
        .await?;
    let adapter_arc: Arc<dyn DbAdapter> = Arc::new(adapter.clone());
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            ..OpenAuthOptions::default()
        },
        adapter_arc,
    )?;
    let payload = br#"{"id":"evt_hook","type":"customer.subscription.updated","data":{"object":{"id":"stripe_sub_123","customer":"cus_123","status":"active","metadata":{},"cancel_at_period_end":false,"items":{"data":[{"id":"si_hook","price":{"id":"price_pro","recurring":{"interval":"month","usage_type":"licensed"}},"quantity":2,"current_period_start":1700000000,"current_period_end":1702592000}]}}}}"#;

    let response = (endpoint.handler)(&context, signed_webhook_request(payload)?).await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(hook_calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn subscription_updated_webhook_sets_and_clears_schedule_id(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin = stripe(
        StripeOptions::new(StripeClient::new("sk_test"), "whsec_test").subscription(
            SubscriptionOptions::enabled(vec![StripePlan::new("pro").price_id("price_pro")]),
        ),
    );
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
                .data("stripe_customer_id", DbValue::String("cus_123".to_owned()))
                .data(
                    "stripe_subscription_id",
                    DbValue::String("stripe_sub_123".to_owned()),
                )
                .data("status", DbValue::String("active".to_owned()))
                .data("stripe_schedule_id", DbValue::Null)
                .force_allow_id(),
        )
        .await?;
    let adapter_arc: Arc<dyn DbAdapter> = Arc::new(adapter.clone());
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            ..OpenAuthOptions::default()
        },
        adapter_arc,
    )?;
    let with_schedule = br#"{"id":"evt_sched_1","type":"customer.subscription.updated","data":{"object":{"id":"stripe_sub_123","customer":"cus_123","status":"active","metadata":{},"cancel_at_period_end":false,"schedule":"sched_123","items":{"data":[{"id":"si_sched","price":{"id":"price_pro","recurring":{"interval":"month","usage_type":"licensed"}},"quantity":1,"current_period_start":1700000000,"current_period_end":1702592000}]}}}}"#;
    let response = (endpoint.handler)(&context, signed_webhook_request(with_schedule)?).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let scheduled = adapter
        .find_one(
            FindOne::new("subscription")
                .where_clause(Where::new("id", DbValue::String("sub_local".to_owned()))),
        )
        .await?
        .ok_or("scheduled subscription")?;
    assert_eq!(
        scheduled.get("stripe_schedule_id"),
        Some(&DbValue::String("sched_123".to_owned()))
    );

    let without_schedule = br#"{"id":"evt_sched_2","type":"customer.subscription.updated","data":{"object":{"id":"stripe_sub_123","customer":"cus_123","status":"active","metadata":{},"cancel_at_period_end":false,"schedule":null,"items":{"data":[{"id":"si_sched","price":{"id":"price_pro","recurring":{"interval":"month","usage_type":"licensed"}},"quantity":1,"current_period_start":1700000000,"current_period_end":1702592000}]}}}}"#;
    let response = (endpoint.handler)(&context, signed_webhook_request(without_schedule)?).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let cleared = adapter
        .find_one(
            FindOne::new("subscription")
                .where_clause(Where::new("id", DbValue::String("sub_local".to_owned()))),
        )
        .await?
        .ok_or("cleared subscription")?;
    assert_eq!(cleared.get("stripe_schedule_id"), Some(&DbValue::Null));
    Ok(())
}

#[tokio::test]
async fn subscription_deleted_webhook_marks_local_subscription_canceled(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin = stripe(
        StripeOptions::new(StripeClient::new("sk_test"), "whsec_test").subscription(
            SubscriptionOptions::enabled(vec![StripePlan::new("pro").price_id("price_pro")]),
        ),
    );
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
                .data("stripe_customer_id", DbValue::String("cus_123".to_owned()))
                .data(
                    "stripe_subscription_id",
                    DbValue::String("stripe_sub_123".to_owned()),
                )
                .data("status", DbValue::String("active".to_owned()))
                .data(
                    "stripe_schedule_id",
                    DbValue::String("sched_123".to_owned()),
                )
                .force_allow_id(),
        )
        .await?;
    let adapter_arc: Arc<dyn DbAdapter> = Arc::new(adapter.clone());
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            ..OpenAuthOptions::default()
        },
        adapter_arc,
    )?;
    let payload = br#"{"id":"evt_999","type":"customer.subscription.deleted","data":{"object":{"id":"stripe_sub_123","customer":"cus_123","status":"canceled","metadata":{},"cancel_at_period_end":false,"canceled_at":1700100000,"ended_at":1700200000,"items":{"data":[{"id":"si_999","price":{"id":"price_pro","recurring":{"interval":"month","usage_type":"licensed"}},"quantity":1,"current_period_start":1700000000,"current_period_end":1702592000}]}}}}"#;
    let request = signed_webhook_request(payload)?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let subscription = adapter
        .find_one(
            FindOne::new("subscription")
                .where_clause(Where::new("id", DbValue::String("sub_local".to_owned()))),
        )
        .await?
        .ok_or("deleted subscription")?;
    assert_eq!(
        subscription.get("status"),
        Some(&DbValue::String("canceled".to_owned()))
    );
    assert_eq!(
        subscription.get("cancel_at_period_end"),
        Some(&DbValue::Boolean(false))
    );
    assert_eq!(subscription.get("stripe_schedule_id"), Some(&DbValue::Null));
    assert!(matches!(
        subscription.get("canceled_at"),
        Some(DbValue::Timestamp(_))
    ));
    assert!(matches!(
        subscription.get("ended_at"),
        Some(DbValue::Timestamp(_))
    ));
    Ok(())
}

fn signed_webhook_request(payload: &[u8]) -> Result<Request<Vec<u8>>, Box<dyn std::error::Error>> {
    let timestamp = time::OffsetDateTime::now_utc().unix_timestamp();
    let mut mac = Hmac::<Sha256>::new_from_slice(b"whsec_test")?;
    mac.update(format!("{timestamp}.").as_bytes());
    mac.update(payload);
    let signature = hex::encode(mac.finalize().into_bytes());
    Ok(Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/stripe/webhook")
        .header("stripe-signature", format!("t={timestamp},v1={signature}"))
        .body(payload.to_vec())?)
}
