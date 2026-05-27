use http::{Method, Request, StatusCode};

#[path = "common/mod.rs"]
mod common;
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::db::{Create, DbAdapter, DbValue, FindOne, MemoryAdapter, Where};
use openauth_core::options::OpenAuthOptions;
use openauth_stripe::options::{FreeTrialOptions, StripeOptions, StripePlan, SubscriptionOptions};
use openauth_stripe::stripe;
use openauth_stripe::stripe_api::{
    StripeClient, StripeRequest, StripeResponse, StripeTransport, StripeTransportFuture,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use time::OffsetDateTime;

struct RetrieveSubscriptionTransport;

impl StripeTransport for RetrieveSubscriptionTransport {
    fn send<'a>(&'a self, request: StripeRequest) -> StripeTransportFuture<'a> {
        Box::pin(async move {
            if request.path == "/v1/subscriptions/stripe_sub_complete" {
                Ok(StripeResponse {
                    status: 200,
                    body: serde_json::json!({
                        "id": "stripe_sub_complete",
                        "object": "subscription",
                        "customer": "cus_123",
                        "status": "trialing",
                        "cancel_at_period_end": false,
                        "trial_start": 1700000000,
                        "trial_end": 1700604800,
                        "items": {
                            "data": [{
                                "id": "si_complete",
                                "price": {
                                    "id": "price_pro",
                                    "recurring": {
                                        "interval": "month",
                                        "usage_type": "licensed"
                                    }
                                },
                                "quantity": 2,
                                "current_period_start": 1700000000,
                                "current_period_end": 1702592000
                            }]
                        }
                    }),
                })
            } else {
                Ok(StripeResponse {
                    status: 404,
                    body: serde_json::json!({
                        "error": { "message": "not found" }
                    }),
                })
            }
        })
    }
}

#[tokio::test]
async fn checkout_completed_hooks_run_without_failing_webhook(
) -> Result<(), Box<dyn std::error::Error>> {
    let trial_start_calls = Arc::new(AtomicUsize::new(0));
    let complete_calls = Arc::new(AtomicUsize::new(0));
    let trial_start_for_options = Arc::clone(&trial_start_calls);
    let complete_for_options = Arc::clone(&complete_calls);
    let plugin = stripe(
        StripeOptions::new(
            StripeClient::with_transport("sk_test", Arc::new(RetrieveSubscriptionTransport)),
            "whsec_test",
        )
        .subscription(
            SubscriptionOptions::enabled(vec![StripePlan::new("pro")
                .price_id("price_pro")
                .free_trial(
                    FreeTrialOptions::new(14).on_trial_start(move |subscription| {
                        let trial_start_calls = Arc::clone(&trial_start_for_options);
                        Box::pin(async move {
                            assert_eq!(subscription.id, "sub_local");
                            trial_start_calls.fetch_add(1, Ordering::SeqCst);
                            Err(openauth_core::error::OpenAuthError::Api(
                                "trial hook failed".to_owned(),
                            ))
                        })
                    }),
                )])
            .on_subscription_complete(move |input| {
                let complete_calls = Arc::clone(&complete_for_options);
                Box::pin(async move {
                    assert_eq!(input.event.event_type, "checkout.session.completed");
                    assert_eq!(input.subscription.id, "sub_local");
                    assert_eq!(
                        input
                            .stripe_subscription
                            .as_ref()
                            .map(|sub| sub.id.as_str()),
                        Some("stripe_sub_complete")
                    );
                    assert_eq!(
                        input.plan.as_ref().map(|plan| plan.name.as_str()),
                        Some("pro")
                    );
                    complete_calls.fetch_add(1, Ordering::SeqCst);
                    Err(openauth_core::error::OpenAuthError::Api(
                        "complete hook failed".to_owned(),
                    ))
                })
            }),
        ),
    );
    let (context, adapter) = context_with_user_customer(plugin).await?;
    create_local_subscription(&adapter, "sub_local", "stripe_sub_complete", "incomplete").await?;
    let endpoint = stripe_webhook_endpoint(&context)?;
    let payload = br#"{"id":"evt_complete","type":"checkout.session.completed","data":{"object":{"id":"cs_complete","mode":"subscription","customer":"cus_123","subscription":"stripe_sub_complete","client_reference_id":"user_1","metadata":{"userId":"user_1","referenceId":"user_1","subscriptionId":"sub_local"}}}}"#;

    let response = (endpoint.handler)(&context, signed_webhook_request(payload)?).await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(trial_start_calls.load(Ordering::SeqCst), 1);
    assert_eq!(complete_calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn subscription_created_hook_runs_without_failing_webhook(
) -> Result<(), Box<dyn std::error::Error>> {
    let hook_calls = Arc::new(AtomicUsize::new(0));
    let hook_calls_for_options = Arc::clone(&hook_calls);
    let plugin = stripe(
        StripeOptions::new(StripeClient::new("sk_test"), "whsec_test").subscription(
            SubscriptionOptions::enabled(vec![StripePlan::new("pro").price_id("price_pro")])
                .on_subscription_created(move |input| {
                    let hook_calls = Arc::clone(&hook_calls_for_options);
                    Box::pin(async move {
                        assert_eq!(input.event.event_type, "customer.subscription.created");
                        assert_eq!(input.subscription.reference_id, "user_1");
                        assert_eq!(
                            input.subscription.stripe_subscription_id.as_deref(),
                            Some("stripe_sub_created")
                        );
                        assert_eq!(
                            input
                                .stripe_subscription
                                .as_ref()
                                .map(|sub| sub.id.as_str()),
                            Some("stripe_sub_created")
                        );
                        assert_eq!(
                            input.plan.as_ref().map(|plan| plan.name.as_str()),
                            Some("pro")
                        );
                        hook_calls.fetch_add(1, Ordering::SeqCst);
                        Err(openauth_core::error::OpenAuthError::Api(
                            "hook failed".to_owned(),
                        ))
                    })
                }),
        ),
    );
    let (context, adapter) = context_with_user_customer(plugin).await?;
    let endpoint = stripe_webhook_endpoint(&context)?;
    let payload = br#"{"id":"evt_created","type":"customer.subscription.created","data":{"object":{"id":"stripe_sub_created","customer":"cus_123","status":"trialing","metadata":{},"cancel_at_period_end":false,"trial_start":1700000000,"trial_end":1700604800,"items":{"data":[{"id":"si_created","price":{"id":"price_pro","recurring":{"interval":"month","usage_type":"licensed"}},"quantity":3,"current_period_start":1700000000,"current_period_end":1702592000}]}}}}"#;

    let response = (endpoint.handler)(&context, signed_webhook_request(payload)?).await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(hook_calls.load(Ordering::SeqCst), 1);
    assert!(adapter
        .find_one(FindOne::new("subscription").where_clause(Where::new(
            "stripe_subscription_id",
            DbValue::String("stripe_sub_created".to_owned()),
        )))
        .await?
        .is_some());
    Ok(())
}

#[tokio::test]
async fn subscription_deleted_hook_runs_without_failing_webhook(
) -> Result<(), Box<dyn std::error::Error>> {
    let hook_calls = Arc::new(AtomicUsize::new(0));
    let hook_calls_for_options = Arc::clone(&hook_calls);
    let plugin = stripe(
        StripeOptions::new(StripeClient::new("sk_test"), "whsec_test").subscription(
            SubscriptionOptions::enabled(vec![StripePlan::new("pro").price_id("price_pro")])
                .on_subscription_deleted(move |input| {
                    let hook_calls = Arc::clone(&hook_calls_for_options);
                    Box::pin(async move {
                        assert_eq!(input.event.event_type, "customer.subscription.deleted");
                        assert_eq!(input.subscription.id, "sub_local");
                        assert_eq!(
                            input
                                .stripe_subscription
                                .as_ref()
                                .map(|sub| sub.id.as_str()),
                            Some("stripe_sub_deleted")
                        );
                        hook_calls.fetch_add(1, Ordering::SeqCst);
                        Err(openauth_core::error::OpenAuthError::Api(
                            "hook failed".to_owned(),
                        ))
                    })
                }),
        ),
    );
    let (context, adapter) = context_with_user_customer(plugin).await?;
    create_local_subscription(&adapter, "sub_local", "stripe_sub_deleted", "active").await?;
    let endpoint = stripe_webhook_endpoint(&context)?;
    let payload = br#"{"id":"evt_deleted","type":"customer.subscription.deleted","data":{"object":{"id":"stripe_sub_deleted","customer":"cus_123","status":"canceled","metadata":{},"cancel_at_period_end":false,"canceled_at":1700100000,"ended_at":1700200000,"items":{"data":[{"id":"si_deleted","price":{"id":"price_pro","recurring":{"interval":"month","usage_type":"licensed"}},"quantity":1,"current_period_start":1700000000,"current_period_end":1702592000}]}}}}"#;

    let response = (endpoint.handler)(&context, signed_webhook_request(payload)?).await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(hook_calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn subscription_cancel_hook_runs_only_for_new_pending_cancel(
) -> Result<(), Box<dyn std::error::Error>> {
    let hook_calls = Arc::new(AtomicUsize::new(0));
    let hook_calls_for_options = Arc::clone(&hook_calls);
    let plugin = stripe(
        StripeOptions::new(StripeClient::new("sk_test"), "whsec_test").subscription(
            SubscriptionOptions::enabled(vec![StripePlan::new("pro").price_id("price_pro")])
                .on_subscription_cancel(move |input| {
                    let hook_calls = Arc::clone(&hook_calls_for_options);
                    Box::pin(async move {
                        assert_eq!(input.subscription.id, "sub_local");
                        assert_eq!(
                            input
                                .cancellation_details
                                .as_ref()
                                .and_then(|details| details.get("reason"))
                                .and_then(serde_json::Value::as_str),
                            Some("cancellation_requested")
                        );
                        hook_calls.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    })
                }),
        ),
    );
    let (context, adapter) = context_with_user_customer(plugin).await?;
    create_local_subscription(&adapter, "sub_local", "stripe_sub_cancel", "active").await?;
    let endpoint = stripe_webhook_endpoint(&context)?;
    let payload = br#"{"id":"evt_cancel","type":"customer.subscription.updated","data":{"object":{"id":"stripe_sub_cancel","customer":"cus_123","status":"active","metadata":{},"cancel_at_period_end":true,"cancellation_details":{"reason":"cancellation_requested"},"items":{"data":[{"id":"si_cancel","price":{"id":"price_pro","recurring":{"interval":"month","usage_type":"licensed"}},"quantity":1,"current_period_start":1700000000,"current_period_end":1702592000}]}}}}"#;

    let response = (endpoint.handler)(&context, signed_webhook_request(payload)?).await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(hook_calls.load(Ordering::SeqCst), 1);
    let second_response = (endpoint.handler)(&context, signed_webhook_request(payload)?).await?;
    assert_eq!(second_response.status(), StatusCode::OK);
    assert_eq!(hook_calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn trial_transition_hooks_run_for_trial_end_and_expiration(
) -> Result<(), Box<dyn std::error::Error>> {
    let trial_end_calls = Arc::new(AtomicUsize::new(0));
    let trial_expired_calls = Arc::new(AtomicUsize::new(0));
    let trial_end_for_options = Arc::clone(&trial_end_calls);
    let trial_expired_for_options = Arc::clone(&trial_expired_calls);
    let plugin = stripe(
        StripeOptions::new(StripeClient::new("sk_test"), "whsec_test").subscription(
            SubscriptionOptions::enabled(vec![StripePlan::new("pro")
                .price_id("price_pro")
                .free_trial(
                    FreeTrialOptions::new(14)
                        .on_trial_end(move |subscription, _| {
                            let trial_end_calls = Arc::clone(&trial_end_for_options);
                            Box::pin(async move {
                                assert_eq!(subscription.id, "sub_local");
                                trial_end_calls.fetch_add(1, Ordering::SeqCst);
                                Ok(())
                            })
                        })
                        .on_trial_expired(move |subscription, _| {
                            let trial_expired_calls = Arc::clone(&trial_expired_for_options);
                            Box::pin(async move {
                                assert_eq!(subscription.id, "sub_local");
                                trial_expired_calls.fetch_add(1, Ordering::SeqCst);
                                Ok(())
                            })
                        }),
                )]),
        ),
    );
    let (context, adapter) = context_with_user_customer(plugin).await?;
    create_local_subscription(&adapter, "sub_local", "stripe_sub_trial", "trialing").await?;
    let endpoint = stripe_webhook_endpoint(&context)?;
    let ended = br#"{"id":"evt_trial_end","type":"customer.subscription.updated","data":{"object":{"id":"stripe_sub_trial","customer":"cus_123","status":"active","metadata":{},"cancel_at_period_end":false,"items":{"data":[{"id":"si_trial","price":{"id":"price_pro","recurring":{"interval":"month","usage_type":"licensed"}},"quantity":1,"current_period_start":1700000000,"current_period_end":1702592000}]}}}}"#;

    let response = (endpoint.handler)(&context, signed_webhook_request(ended)?).await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(trial_end_calls.load(Ordering::SeqCst), 1);
    openauth_core::db::DbAdapter::update(
        &adapter,
        openauth_core::db::Update::new("subscription")
            .where_clause(Where::new("id", DbValue::String("sub_local".to_owned())))
            .data("status", DbValue::String("trialing".to_owned())),
    )
    .await?;
    let expired = br#"{"id":"evt_trial_expired","type":"customer.subscription.updated","data":{"object":{"id":"stripe_sub_trial","customer":"cus_123","status":"incomplete_expired","metadata":{},"cancel_at_period_end":false,"items":{"data":[{"id":"si_trial","price":{"id":"price_pro","recurring":{"interval":"month","usage_type":"licensed"}},"quantity":1,"current_period_start":1700000000,"current_period_end":1702592000}]}}}}"#;
    let response = (endpoint.handler)(&context, signed_webhook_request(expired)?).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(trial_expired_calls.load(Ordering::SeqCst), 1);
    Ok(())
}

async fn context_with_user_customer(
    plugin: openauth_core::plugin::AuthPlugin,
) -> Result<(openauth_core::context::AuthContext, MemoryAdapter), Box<dyn std::error::Error>> {
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
            plugins: vec![plugin],
            ..OpenAuthOptions::default()
        },
        adapter_arc,
    )?;
    Ok((context, adapter))
}

fn stripe_webhook_endpoint(
    context: &openauth_core::context::AuthContext,
) -> Result<&openauth_core::api::AsyncAuthEndpoint, Box<dyn std::error::Error>> {
    context
        .plugins
        .iter()
        .find(|plugin| plugin.id == "stripe")
        .and_then(|plugin| {
            plugin
                .endpoints
                .iter()
                .find(|endpoint| endpoint.path == "/stripe/webhook")
        })
        .ok_or_else(|| "stripe webhook endpoint missing".into())
}

async fn create_local_subscription(
    adapter: &MemoryAdapter,
    id: &str,
    stripe_subscription_id: &str,
    status: &str,
) -> Result<(), openauth_core::error::OpenAuthError> {
    adapter
        .create(
            Create::new("subscription")
                .data("id", DbValue::String(id.to_owned()))
                .data("plan", DbValue::String("pro".to_owned()))
                .data("reference_id", DbValue::String("user_1".to_owned()))
                .data("stripe_customer_id", DbValue::String("cus_123".to_owned()))
                .data(
                    "stripe_subscription_id",
                    DbValue::String(stripe_subscription_id.to_owned()),
                )
                .data("status", DbValue::String(status.to_owned()))
                .data("cancel_at_period_end", DbValue::Boolean(false))
                .data("cancel_at", DbValue::Null)
                .force_allow_id(),
        )
        .await?;
    Ok(())
}

fn signed_webhook_request(payload: &[u8]) -> Result<Request<Vec<u8>>, Box<dyn std::error::Error>> {
    let timestamp = time::OffsetDateTime::now_utc().unix_timestamp();
    let signature = common::webhook::sign_webhook_payload("whsec_test", payload, timestamp)?;
    Ok(Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/stripe/webhook")
        .header("stripe-signature", signature)
        .body(payload.to_vec())?)
}
