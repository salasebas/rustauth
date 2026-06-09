#![allow(clippy::unwrap_used)]

use super::*;
use openauth_stripe::options::{FreeTrialOptions, StripeOptions, StripePlan, SubscriptionOptions};
use openauth_stripe::stripe;
use openauth_stripe::stripe_api::{
    StripeRequest, StripeResponse, StripeTransport, StripeTransportFuture,
};
use std::sync::{Arc, Mutex};

const FILLER_PAGE_SIZE: usize = 100;

async fn seed_filler_subscriptions(
    adapter: &MemoryAdapter,
    reference_id: &str,
    count: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    for index in 0..count {
        create_subscription_record(
            adapter,
            &format!("sub_filler_{index}"),
            reference_id,
            "canceled",
            Some("cus_123"),
        )
        .await?;
    }
    Ok(())
}

struct PaginatedActiveSubscriptionTransport {
    requests: Mutex<Vec<StripeRequest>>,
    target_subscription_id: &'static str,
}

impl PaginatedActiveSubscriptionTransport {
    fn new(target_subscription_id: &'static str) -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            target_subscription_id,
        }
    }

    fn requests(&self) -> Result<Vec<StripeRequest>, String> {
        self.requests
            .lock()
            .map(|requests| requests.clone())
            .map_err(|error| error.to_string())
    }
}

impl StripeTransport for PaginatedActiveSubscriptionTransport {
    fn send<'a>(&'a self, request: StripeRequest) -> StripeTransportFuture<'a> {
        let body = match request.path.as_str() {
            path if path.starts_with("/v1/checkout/sessions/") => json!({
                "id": "cs_test_123",
                "object": "checkout.session",
                "metadata": {
                    "userId": "user_1",
                    "subscriptionId": "sub_incomplete",
                    "referenceId": "user_1"
                }
            }),
            "/v1/subscriptions" => {
                if request.body.contains("starting_after=") {
                    json!({
                        "object": "list",
                        "has_more": false,
                        "data": [{
                            "id": self.target_subscription_id,
                            "object": "subscription",
                            "status": "active",
                            "cancel_at_period_end": false,
                            "items": {
                                "data": [{
                                    "id": "si_base",
                                    "price": {
                                        "id": "price_pro",
                                        "object": "price",
                                        "recurring": {
                                            "interval": "month",
                                            "usage_type": "licensed"
                                        }
                                    },
                                    "quantity": 1,
                                    "current_period_start": 1_700_000_000,
                                    "current_period_end": 1_702_592_000
                                }]
                            }
                        }]
                    })
                } else {
                    let filler: Vec<Value> = (0..FILLER_PAGE_SIZE)
                        .map(|index| {
                            json!({
                                "id": format!("sub_filler_{index}"),
                                "object": "subscription",
                                "status": "canceled",
                            })
                        })
                        .collect();
                    json!({
                        "object": "list",
                        "has_more": true,
                        "data": filler,
                    })
                }
            }
            "/v1/billing_portal/sessions" => json!({
                "id": "bps_test_123",
                "object": "billing_portal.session",
                "url": "https://billing.stripe.test/session"
            }),
            "/v1/subscriptions/stripe_sub_active" => json!({
                "id": "stripe_sub_active",
                "object": "subscription",
                "status": "active",
                "cancel_at_period_end": false,
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
async fn subscription_list_finds_active_record_beyond_first_local_page(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let plugin = stripe(stripe_options(transport)).unwrap();
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/list")
        .ok_or("list endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    seed_filler_subscriptions(&adapter, "user_1", FILLER_PAGE_SIZE).await?;
    create_subscription_record(
        &adapter,
        "sub_active_page2",
        "user_1",
        "active",
        Some("cus_123"),
    )
    .await?;
    let request = Request::builder()
        .method(Method::GET)
        .uri("http://localhost:3000/api/auth/subscription/list")
        .header("cookie", cookie_header)
        .body(Vec::new())?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    let subscriptions = body.as_array().ok_or("subscription list response")?;
    assert_eq!(subscriptions.len(), 1);
    assert_eq!(subscriptions[0]["id"], "sub_active_page2");
    Ok(())
}

#[tokio::test]
async fn reference_has_ever_trialed_detects_trial_beyond_first_local_page(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let options = StripeOptions::new(
        StripeClient::with_transport(
            "sk_test",
            Arc::clone(&transport) as Arc<dyn StripeTransport>,
        ),
        "whsec_test",
    )
    .subscription(SubscriptionOptions::enabled(vec![StripePlan::new("pro")
        .price_id("price_pro")
        .free_trial(FreeTrialOptions::new(7))]));
    let plugin = stripe(options).unwrap();
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    seed_filler_subscriptions(&adapter, "user_1", FILLER_PAGE_SIZE).await?;
    create_subscription_record(
        &adapter,
        "sub_trialed_page2",
        "user_1",
        "canceled",
        Some("cus_123"),
    )
    .await?;
    openauth_core::db::DbAdapter::update(
        &adapter,
        openauth_core::db::Update::new("subscription")
            .where_clause(openauth_core::db::Where::new(
                "id",
                DbValue::String("sub_trialed_page2".to_owned()),
            ))
            .data("trial_start", DbValue::Timestamp(OffsetDateTime::now_utc())),
    )
    .await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(br#"{"plan":"pro","successUrl":"/ok","cancelUrl":"/pricing"}"#.to_vec())?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let checkout_request = transport
        .requests()?
        .into_iter()
        .find(|request| request.path == "/v1/checkout/sessions")
        .ok_or("checkout request")?;
    assert!(!checkout_request.body.contains("trial_period_days"));
    Ok(())
}

#[tokio::test]
async fn cancel_subscription_finds_active_stripe_row_on_second_page(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(PaginatedActiveSubscriptionTransport::new(
        "stripe_sub_active",
    ));
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
        .find(|endpoint| endpoint.path == "/subscription/cancel")
        .ok_or("cancel endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    create_subscription_record(&adapter, "sub_active", "user_1", "active", Some("cus_123")).await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/cancel")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"returnUrl":"http://localhost:3000/account","disableRedirect":true}"#.to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let list_requests: Vec<_> = transport
        .requests()?
        .into_iter()
        .filter(|request| request.path == "/v1/subscriptions")
        .collect();
    assert_eq!(list_requests.len(), 2);
    assert!(!list_requests[0].body.contains("starting_after="));
    assert!(list_requests[1]
        .body
        .contains("starting_after=sub_filler_99"));
    Ok(())
}

#[tokio::test]
async fn restore_subscription_finds_active_stripe_row_on_second_page(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(PaginatedActiveSubscriptionTransport::new(
        "stripe_sub_active",
    ));
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
        .find(|endpoint| endpoint.path == "/subscription/restore")
        .ok_or("restore endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    create_pending_cancel_subscription_record(&adapter).await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/restore")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(br#"{"subscriptionId":"stripe_sub_active"}"#.to_vec())?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let list_requests: Vec<_> = transport
        .requests()?
        .into_iter()
        .filter(|request| request.path == "/v1/subscriptions")
        .collect();
    assert_eq!(list_requests.len(), 2);
    Ok(())
}

#[tokio::test]
async fn subscription_success_reconciles_active_subscription_from_second_stripe_page(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(PaginatedActiveSubscriptionTransport::new(
        "stripe_sub_active",
    ));
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
        .find(|endpoint| endpoint.path == "/subscription/success")
        .ok_or("success endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    create_subscription_record(
        &adapter,
        "sub_incomplete",
        "user_1",
        "incomplete",
        Some("cus_123"),
    )
    .await?;
    let request = Request::builder()
        .method(Method::GET)
        .uri("http://localhost:3000/api/auth/subscription/success?callbackURL=/done&checkoutSessionId=cs_test_123")
        .header("cookie", cookie_header)
        .body(Vec::new())?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    let records = adapter.records("subscription").await;
    let subscription = records
        .iter()
        .find(|record| record.get("id") == Some(&DbValue::String("sub_incomplete".to_owned())))
        .ok_or("subscription")?;
    assert_eq!(
        subscription.get("stripe_subscription_id"),
        Some(&DbValue::String("stripe_sub_active".to_owned()))
    );
    let list_requests: Vec<_> = transport
        .requests()?
        .into_iter()
        .filter(|request| request.path == "/v1/subscriptions")
        .collect();
    assert_eq!(list_requests.len(), 2);
    Ok(())
}
