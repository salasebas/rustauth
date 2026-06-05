use http::{Method, Request, StatusCode};
use openauth_core::context::{create_auth_context, create_auth_context_with_adapter, AuthContext};
use openauth_core::cookies::{set_session_cookie, CookieOptions, SessionCookieOptions};
use openauth_core::db::{Create, DbAdapter, DbRecord, DbValue, MemoryAdapter};
use openauth_core::error::OpenAuthError;
use openauth_core::options::OpenAuthOptions;
use openauth_core::session::{CreateSessionInput, DbSessionStore};
use openauth_core::user::{CreateUserInput, DbUserStore};
use openauth_stripe::options::{StripeOptions, StripePlan, SubscriptionOptions};
use openauth_stripe::stripe;
use openauth_stripe::stripe_api::{
    StripeClient, StripeRequest, StripeResponse, StripeTransport, StripeTransportFuture,
};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use time::{Duration, OffsetDateTime};

#[derive(Default)]
struct CaptureTransport {
    requests: Mutex<Vec<StripeRequest>>,
}

impl CaptureTransport {
    fn requests(&self) -> Result<Vec<StripeRequest>, String> {
        self.requests
            .lock()
            .map(|requests| requests.clone())
            .map_err(|error| error.to_string())
    }
}

#[derive(Default)]
struct FailingCheckoutSessionTransport {
    requests: Mutex<Vec<StripeRequest>>,
}

impl FailingCheckoutSessionTransport {
    fn requests(&self) -> Result<Vec<StripeRequest>, String> {
        self.requests
            .lock()
            .map(|requests| requests.clone())
            .map_err(|error| error.to_string())
    }
}

impl StripeTransport for FailingCheckoutSessionTransport {
    fn send<'a>(&'a self, request: StripeRequest) -> StripeTransportFuture<'a> {
        let response = if request.path.starts_with("/v1/checkout/sessions/") {
            StripeResponse {
                status: 404,
                body: json!({ "error": { "message": "checkout session not found" } }),
            }
        } else {
            StripeResponse {
                status: 200,
                body: json!({ "id": "ok" }),
            }
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
        Box::pin(async move { Ok(response) })
    }
}

struct TrialingSubscriptionTransport;

impl StripeTransport for TrialingSubscriptionTransport {
    fn send<'a>(&'a self, request: StripeRequest) -> StripeTransportFuture<'a> {
        let body = match request.path.as_str() {
            path if path.starts_with("/v1/checkout/sessions/") => json!({
                "id": "cs_trial_123",
                "object": "checkout.session",
                "metadata": {
                    "userId": "user_1",
                    "subscriptionId": "sub_incomplete",
                    "referenceId": "user_1"
                }
            }),
            "/v1/subscriptions" => json!({
                "object": "list",
                "data": [{
                    "id": "stripe_sub_trialing",
                    "object": "subscription",
                    "status": "trialing",
                    "cancel_at_period_end": false,
                    "trial_start": 1_700_000_000,
                    "trial_end": 1_701_209_600,
                    "items": {
                        "data": [{
                            "id": "si_base",
                            "price": {
                                "id": "price_pro",
                                "object": "price",
                                "recurring": { "interval": "month", "usage_type": "licensed" }
                            },
                            "quantity": 3,
                            "current_period_start": 1_700_000_000,
                            "current_period_end": 1_702_592_000
                        }]
                    }
                }]
            }),
            _ => json!({ "id": "ok" }),
        };
        Box::pin(async move { Ok(StripeResponse { status: 200, body }) })
    }
}

impl StripeTransport for CaptureTransport {
    fn send<'a>(&'a self, request: StripeRequest) -> StripeTransportFuture<'a> {
        let response = match request.path.as_str() {
            path if path.starts_with("/v1/checkout/sessions/") => json!({
                "id": "cs_test_123",
                "object": "checkout.session",
                "metadata": {
                    "userId": "user_1",
                    "subscriptionId": "sub_incomplete",
                    "referenceId": "user_1"
                }
            }),
            "/v1/prices" => json!({
                "object": "list",
                "data": [{
                    "id": "price_from_lookup",
                    "object": "price",
                    "lookup_key": "pro_lookup",
                    "recurring": { "interval": "month", "usage_type": "licensed" }
                }]
            }),
            "/v1/prices/price_metered" => json!({
                "id": "price_metered",
                "object": "price",
                "recurring": { "interval": "month", "usage_type": "metered" }
            }),
            "/v1/checkout/sessions" => json!({
                "id": "cs_test_123",
                "object": "checkout.session",
                "url": "https://checkout.stripe.test/session"
            }),
            "/v1/billing_portal/sessions" => json!({
                "id": "bps_test_123",
                "object": "billing_portal.session",
                "url": "https://billing.stripe.test/session"
            }),
            "/v1/subscriptions" => json!({
                "object": "list",
                "data": [{
                    "id": "stripe_sub_active",
                    "object": "subscription",
                    "status": "active",
                    "cancel_at_period_end": true,
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
                            "quantity": 4,
                            "current_period_start": 1700000000,
                            "current_period_end": 1702592000
                        }]
                    }
                }]
            }),
            "/v1/subscriptions/stripe_sub_active" => json!({
                "id": "stripe_sub_active",
                "object": "subscription",
                "status": "active",
                "cancel_at_period_end": false
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
        Box::pin(async move {
            Ok(StripeResponse {
                status: 200,
                body: response,
            })
        })
    }
}

async fn authenticated_context(
) -> Result<(AuthContext, MemoryAdapter, String), Box<dyn std::error::Error>> {
    authenticated_context_with_email_verified(true).await
}

async fn authenticated_context_with_email_verified(
    email_verified: bool,
) -> Result<(AuthContext, MemoryAdapter, String), Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    let adapter_arc: Arc<dyn DbAdapter> = Arc::new(adapter.clone());
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            base_url: Some("http://localhost:3000".to_owned()),
            ..OpenAuthOptions::default()
        },
        adapter_arc,
    )?;
    let user = DbUserStore::new(&adapter)
        .create_user(
            CreateUserInput::new("Ada Lovelace", "ada@example.com")
                .id("user_1")
                .email_verified(email_verified),
        )
        .await?;
    let session = DbSessionStore::new(&adapter)
        .create_session(
            CreateSessionInput::new(user.id, OffsetDateTime::now_utc() + Duration::days(7))
                .token("session_token_1"),
        )
        .await?;
    let cookies = set_session_cookie(
        &context.auth_cookies,
        &context.secret,
        &session.token,
        SessionCookieOptions {
            dont_remember: false,
            overrides: CookieOptions::default(),
        },
    )?;
    let session_cookie = cookies.first().ok_or("session cookie")?;
    Ok((
        context,
        adapter,
        format!("{}={}", session_cookie.name, session_cookie.value),
    ))
}

fn stripe_options(transport: Arc<CaptureTransport>) -> StripeOptions {
    StripeOptions::new(
        StripeClient::with_transport("sk_test", transport),
        "whsec_test",
    )
    .subscription(SubscriptionOptions::enabled(vec![
        StripePlan::new("pro").price_id("price_pro")
    ]))
}

fn stripe_options_with_authorized_references(transport: Arc<CaptureTransport>) -> StripeOptions {
    StripeOptions::new(
        StripeClient::with_transport("sk_test", transport),
        "whsec_test",
    )
    .subscription(
        SubscriptionOptions::enabled(vec![StripePlan::new("pro").price_id("price_pro")])
            .authorize_reference(|input, _| {
                Box::pin(async move {
                    assert_eq!(input.user.id, "user_1");
                    assert_eq!(input.session.token, "session_token_1");
                    Ok(true)
                })
            }),
    )
}

mod common;

#[path = "routes/active_upgrade.rs"]
mod active_upgrade;
#[path = "routes/cancel_already_canceled.rs"]
mod cancel_already_canceled;
#[path = "routes/cross_user.rs"]
mod cross_user;
#[path = "routes/customer_metadata.rs"]
mod customer_metadata;
#[path = "routes/list_limits.rs"]
mod list_limits;
#[path = "routes/manage.rs"]
mod manage;
#[path = "routes/reference.rs"]
mod reference;
#[path = "routes/reuse_incomplete.rs"]
mod reuse_incomplete;
#[path = "routes/subscription_pagination.rs"]
mod subscription_pagination;
#[path = "routes/trial_abuse.rs"]
mod trial_abuse;
#[path = "routes/upgrade.rs"]
mod upgrade;
#[path = "routes/upgrade_errors.rs"]
mod upgrade_errors;
#[path = "routes/upgrade_lookup.rs"]
mod upgrade_lookup;
#[path = "routes/upgrade_trial_validation.rs"]
mod upgrade_trial_validation;
#[tokio::test]
async fn subscription_list_returns_active_records_for_authenticated_reference(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let plugin = stripe(stripe_options(transport));
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/list")
        .ok_or("list endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    create_subscription_record(&adapter, "sub_active", "user_1", "active", Some("cus_123")).await?;
    create_subscription_record(&adapter, "sub_canceled", "user_1", "canceled", None).await?;
    create_subscription_record(&adapter, "sub_other", "user_2", "active", None).await?;
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
    assert_eq!(subscriptions[0]["id"], "sub_active");
    assert_eq!(subscriptions[0]["referenceId"], "user_1");
    assert_eq!(subscriptions[0]["stripeCustomerId"], "cus_123");
    Ok(())
}

#[tokio::test]
async fn subscription_list_uses_authorized_reference_query(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let plugin = stripe(stripe_options_with_authorized_references(transport));
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/list")
        .ok_or("list endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    create_subscription_record(&adapter, "sub_user", "user_1", "active", Some("cus_user")).await?;
    create_subscription_record(
        &adapter,
        "sub_target",
        "user_2",
        "active",
        Some("cus_target"),
    )
    .await?;
    let request = Request::builder()
        .method(Method::GET)
        .uri("http://localhost:3000/api/auth/subscription/list?referenceId=user_2")
        .header("cookie", cookie_header)
        .body(Vec::new())?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    let subscriptions = body.as_array().ok_or("subscription list response")?;
    assert_eq!(subscriptions.len(), 1);
    assert_eq!(subscriptions[0]["id"], "sub_target");
    assert_eq!(subscriptions[0]["referenceId"], "user_2");
    Ok(())
}

#[tokio::test]
async fn subscription_list_includes_plan_limits_and_interval_price_id(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let options = StripeOptions::new(
        StripeClient::with_transport("sk_test", transport),
        "whsec_test",
    )
    .subscription(SubscriptionOptions::enabled(vec![StripePlan::new("pro")
        .price_id("price_pro_monthly")
        .annual_discount_price_id("price_pro_yearly")
        .limits(json!({ "projects": 10 }))]));
    let plugin = stripe(options);
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/list")
        .ok_or("list endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    create_subscription_record(&adapter, "sub_active", "user_1", "active", Some("cus_123")).await?;
    openauth_core::db::DbAdapter::update(
        &adapter,
        openauth_core::db::Update::new("subscription")
            .where_clause(openauth_core::db::Where::new(
                "id",
                DbValue::String("sub_active".to_owned()),
            ))
            .data("billing_interval", DbValue::String("year".to_owned())),
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
    let subscription = body
        .as_array()
        .and_then(|subscriptions| subscriptions.first())
        .ok_or("subscription")?;
    assert_eq!(subscription["limits"]["projects"], 10);
    assert_eq!(subscription["priceId"], "price_pro_yearly");
    Ok(())
}

#[tokio::test]
async fn subscription_list_resolves_dynamic_plan_provider() -> Result<(), Box<dyn std::error::Error>>
{
    let transport = Arc::new(CaptureTransport::default());
    let plugin = stripe(
        StripeOptions::new(
            StripeClient::with_transport(
                "sk_test",
                Arc::clone(&transport) as Arc<dyn StripeTransport>,
            ),
            "whsec_test",
        )
        .subscription(SubscriptionOptions::enabled_dynamic(|| {
            Box::pin(async {
                Ok(vec![StripePlan::new("pro")
                    .price_id("price_dynamic")
                    .limits(json!({ "projects": 10 }))])
            })
        })),
    );
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/list")
        .ok_or("list endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    create_subscription_record(&adapter, "sub_active", "user_1", "active", Some("cus_123")).await?;
    let request = Request::builder()
        .method(Method::GET)
        .uri("http://localhost:3000/api/auth/subscription/list")
        .header("cookie", cookie_header)
        .body(Vec::new())?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body[0]["priceId"], "price_dynamic");
    assert_eq!(body[0]["limits"]["projects"], 10);
    Ok(())
}

#[tokio::test]
async fn subscription_success_reconciles_checkout_session_and_redirects(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let plugin = stripe(stripe_options(Arc::clone(&transport)));
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
        .uri("http://localhost:3000/api/auth/subscription/success?callbackURL=/done/{CHECKOUT_SESSION_ID}&checkoutSessionId=cs_test_123")
        .header("cookie", cookie_header)
        .body(Vec::new())?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers().get(http::header::LOCATION),
        Some(&http::HeaderValue::from_static("/done/cs_test_123"))
    );
    let records = adapter.records("subscription").await;
    let subscription = records
        .iter()
        .find(|record| record.get("id") == Some(&DbValue::String("sub_incomplete".to_owned())))
        .ok_or("subscription")?;
    assert_eq!(
        subscription.get("status"),
        Some(&DbValue::String("active".to_owned()))
    );
    assert_eq!(
        subscription.get("stripe_subscription_id"),
        Some(&DbValue::String("stripe_sub_active".to_owned()))
    );
    assert_eq!(subscription.get("seats"), Some(&DbValue::Number(4)));
    assert_eq!(
        subscription.get("billing_interval"),
        Some(&DbValue::String("month".to_owned()))
    );
    let requests = transport.requests()?;
    assert!(requests
        .iter()
        .any(|request| request.path == "/v1/checkout/sessions/cs_test_123"));
    assert!(requests
        .iter()
        .any(|request| request.path == "/v1/subscriptions"
            && request.body.contains("customer=cus_123")));
    Ok(())
}

#[tokio::test]
async fn subscription_success_resolves_dynamic_plans() -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let options = StripeOptions::new(
        StripeClient::with_transport(
            "sk_test",
            Arc::clone(&transport) as Arc<dyn StripeTransport>,
        ),
        "whsec_test",
    )
    .subscription(SubscriptionOptions::enabled_dynamic(|| {
        Box::pin(async { Ok(vec![StripePlan::new("dynamic-pro").price_id("price_pro")]) })
    }));
    let plugin = stripe(options);
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
        subscription.get("plan"),
        Some(&DbValue::String("dynamic-pro".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn subscription_success_reconciles_trialing_checkout_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let options = StripeOptions::new(
        StripeClient::with_transport(
            "sk_test",
            Arc::new(TrialingSubscriptionTransport) as Arc<dyn StripeTransport>,
        ),
        "whsec_test",
    )
    .subscription(SubscriptionOptions::enabled(vec![
        StripePlan::new("pro").price_id("price_pro")
    ]));
    let plugin = stripe(options);
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
        .uri("http://localhost:3000/api/auth/subscription/success?callbackURL=/done&checkoutSessionId=cs_trial_123")
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
        subscription.get("status"),
        Some(&DbValue::String("trialing".to_owned()))
    );
    assert_eq!(
        subscription.get("stripe_subscription_id"),
        Some(&DbValue::String("stripe_sub_trialing".to_owned()))
    );
    assert_eq!(
        subscription.get("plan"),
        Some(&DbValue::String("pro".to_owned()))
    );
    assert_eq!(subscription.get("seats"), Some(&DbValue::Number(3)));
    assert_eq!(
        subscription.get("billing_interval"),
        Some(&DbValue::String("month".to_owned()))
    );
    assert_eq!(
        subscription.get("trial_start"),
        Some(&DbValue::Timestamp(OffsetDateTime::from_unix_timestamp(
            1_700_000_000
        )?))
    );
    assert_eq!(
        subscription.get("trial_end"),
        Some(&DbValue::Timestamp(OffsetDateTime::from_unix_timestamp(
            1_701_209_600
        )?))
    );
    Ok(())
}

#[tokio::test]
async fn subscription_success_redirects_without_checkout_session_id(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let plugin = stripe(stripe_options(Arc::clone(&transport)));
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/success")
        .ok_or("success endpoint")?;
    let (context, _adapter, cookie_header) = authenticated_context().await?;
    let request = Request::builder()
        .method(Method::GET)
        .uri("http://localhost:3000/api/auth/subscription/success?callbackURL=/dashboard")
        .header("cookie", cookie_header)
        .body(Vec::new())?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers().get(http::header::LOCATION),
        Some(&http::HeaderValue::from_static("/dashboard"))
    );
    assert!(transport.requests()?.is_empty());
    Ok(())
}

#[tokio::test]
async fn subscription_success_redirects_when_checkout_session_retrieval_fails(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(FailingCheckoutSessionTransport::default());
    let options = StripeOptions::new(
        StripeClient::with_transport(
            "sk_test",
            Arc::clone(&transport) as Arc<dyn StripeTransport>,
        ),
        "whsec_test",
    )
    .subscription(SubscriptionOptions::enabled(vec![
        StripePlan::new("pro").price_id("price_pro")
    ]));
    let plugin = stripe(options);
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/success")
        .ok_or("success endpoint")?;
    let (context, _adapter, cookie_header) = authenticated_context().await?;
    let request = Request::builder()
        .method(Method::GET)
        .uri("http://localhost:3000/api/auth/subscription/success?callbackURL=/dashboard&checkoutSessionId=cs_invalid")
        .header("cookie", cookie_header)
        .body(Vec::new())?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers().get(http::header::LOCATION),
        Some(&http::HeaderValue::from_static("/dashboard"))
    );
    assert!(transport
        .requests()?
        .iter()
        .any(|request| request.path == "/v1/checkout/sessions/cs_invalid"));
    Ok(())
}

#[tokio::test]
async fn billing_portal_uses_current_users_subscription_customer(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let plugin = stripe(stripe_options(Arc::clone(&transport)));
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/billing-portal")
        .ok_or("billing portal endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    create_subscription_record(&adapter, "sub_active", "user_1", "active", Some("cus_123")).await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/billing-portal")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"returnUrl":"http://localhost:3000/account","disableRedirect":true}"#.to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["id"], "bps_test_123");
    assert_eq!(body["redirect"], false);
    let requests = transport.requests()?;
    let portal_request = requests
        .iter()
        .find(|request| request.path == "/v1/billing_portal/sessions")
        .ok_or("billing portal request")?;
    assert!(portal_request.body.contains("customer=cus_123"));
    assert!(portal_request
        .body
        .contains("return_url=http%3A%2F%2Flocalhost%3A3000%2Faccount"));
    Ok(())
}

#[tokio::test]
async fn billing_portal_prefers_user_customer_and_forwards_locale(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let plugin = stripe(stripe_options(Arc::clone(&transport)));
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/billing-portal")
        .ok_or("billing portal endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    openauth_core::db::DbAdapter::update(
        &adapter,
        openauth_core::db::Update::new("user")
            .where_clause(openauth_core::db::Where::new(
                "id",
                DbValue::String("user_1".to_owned()),
            ))
            .data(
                "stripe_customer_id",
                DbValue::String("cus_user_record".to_owned()),
            ),
    )
    .await?;
    create_subscription_record(&adapter, "sub_active", "user_1", "active", Some("cus_sub")).await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/billing-portal")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(br#"{"returnUrl":"/account","locale":"es"}"#.to_vec())?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let requests = transport.requests()?;
    let portal_request = requests
        .iter()
        .find(|request| request.path == "/v1/billing_portal/sessions")
        .ok_or("billing portal request")?;
    assert!(portal_request.body.contains("customer=cus_user_record"));
    assert!(portal_request.body.contains("locale=es"));
    assert!(!portal_request.body.contains("customer=cus_sub"));
    Ok(())
}

#[tokio::test]
async fn cancel_subscription_uses_stripe_portal_cancel_flow(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let plugin = stripe(stripe_options(Arc::clone(&transport)));
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
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["url"], "https://billing.stripe.test/session");
    assert_eq!(body["redirect"], false);
    let requests = transport.requests()?;
    let list_request = requests
        .iter()
        .find(|request| request.path == "/v1/subscriptions")
        .ok_or("subscription list request")?;
    assert!(list_request.body.contains("customer=cus_123"));
    let portal_request = requests
        .iter()
        .find(|request| request.path == "/v1/billing_portal/sessions")
        .ok_or("billing portal request")?;
    assert!(portal_request
        .body
        .contains("flow_data%5Btype%5D=subscription_cancel"));
    assert!(portal_request
        .body
        .contains("flow_data%5Bsubscription_cancel%5D%5Bsubscription%5D=stripe_sub_active"));
    Ok(())
}

#[tokio::test]
async fn restore_subscription_clears_pending_cancel_for_owned_subscription(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let plugin = stripe(stripe_options(Arc::clone(&transport)));
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
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["id"], "stripe_sub_active");
    assert_eq!(body["cancel_at_period_end"], false);
    let records = adapter.records("subscription").await;
    let updated = records
        .iter()
        .find(|record| record.get("id") == Some(&DbValue::String("sub_active".to_owned())))
        .ok_or("updated subscription")?;
    assert_eq!(
        updated.get("cancel_at_period_end"),
        Some(&DbValue::Boolean(false))
    );
    assert_eq!(updated.get("cancel_at"), Some(&DbValue::Null));
    assert_eq!(updated.get("canceled_at"), Some(&DbValue::Null));
    let requests = transport.requests()?;
    let update_request = requests
        .iter()
        .find(|request| {
            request.method == "POST" && request.path == "/v1/subscriptions/stripe_sub_active"
        })
        .ok_or("subscription update request")?;
    assert!(update_request.body.contains("cancel_at_period_end=false"));
    Ok(())
}

#[tokio::test]
async fn webhook_endpoint_rejects_missing_stripe_signature_header(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin = stripe(StripeOptions::new(
        StripeClient::new("sk_test"),
        "whsec_test",
    ));
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/stripe/webhook")
        .ok_or("webhook endpoint")?;
    let context = create_auth_context(OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/stripe/webhook")
        .body(br#"{"id":"evt_123","type":"invoice.paid","data":{"object":{}}}"#.to_vec())?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "STRIPE_SIGNATURE_NOT_FOUND");
    Ok(())
}

#[tokio::test]
async fn webhook_endpoint_verifies_signature_and_calls_on_event(
) -> Result<(), Box<dyn std::error::Error>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen_for_hook = Arc::clone(&seen);
    let options =
        StripeOptions::new(StripeClient::new("sk_test"), "whsec_test").on_event(move |event| {
            let seen = Arc::clone(&seen_for_hook);
            Box::pin(async move {
                seen.lock()
                    .map_err(|error| openauth_core::error::OpenAuthError::Api(error.to_string()))?
                    .push(event.event_type);
                Ok(())
            })
        });
    let plugin = stripe(options);
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/stripe/webhook")
        .ok_or("webhook endpoint")?;
    let context = create_auth_context(OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let payload = br#"{"id":"evt_123","type":"invoice.paid","data":{"object":{"id":"in_123"}}}"#;
    let timestamp = time::OffsetDateTime::now_utc().unix_timestamp();
    let signature = common::webhook::sign_webhook_payload("whsec_test", payload, timestamp)?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/stripe/webhook")
        .header("stripe-signature", signature)
        .body(payload.to_vec())?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        seen.lock().map_err(|error| error.to_string())?.as_slice(),
        ["invoice.paid"]
    );
    Ok(())
}

#[tokio::test]
async fn webhook_endpoint_rejects_empty_webhook_secret_with_config_error(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin = stripe(StripeOptions::new(StripeClient::new("sk_test"), ""));
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/stripe/webhook")
        .ok_or("webhook endpoint")?;
    let context = create_auth_context(OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let payload = br#"{"id":"evt_123","type":"invoice.paid","data":{"object":{"id":"in_123"}}}"#;
    let timestamp = time::OffsetDateTime::now_utc().unix_timestamp();
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/stripe/webhook")
        .header("stripe-signature", format!("t={timestamp},v1=bad"))
        .body(payload.to_vec())?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "STRIPE_WEBHOOK_SECRET_NOT_FOUND");
    Ok(())
}

#[tokio::test]
async fn webhook_endpoint_maps_invalid_signature_to_construct_event_error(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin = stripe(StripeOptions::new(
        StripeClient::new("sk_test"),
        "whsec_test",
    ));
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/stripe/webhook")
        .ok_or("webhook endpoint")?;
    let context = create_auth_context(OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let payload = br#"{"id":"evt_123","type":"invoice.paid","data":{"object":{"id":"in_123"}}}"#;
    let timestamp = time::OffsetDateTime::now_utc().unix_timestamp();
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/stripe/webhook")
        .header("stripe-signature", format!("t={timestamp},v1=bad"))
        .body(payload.to_vec())?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "FAILED_TO_CONSTRUCT_STRIPE_EVENT");
    Ok(())
}

#[tokio::test]
async fn webhook_endpoint_maps_invalid_json_to_construct_event_error(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin = stripe(StripeOptions::new(
        StripeClient::new("sk_test"),
        "whsec_test",
    ));
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/stripe/webhook")
        .ok_or("webhook endpoint")?;
    let context = create_auth_context(OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let payload = br#"{"id":"evt_123","type":"invoice.paid""#;
    let timestamp = time::OffsetDateTime::now_utc().unix_timestamp();
    let signature = common::webhook::sign_webhook_payload("whsec_test", payload, timestamp)?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/stripe/webhook")
        .header("stripe-signature", signature)
        .body(payload.to_vec())?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "FAILED_TO_CONSTRUCT_STRIPE_EVENT");
    Ok(())
}

#[tokio::test]
async fn webhook_endpoint_wraps_event_hook_errors() -> Result<(), Box<dyn std::error::Error>> {
    let options = StripeOptions::new(StripeClient::new("sk_test"), "whsec_test").on_event(|_| {
        Box::pin(async { Err(openauth_core::error::OpenAuthError::Api("boom".to_owned())) })
    });
    let plugin = stripe(options);
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/stripe/webhook")
        .ok_or("webhook endpoint")?;
    let context = create_auth_context(OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let payload = br#"{"id":"evt_123","type":"invoice.paid","data":{"object":{"id":"in_123"}}}"#;
    let timestamp = time::OffsetDateTime::now_utc().unix_timestamp();
    let signature = common::webhook::sign_webhook_payload("whsec_test", payload, timestamp)?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/stripe/webhook")
        .header("stripe-signature", signature)
        .body(payload.to_vec())?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "STRIPE_WEBHOOK_ERROR");
    Ok(())
}

async fn create_subscription_record(
    adapter: &MemoryAdapter,
    id: &str,
    reference_id: &str,
    status: &str,
    stripe_customer_id: Option<&str>,
) -> Result<DbRecord, openauth_core::error::OpenAuthError> {
    let now = OffsetDateTime::now_utc();
    let mut query = Create::new("subscription")
        .data("id", DbValue::String(id.to_owned()))
        .data("plan", DbValue::String("pro".to_owned()))
        .data("reference_id", DbValue::String(reference_id.to_owned()))
        .data("stripe_customer_id", optional_string(stripe_customer_id))
        .data(
            "stripe_subscription_id",
            DbValue::String(format!("stripe_{id}")),
        )
        .data("status", DbValue::String(status.to_owned()))
        .data("period_start", DbValue::Timestamp(now))
        .data("period_end", DbValue::Timestamp(now + Duration::days(30)))
        .data("trial_start", DbValue::Null)
        .data("trial_end", DbValue::Null)
        .data("cancel_at_period_end", DbValue::Boolean(false))
        .data("cancel_at", DbValue::Null)
        .data("canceled_at", DbValue::Null)
        .data("ended_at", DbValue::Null)
        .data("seats", DbValue::Number(1))
        .data("billing_interval", DbValue::String("month".to_owned()))
        .data("stripe_schedule_id", DbValue::Null)
        .force_allow_id();
    query.select = Vec::new();
    adapter.create(query).await
}

async fn create_pending_cancel_subscription_record(
    adapter: &MemoryAdapter,
) -> Result<DbRecord, openauth_core::error::OpenAuthError> {
    let mut record =
        create_subscription_record(adapter, "sub_active", "user_1", "active", Some("cus_123"))
            .await?;
    record.insert(
        "stripe_subscription_id".to_owned(),
        DbValue::String("stripe_sub_active".to_owned()),
    );
    record.insert("cancel_at_period_end".to_owned(), DbValue::Boolean(true));
    openauth_core::db::DbAdapter::update(
        adapter,
        openauth_core::db::Update::new("subscription")
            .where_clause(openauth_core::db::Where::new(
                "id",
                DbValue::String("sub_active".to_owned()),
            ))
            .data(
                "stripe_subscription_id",
                DbValue::String("stripe_sub_active".to_owned()),
            )
            .data("cancel_at_period_end", DbValue::Boolean(true)),
    )
    .await?;
    Ok(record)
}

fn optional_string(value: Option<&str>) -> DbValue {
    value
        .map(|value| DbValue::String(value.to_owned()))
        .unwrap_or(DbValue::Null)
}
