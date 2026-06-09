use super::*;

struct RestoreScheduleTransport {
    requests: Mutex<Vec<StripeRequest>>,
    schedule_status: &'static str,
}

impl RestoreScheduleTransport {
    fn new(schedule_status: &'static str) -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            schedule_status,
        }
    }

    fn requests(&self) -> Result<Vec<StripeRequest>, String> {
        self.requests
            .lock()
            .map(|requests| requests.clone())
            .map_err(|error| error.to_string())
    }
}

impl StripeTransport for RestoreScheduleTransport {
    fn send<'a>(&'a self, request: StripeRequest) -> StripeTransportFuture<'a> {
        let response = match request.path.as_str() {
            "/v1/subscription_schedules/sched_pending" => json!({
                "id": "sched_pending",
                "object": "subscription_schedule",
                "status": self.schedule_status,
            }),
            "/v1/subscription_schedules/sched_pending/release" => json!({
                "id": "sched_pending",
                "object": "subscription_schedule",
                "released_subscription": "stripe_sub_active",
            }),
            "/v1/subscriptions/stripe_sub_active" => json!({
                "id": "stripe_sub_active",
                "object": "subscription",
                "status": "active",
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

#[derive(Default)]
struct AlreadyCanceledPortalTransport {
    requests: Mutex<Vec<StripeRequest>>,
}

impl AlreadyCanceledPortalTransport {
    fn requests(&self) -> Result<Vec<StripeRequest>, String> {
        self.requests
            .lock()
            .map(|requests| requests.clone())
            .map_err(|error| error.to_string())
    }
}

impl StripeTransport for AlreadyCanceledPortalTransport {
    fn send<'a>(&'a self, request: StripeRequest) -> StripeTransportFuture<'a> {
        let response = match request.path.as_str() {
            "/v1/subscriptions" => Ok(json!({
                "object": "list",
                "data": [{
                    "id": "stripe_sub_active",
                    "object": "subscription",
                    "status": "active",
                    "cancel_at_period_end": false,
                    "cancel_at": 1702592000
                }]
            })),
            "/v1/billing_portal/sessions" => Err(StripeResponse {
                status: 400,
                body: json!({
                    "error": {
                        "code": "subscription_already_canceled",
                        "message": "This subscription is already set to be canceled"
                    }
                }),
            }),
            "/v1/subscriptions/stripe_sub_active" => Ok(json!({
                "id": "stripe_sub_active",
                "object": "subscription",
                "status": "active",
                "cancel_at_period_end": false,
                "cancel_at": 1702592000,
                "canceled_at": 1700000000
            })),
            _ => Ok(json!({ "id": "ok" })),
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
            match response {
                Ok(body) => Ok(StripeResponse { status: 200, body }),
                Err(response) => Ok(response),
            }
        })
    }
}

#[derive(Default)]
struct EmptySubscriptionListTransport {
    requests: Mutex<Vec<StripeRequest>>,
}

impl EmptySubscriptionListTransport {
    fn requests(&self) -> Result<Vec<StripeRequest>, String> {
        self.requests
            .lock()
            .map(|requests| requests.clone())
            .map_err(|error| error.to_string())
    }
}

impl StripeTransport for EmptySubscriptionListTransport {
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
                body: json!({ "object": "list", "data": [] }),
            })
        })
    }
}

#[derive(Default)]
struct FailingBillingPortalTransport {
    requests: Mutex<Vec<StripeRequest>>,
}

impl FailingBillingPortalTransport {
    fn requests(&self) -> Result<Vec<StripeRequest>, String> {
        self.requests
            .lock()
            .map(|requests| requests.clone())
            .map_err(|error| error.to_string())
    }
}

impl StripeTransport for FailingBillingPortalTransport {
    fn send<'a>(&'a self, request: StripeRequest) -> StripeTransportFuture<'a> {
        let response = if request.path == "/v1/billing_portal/sessions" {
            StripeResponse {
                status: 500,
                body: json!({ "error": { "message": "portal unavailable" } }),
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

#[tokio::test]
async fn restore_subscription_releases_active_schedule_and_clears_local_schedule(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(RestoreScheduleTransport::new("active"));
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
    let plugin = stripe(options).unwrap();
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/restore")
        .ok_or("restore endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    create_subscription_record(&adapter, "sub_active", "user_1", "active", Some("cus_123")).await?;
    openauth_core::db::DbAdapter::update(
        &adapter,
        openauth_core::db::Update::new("subscription")
            .where_clause(openauth_core::db::Where::new(
                "id",
                DbValue::String("sub_active".to_owned()),
            ))
            .data(
                "stripe_schedule_id",
                DbValue::String("sched_pending".to_owned()),
            ),
    )
    .await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/restore")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(br#"{"subscriptionId":"stripe_sub_active"}"#.to_vec())?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let requests = transport.requests()?;
    assert!(requests.iter().any(|request| request.method == "GET"
        && request.path == "/v1/subscription_schedules/sched_pending"));
    assert!(requests
        .iter()
        .any(|request| request.path == "/v1/subscription_schedules/sched_pending/release"));
    let records = adapter.records("subscription").await;
    let subscription = records
        .iter()
        .find(|record| record.get("id") == Some(&DbValue::String("sub_active".to_owned())))
        .ok_or("subscription")?;
    assert_eq!(subscription.get("stripe_schedule_id"), Some(&DbValue::Null));
    Ok(())
}

#[tokio::test]
async fn cancel_subscription_syncs_pending_cancel_when_portal_says_already_canceled(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(AlreadyCanceledPortalTransport::default());
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
    let plugin = stripe(options).unwrap();
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
        .body(br#"{"returnUrl":"/account"}"#.to_vec())?;

    let response = (endpoint.handler)(&context, request).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let records = adapter.records("subscription").await;
    let subscription = records
        .iter()
        .find(|record| record.get("id") == Some(&DbValue::String("sub_active".to_owned())))
        .ok_or("subscription")?;
    assert_eq!(
        subscription.get("cancel_at_period_end"),
        Some(&DbValue::Boolean(false))
    );
    assert_eq!(
        subscription.get("cancel_at"),
        Some(&DbValue::Timestamp(OffsetDateTime::from_unix_timestamp(
            1702592000
        )?))
    );
    assert_eq!(
        subscription.get("canceled_at"),
        Some(&DbValue::Timestamp(OffsetDateTime::from_unix_timestamp(
            1700000000
        )?))
    );
    let requests = transport.requests()?;
    assert!(requests.iter().any(|request| {
        request.method == "GET" && request.path == "/v1/subscriptions/stripe_sub_active"
    }));
    Ok(())
}

#[tokio::test]
async fn cancel_subscription_preserves_local_subscriptions_when_stripe_has_no_active(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(EmptySubscriptionListTransport::default());
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
    let plugin = stripe(options).unwrap();
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
        .body(br#"{"returnUrl":"/account"}"#.to_vec())?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "SUBSCRIPTION_NOT_FOUND");
    let records = adapter.records("subscription").await;
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].get("id"),
        Some(&DbValue::String("sub_active".to_owned()))
    );
    let requests = transport.requests()?;
    assert!(requests
        .iter()
        .any(|request| request.method == "GET" && request.path == "/v1/subscriptions"));
    assert!(!requests
        .iter()
        .any(|request| request.path == "/v1/billing_portal/sessions"));
    Ok(())
}

#[derive(Default)]
struct EmptyListCheckoutTransport {
    requests: Mutex<Vec<StripeRequest>>,
}

impl EmptyListCheckoutTransport {
    fn requests(&self) -> Result<Vec<StripeRequest>, String> {
        self.requests
            .lock()
            .map(|requests| requests.clone())
            .map_err(|error| error.to_string())
    }
}

impl StripeTransport for EmptyListCheckoutTransport {
    fn send<'a>(&'a self, request: StripeRequest) -> StripeTransportFuture<'a> {
        let response = match request.path.as_str() {
            "/v1/subscriptions" => json!({ "object": "list", "data": [] }),
            "/v1/checkout/sessions" => json!({
                "id": "cs_test_123",
                "object": "checkout.session",
                "url": "https://checkout.stripe.test/session"
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

#[tokio::test]
async fn cancel_subscription_preserves_trial_history_for_upgrade_guard(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(EmptyListCheckoutTransport::default());
    let options = StripeOptions::new(
        StripeClient::with_transport(
            "sk_test",
            Arc::clone(&transport) as Arc<dyn StripeTransport>,
        ),
        "whsec_test",
    )
    .subscription(SubscriptionOptions::enabled(vec![StripePlan::new("pro")
        .price_id("price_pro")
        .free_trial(openauth_stripe::options::FreeTrialOptions::new(7))]));
    let plugin = stripe(options).unwrap();
    let cancel_endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/cancel")
        .ok_or("cancel endpoint")?;
    let upgrade_endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    create_subscription_record(
        &adapter,
        "sub_canceled_trial",
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
                DbValue::String("sub_canceled_trial".to_owned()),
            ))
            .data("trial_start", DbValue::Timestamp(OffsetDateTime::now_utc())),
    )
    .await?;
    create_subscription_record(&adapter, "sub_active", "user_1", "active", Some("cus_123")).await?;
    let cancel_request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/cancel")
        .header("content-type", "application/json")
        .header("cookie", cookie_header.clone())
        .body(br#"{"returnUrl":"/account"}"#.to_vec())?;

    let cancel_response = (cancel_endpoint.handler)(&context, cancel_request).await?;

    assert_eq!(cancel_response.status(), StatusCode::BAD_REQUEST);
    let cancel_body: Value = serde_json::from_slice(cancel_response.body())?;
    assert_eq!(cancel_body["code"], "SUBSCRIPTION_NOT_FOUND");
    let records = adapter.records("subscription").await;
    assert!(records
        .iter()
        .any(|record| record.get("id") == Some(&DbValue::String("sub_canceled_trial".to_owned()))));
    let historical = records
        .iter()
        .find(|record| record.get("id") == Some(&DbValue::String("sub_canceled_trial".to_owned())))
        .ok_or("historical trial subscription")?;
    assert!(historical
        .get("trial_start")
        .is_some_and(|value| !matches!(value, DbValue::Null)));
    let upgrade_request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(br#"{"plan":"pro","successUrl":"/ok","cancelUrl":"/pricing"}"#.to_vec())?;

    let upgrade_response = (upgrade_endpoint.handler)(&context, upgrade_request).await?;

    assert_eq!(upgrade_response.status(), StatusCode::OK);
    let checkout_request = transport
        .requests()?
        .into_iter()
        .find(|request| request.path == "/v1/checkout/sessions")
        .ok_or("checkout request")?;
    assert!(!checkout_request.body.contains("trial_period_days"));
    Ok(())
}

#[tokio::test]
async fn restore_subscription_skips_release_for_inactive_schedule(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(RestoreScheduleTransport::new("released"));
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
    let plugin = stripe(options).unwrap();
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/restore")
        .ok_or("restore endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    create_subscription_record(&adapter, "sub_active", "user_1", "active", Some("cus_123")).await?;
    openauth_core::db::DbAdapter::update(
        &adapter,
        openauth_core::db::Update::new("subscription")
            .where_clause(openauth_core::db::Where::new(
                "id",
                DbValue::String("sub_active".to_owned()),
            ))
            .data(
                "stripe_schedule_id",
                DbValue::String("sched_pending".to_owned()),
            ),
    )
    .await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/restore")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(br#"{"subscriptionId":"stripe_sub_active"}"#.to_vec())?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let requests = transport.requests()?;
    assert!(requests.iter().any(|request| request.method == "GET"
        && request.path == "/v1/subscription_schedules/sched_pending"));
    assert!(!requests
        .iter()
        .any(|request| request.path == "/v1/subscription_schedules/sched_pending/release"));
    let records = adapter.records("subscription").await;
    let subscription = records
        .iter()
        .find(|record| record.get("id") == Some(&DbValue::String("sub_active".to_owned())))
        .ok_or("subscription")?;
    assert_eq!(subscription.get("stripe_schedule_id"), Some(&DbValue::Null));
    Ok(())
}

#[tokio::test]
async fn restore_subscription_rejects_without_pending_cancel_or_schedule(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
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
    let plugin = stripe(options).unwrap();
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/restore")
        .ok_or("restore endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    create_subscription_record(&adapter, "sub_active", "user_1", "active", Some("cus_123")).await?;
    openauth_core::db::DbAdapter::update(
        &adapter,
        openauth_core::db::Update::new("subscription")
            .where_clause(openauth_core::db::Where::new(
                "id",
                DbValue::String("sub_active".to_owned()),
            ))
            .data(
                "stripe_subscription_id",
                DbValue::String("stripe_sub_active".to_owned()),
            ),
    )
    .await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/restore")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(br#"{"subscriptionId":"stripe_sub_active"}"#.to_vec())?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "SUBSCRIPTION_NOT_PENDING_CHANGE");
    assert!(!transport
        .requests()?
        .iter()
        .any(|request| request.path.starts_with("/v1/")));
    Ok(())
}

#[tokio::test]
async fn billing_portal_maps_stripe_failure_to_plugin_error(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(FailingBillingPortalTransport::default());
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
    let plugin = stripe(options).unwrap();
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
            .data("stripe_customer_id", DbValue::String("cus_user".to_owned())),
    )
    .await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/billing-portal")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(br#"{"returnUrl":"/account"}"#.to_vec())?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "FAILED_TO_FETCH_PLANS");
    assert_eq!(body["originalMessage"], "portal unavailable");
    assert!(transport
        .requests()?
        .iter()
        .any(|request| request.path == "/v1/billing_portal/sessions"));
    Ok(())
}

#[tokio::test]
async fn billing_portal_for_organization_uses_organization_customer(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let options = StripeOptions::new(
        StripeClient::with_transport(
            "sk_test",
            Arc::clone(&transport) as Arc<dyn StripeTransport>,
        ),
        "whsec_test",
    )
    .organization(openauth_stripe::options::OrganizationStripeOptions::enabled())
    .subscription(
        SubscriptionOptions::enabled(vec![StripePlan::new("pro").price_id("price_pro")])
            .authorize_reference(|input, _| {
                Box::pin(async move {
                    Ok(input.reference_id == "org_1"
                        && input.action
                            == openauth_stripe::options::AuthorizeReferenceAction::BillingPortal)
                })
            }),
    );
    let plugin = stripe(options).unwrap();
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
            .data("stripe_customer_id", DbValue::String("cus_user".to_owned())),
    )
    .await?;
    adapter
        .create(
            Create::new("organization")
                .data("id", DbValue::String("org_1".to_owned()))
                .data("name", DbValue::String("Acme".to_owned()))
                .data("slug", DbValue::String("acme".to_owned()))
                .data("stripe_customer_id", DbValue::String("cus_org".to_owned()))
                .force_allow_id(),
        )
        .await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/billing-portal")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"customerType":"organization","referenceId":"org_1","returnUrl":"/account"}"#
                .to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let requests = transport.requests()?;
    let portal_request = requests
        .iter()
        .find(|request| request.path == "/v1/billing_portal/sessions")
        .ok_or("billing portal request")?;
    assert!(portal_request.body.contains("customer=cus_org"));
    assert!(!portal_request.body.contains("customer=cus_user"));
    Ok(())
}

#[tokio::test]
async fn cancel_subscription_rejects_organization_customer_type_when_org_disabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let options = StripeOptions::new(
        StripeClient::with_transport(
            "sk_test",
            Arc::clone(&transport) as Arc<dyn StripeTransport>,
        ),
        "whsec_test",
    )
    .subscription(
        SubscriptionOptions::enabled(vec![StripePlan::new("pro").price_id("price_pro")])
            .authorize_reference(|input, _| {
                Box::pin(async move {
                    Ok(input.reference_id == "org_1"
                        && input.action
                            == openauth_stripe::options::AuthorizeReferenceAction::CancelSubscription)
                })
            }),
    );
    let plugin = stripe(options).unwrap();
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/cancel")
        .ok_or("cancel endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    create_subscription_record(&adapter, "sub_active", "org_1", "active", Some("cus_org")).await?;
    openauth_core::db::DbAdapter::update(
        &adapter,
        openauth_core::db::Update::new("subscription")
            .where_clause(openauth_core::db::Where::new(
                "id",
                DbValue::String("sub_active".to_owned()),
            ))
            .data(
                "stripe_subscription_id",
                DbValue::String("stripe_sub_active".to_owned()),
            ),
    )
    .await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/cancel")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"customerType":"organization","referenceId":"org_1","returnUrl":"/account"}"#
                .to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "ORGANIZATION_SUBSCRIPTION_NOT_ENABLED");
    assert!(!transport
        .requests()?
        .iter()
        .any(|request| request.path.starts_with("/v1/")));
    Ok(())
}

#[tokio::test]
async fn list_subscription_rejects_organization_customer_type_when_org_disabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let options = StripeOptions::new(
        StripeClient::with_transport("sk_test", transport),
        "whsec_test",
    )
    .subscription(
        SubscriptionOptions::enabled(vec![StripePlan::new("pro").price_id("price_pro")])
            .authorize_reference(|input, _| {
                Box::pin(async move {
                    Ok(input.reference_id == "org_1"
                        && input.action
                            == openauth_stripe::options::AuthorizeReferenceAction::ListSubscription)
                })
            }),
    );
    let plugin = stripe(options).unwrap();
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/list")
        .ok_or("list endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    create_subscription_record(&adapter, "sub_active", "org_1", "active", Some("cus_org")).await?;
    let request = Request::builder()
        .method(Method::GET)
        .uri(
            "http://localhost:3000/api/auth/subscription/list?customerType=organization&referenceId=org_1",
        )
        .header("cookie", cookie_header)
        .body(Vec::new())?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "ORGANIZATION_SUBSCRIPTION_NOT_ENABLED");
    Ok(())
}

#[tokio::test]
async fn list_subscription_for_organization_uses_active_organization_reference(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let options = organization_options_for_action(
        Arc::clone(&transport) as Arc<dyn StripeTransport>,
        openauth_stripe::options::AuthorizeReferenceAction::ListSubscription,
    );
    let plugin = stripe(options).unwrap();
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/list")
        .ok_or("list endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    create_subscription_record(&adapter, "sub_org", "org_1", "active", Some("cus_org")).await?;
    create_subscription_record(&adapter, "sub_user", "user_1", "active", Some("cus_user")).await?;
    set_active_organization(&adapter, "org_1").await?;
    let request = Request::builder()
        .method(Method::GET)
        .uri("http://localhost:3000/api/auth/subscription/list?customerType=organization")
        .header("cookie", cookie_header)
        .body(Vec::new())?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    let subscriptions = body.as_array().ok_or("subscription list")?;
    assert_eq!(subscriptions.len(), 1);
    assert_eq!(subscriptions[0]["id"], "sub_org");
    assert_eq!(subscriptions[0]["referenceId"], "org_1");
    Ok(())
}

#[tokio::test]
async fn cancel_subscription_for_organization_uses_org_subscription_customer(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let options = organization_options_for_action(
        Arc::clone(&transport) as Arc<dyn StripeTransport>,
        openauth_stripe::options::AuthorizeReferenceAction::CancelSubscription,
    );
    let plugin = stripe(options).unwrap();
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/cancel")
        .ok_or("cancel endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    create_subscription_record(&adapter, "sub_active", "org_1", "active", Some("cus_org")).await?;
    openauth_core::db::DbAdapter::update(
        &adapter,
        openauth_core::db::Update::new("subscription")
            .where_clause(openauth_core::db::Where::new(
                "id",
                DbValue::String("sub_active".to_owned()),
            ))
            .data(
                "stripe_subscription_id",
                DbValue::String("stripe_sub_active".to_owned()),
            ),
    )
    .await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/cancel")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"customerType":"organization","referenceId":"org_1","returnUrl":"/account"}"#
                .to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let requests = transport.requests()?;
    let list_request = requests
        .iter()
        .find(|request| request.path == "/v1/subscriptions")
        .ok_or("subscription list request")?;
    assert!(list_request.body.contains("customer=cus_org"));
    let portal_request = requests
        .iter()
        .find(|request| request.path == "/v1/billing_portal/sessions")
        .ok_or("billing portal request")?;
    assert!(portal_request.body.contains("customer=cus_org"));
    assert!(portal_request
        .body
        .contains("flow_data%5Bsubscription_cancel%5D%5Bsubscription%5D=stripe_sub_active"));
    Ok(())
}

#[derive(Default)]
struct CancelAtRestoreTransport {
    requests: Mutex<Vec<StripeRequest>>,
}

impl CancelAtRestoreTransport {
    fn requests(&self) -> Result<Vec<StripeRequest>, String> {
        self.requests
            .lock()
            .map(|requests| requests.clone())
            .map_err(|error| error.to_string())
    }
}

impl StripeTransport for CancelAtRestoreTransport {
    fn send<'a>(&'a self, request: StripeRequest) -> StripeTransportFuture<'a> {
        let response = match request.path.as_str() {
            "/v1/subscriptions" => json!({
                "object": "list",
                "data": [{
                    "id": "stripe_sub_active",
                    "object": "subscription",
                    "status": "active",
                    "cancel_at_period_end": false,
                    "cancel_at": 1_702_592_000
                }]
            }),
            "/v1/subscriptions/stripe_sub_active" => json!({
                "id": "stripe_sub_active",
                "object": "subscription",
                "status": "active",
                "cancel_at_period_end": false,
                "cancel_at": null
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

#[tokio::test]
async fn restore_subscription_clears_cancel_at_timestamp() -> Result<(), Box<dyn std::error::Error>>
{
    let transport = Arc::new(CancelAtRestoreTransport::default());
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
    let plugin = stripe(options).unwrap();
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/restore")
        .ok_or("restore endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    create_subscription_record(&adapter, "sub_active", "user_1", "active", Some("cus_123")).await?;
    openauth_core::db::DbAdapter::update(
        &adapter,
        openauth_core::db::Update::new("subscription")
            .where_clause(openauth_core::db::Where::new(
                "id",
                DbValue::String("sub_active".to_owned()),
            ))
            .data(
                "stripe_subscription_id",
                DbValue::String("stripe_sub_active".to_owned()),
            )
            .data("cancel_at_period_end", DbValue::Boolean(false))
            .data(
                "cancel_at",
                DbValue::Timestamp(OffsetDateTime::from_unix_timestamp(1_702_592_000)?),
            )
            .data(
                "canceled_at",
                DbValue::Timestamp(OffsetDateTime::from_unix_timestamp(1_700_000_000)?),
            ),
    )
    .await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/restore")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(br#"{"subscriptionId":"stripe_sub_active"}"#.to_vec())?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let update_request = transport
        .requests()?
        .into_iter()
        .find(|request| {
            request.method == "POST" && request.path == "/v1/subscriptions/stripe_sub_active"
        })
        .ok_or("stripe update")?;
    assert!(update_request.body.contains("cancel_at="));
    assert!(!update_request.body.contains("cancel_at_period_end"));
    let subscription = adapter.records("subscription").await;
    let record = subscription
        .iter()
        .find(|record| record.get("id") == Some(&DbValue::String("sub_active".to_owned())))
        .ok_or("subscription")?;
    assert_eq!(record.get("cancel_at"), Some(&DbValue::Null));
    assert_eq!(
        record.get("cancel_at_period_end"),
        Some(&DbValue::Boolean(false))
    );
    assert_eq!(record.get("canceled_at"), Some(&DbValue::Null));
    Ok(())
}

#[tokio::test]
async fn restore_subscription_for_organization_clears_pending_cancel(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let options = organization_options_for_action(
        Arc::clone(&transport) as Arc<dyn StripeTransport>,
        openauth_stripe::options::AuthorizeReferenceAction::RestoreSubscription,
    );
    let plugin = stripe(options).unwrap();
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/restore")
        .ok_or("restore endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    create_subscription_record(&adapter, "sub_active", "org_1", "active", Some("cus_org")).await?;
    openauth_core::db::DbAdapter::update(
        &adapter,
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
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/restore")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"customerType":"organization","referenceId":"org_1","subscriptionId":"stripe_sub_active"}"#
                .to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let requests = transport.requests()?;
    let list_request = requests
        .iter()
        .find(|request| request.path == "/v1/subscriptions")
        .ok_or("subscription list request")?;
    assert!(list_request.body.contains("customer=cus_org"));
    let update_request = requests
        .iter()
        .find(|request| request.path == "/v1/subscriptions/stripe_sub_active")
        .ok_or("subscription update request")?;
    assert!(update_request.body.contains("cancel_at_period_end=false"));
    let records = adapter.records("subscription").await;
    let subscription = records
        .iter()
        .find(|record| record.get("id") == Some(&DbValue::String("sub_active".to_owned())))
        .ok_or("subscription")?;
    assert_eq!(
        subscription.get("cancel_at_period_end"),
        Some(&DbValue::Boolean(false))
    );
    Ok(())
}

fn organization_options_for_action(
    transport: Arc<dyn StripeTransport>,
    expected_action: openauth_stripe::options::AuthorizeReferenceAction,
) -> StripeOptions {
    StripeOptions::new(
        StripeClient::with_transport("sk_test", transport),
        "whsec_test",
    )
    .organization(openauth_stripe::options::OrganizationStripeOptions::enabled())
    .subscription(
        SubscriptionOptions::enabled(vec![StripePlan::new("pro").price_id("price_pro")])
            .authorize_reference(move |input, _| {
                Box::pin(async move {
                    Ok(input.reference_id == "org_1" && input.action == expected_action)
                })
            }),
    )
}

async fn set_active_organization(
    adapter: &MemoryAdapter,
    organization_id: &str,
) -> Result<(), openauth_core::error::OpenAuthError> {
    openauth_core::db::DbAdapter::update(
        adapter,
        openauth_core::db::Update::new("session")
            .where_clause(openauth_core::db::Where::new(
                "token",
                DbValue::String("session_token_1".to_owned()),
            ))
            .data(
                "active_organization_id",
                DbValue::String(organization_id.to_owned()),
            ),
    )
    .await?;
    Ok(())
}
