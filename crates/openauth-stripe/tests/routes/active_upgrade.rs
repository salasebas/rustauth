use super::*;

#[derive(Default)]
struct ActiveUpgradeTransport {
    requests: Mutex<Vec<StripeRequest>>,
    schedule: Option<Value>,
    include_seat_item: bool,
    schedule_source: Option<&'static str>,
    fail_billing_portal: bool,
    fail_schedule_update: bool,
    fail_schedule_release: bool,
}

#[derive(Default)]
struct DuplicateLineItemTransport {
    requests: Mutex<Vec<StripeRequest>>,
}

#[derive(Default)]
struct StaleDestinationLineItemTransport {
    requests: Mutex<Vec<StripeRequest>>,
}

impl StaleDestinationLineItemTransport {
    fn requests(&self) -> Result<Vec<StripeRequest>, String> {
        self.requests
            .lock()
            .map(|requests| requests.clone())
            .map_err(|error| error.to_string())
    }
}

impl StripeTransport for StaleDestinationLineItemTransport {
    fn send<'a>(&'a self, request: StripeRequest) -> StripeTransportFuture<'a> {
        let response = match (request.path.as_str(), request.method.as_str()) {
            ("/v1/subscriptions", _) => json!({
                "object": "list",
                "data": [{
                    "id": "stripe_sub_active",
                    "object": "subscription",
                    "status": "active",
                    "cancel_at_period_end": false,
                    "items": {
                        "data": [
                            {
                                "id": "si_base",
                                "price": {
                                    "id": "price_basic_base",
                                    "object": "price",
                                    "recurring": { "interval": "month", "usage_type": "licensed" }
                                },
                                "quantity": 1
                            },
                            {
                                "id": "si_events",
                                "price": {
                                    "id": "price_basic_events",
                                    "object": "price",
                                    "recurring": { "interval": "month", "usage_type": "metered" }
                                }
                            },
                            {
                                "id": "si_stale_security",
                                "price": {
                                    "id": "price_premium_security",
                                    "object": "price",
                                    "recurring": { "interval": "month", "usage_type": "metered" }
                                }
                            }
                        ]
                    }
                }]
            }),
            ("/v1/subscription_schedules", "POST") => json!({
                "id": "sched_new",
                "object": "subscription_schedule",
                "phases": [{
                    "start_date": 1700000000,
                    "end_date": 1702592000,
                    "items": [
                        { "price": { "id": "price_basic_base" }, "quantity": 1 },
                        { "price": { "id": "price_basic_events" } },
                        { "price": { "id": "price_premium_security" } }
                    ]
                }]
            }),
            ("/v1/subscription_schedules/sched_new", _) => json!({
                "id": "sched_new",
                "object": "subscription_schedule"
            }),
            ("/v1/subscriptions/stripe_sub_active", _) => json!({
                "id": "stripe_sub_active",
                "object": "subscription",
                "status": "active"
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

impl DuplicateLineItemTransport {
    fn requests(&self) -> Result<Vec<StripeRequest>, String> {
        self.requests
            .lock()
            .map(|requests| requests.clone())
            .map_err(|error| error.to_string())
    }
}

impl StripeTransport for DuplicateLineItemTransport {
    fn send<'a>(&'a self, request: StripeRequest) -> StripeTransportFuture<'a> {
        let response = match (request.path.as_str(), request.method.as_str()) {
            ("/v1/subscriptions", _) => json!({
                "object": "list",
                "data": [{
                    "id": "stripe_sub_active",
                    "object": "subscription",
                    "status": "active",
                    "cancel_at_period_end": false,
                    "items": {
                        "data": [
                            {
                                "id": "si_base",
                                "price": {
                                    "id": "price_starter",
                                    "object": "price",
                                    "recurring": { "interval": "month", "usage_type": "licensed" }
                                },
                                "quantity": 1
                            },
                            {
                                "id": "si_addon_a",
                                "price": {
                                    "id": "price_events",
                                    "object": "price",
                                    "recurring": { "interval": "month", "usage_type": "metered" }
                                }
                            },
                            {
                                "id": "si_addon_b",
                                "price": {
                                    "id": "price_events",
                                    "object": "price",
                                    "recurring": { "interval": "month", "usage_type": "metered" }
                                }
                            }
                        ]
                    }
                }]
            }),
            ("/v1/subscriptions/stripe_sub_active", _) => json!({
                "id": "stripe_sub_active",
                "object": "subscription",
                "status": "active"
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

impl ActiveUpgradeTransport {
    fn with_plugin_schedule() -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            schedule: Some(json!("sched_existing")),
            include_seat_item: false,
            schedule_source: Some("@better-auth/stripe"),
            fail_billing_portal: false,
            fail_schedule_update: false,
            fail_schedule_release: false,
        }
    }

    fn with_external_schedule() -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            schedule: Some(json!("sched_existing")),
            include_seat_item: false,
            schedule_source: Some("stripe-dashboard"),
            fail_billing_portal: false,
            fail_schedule_update: false,
            fail_schedule_release: false,
        }
    }

    fn with_seat_item() -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            schedule: None,
            include_seat_item: true,
            schedule_source: None,
            fail_billing_portal: false,
            fail_schedule_update: false,
            fail_schedule_release: false,
        }
    }

    fn with_billing_portal_failure() -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            schedule: None,
            include_seat_item: false,
            schedule_source: None,
            fail_billing_portal: true,
            fail_schedule_update: false,
            fail_schedule_release: false,
        }
    }

    fn with_schedule_update_failure() -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            schedule: None,
            include_seat_item: false,
            schedule_source: None,
            fail_billing_portal: false,
            fail_schedule_update: true,
            fail_schedule_release: false,
        }
    }

    fn with_schedule_update_and_release_failure() -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            schedule: None,
            include_seat_item: false,
            schedule_source: None,
            fail_billing_portal: false,
            fail_schedule_update: true,
            fail_schedule_release: true,
        }
    }

    fn requests(&self) -> Result<Vec<StripeRequest>, String> {
        self.requests
            .lock()
            .map(|requests| requests.clone())
            .map_err(|error| error.to_string())
    }
}

impl StripeTransport for ActiveUpgradeTransport {
    fn send<'a>(&'a self, request: StripeRequest) -> StripeTransportFuture<'a> {
        let schedule = self.schedule.clone().unwrap_or(Value::Null);
        let mut items = vec![
            json!({
                "id": "si_base",
                "price": {
                    "id": "price_starter",
                    "object": "price",
                    "recurring": { "interval": "month", "usage_type": "licensed" }
                },
                "quantity": 1,
                "current_period_start": 1700000000,
                "current_period_end": 1702592000
            }),
            json!({
                "id": "si_events",
                "price": {
                    "id": "price_starter_events",
                    "object": "price",
                    "recurring": { "interval": "month", "usage_type": "metered" }
                }
            }),
        ];
        if self.include_seat_item {
            items.insert(
                1,
                json!({
                    "id": "si_seats",
                    "price": {
                        "id": "price_starter_seats",
                        "object": "price",
                        "recurring": { "interval": "month", "usage_type": "licensed" }
                    },
                    "quantity": 3,
                    "current_period_start": 1700000000,
                    "current_period_end": 1702592000
                }),
            );
        }
        let schedule_source = self.schedule_source.unwrap_or("@better-auth/stripe");
        let (status, response) = match (request.path.as_str(), request.method.as_str()) {
            ("/v1/billing_portal/sessions", _) if self.fail_billing_portal => {
                (500, json!({ "error": { "message": "portal failed" } }))
            }
            ("/v1/prices/price_metered_scheduled", _) => (
                200,
                json!({
                    "id": "price_metered_scheduled",
                    "object": "price",
                    "recurring": { "interval": "month", "usage_type": "metered" }
                }),
            ),
            ("/v1/subscriptions", _) => (
                200,
                json!({
                    "object": "list",
                    "data": [{
                        "id": "stripe_sub_active",
                        "object": "subscription",
                        "status": "active",
                        "cancel_at_period_end": false,
                        "schedule": schedule,
                        "items": {
                            "data": items
                        }
                    }]
                }),
            ),
            ("/v1/subscriptions/stripe_sub_active", _) => (
                200,
                json!({
                    "id": "stripe_sub_active",
                    "object": "subscription",
                    "status": "active"
                }),
            ),
            ("/v1/subscription_schedules", "GET") => (
                200,
                json!({
                        "object": "list",
                        "data": [{
                        "id": "sched_existing",
                        "object": "subscription_schedule",
                        "status": "active",
                        "subscription": "stripe_sub_active",
                        "metadata": { "source": schedule_source }
                    }]
                }),
            ),
            ("/v1/subscription_schedules", "POST") => (
                200,
                json!({
                    "id": "sched_new",
                    "object": "subscription_schedule",
                    "phases": [{
                        "start_date": 1700000000,
                        "end_date": 1702592000,
                        "items": [
                            {
                                "price": {
                                    "id": "price_starter",
                                    "object": "price"
                                },
                                "quantity": 1
                            },
                            { "price": "price_starter_events" }
                        ]
                    }]
                }),
            ),
            ("/v1/subscription_schedules/sched_new/release", _) if self.fail_schedule_release => (
                500,
                json!({ "error": { "message": "schedule release failed" } }),
            ),
            ("/v1/subscription_schedules/sched_new", "POST") if self.fail_schedule_update => (
                500,
                json!({ "error": { "message": "schedule update failed" } }),
            ),
            ("/v1/subscription_schedules/sched_new", _) => (
                200,
                json!({
                    "id": "sched_new",
                    "object": "subscription_schedule"
                }),
            ),
            ("/v1/subscription_schedules/sched_existing/release", _) => (
                200,
                json!({
                    "id": "sched_existing",
                    "object": "subscription_schedule",
                    "released_subscription": "stripe_sub_active"
                }),
            ),
            _ => (200, json!({ "id": "ok" })),
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
                status,
                body: response,
            })
        })
    }
}

#[tokio::test]
async fn subscription_upgrade_uses_billing_portal_for_simple_active_plan_change(
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
        StripePlan::new("starter").price_id("price_starter"),
        StripePlan::new("pro").price_id("price_pro"),
    ]));
    let plugin = stripe(options);
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    openauth_core::db::DbAdapter::update(
        &adapter,
        openauth_core::db::Update::new("user")
            .where_clause(openauth_core::db::Where::new(
                "id",
                DbValue::String("user_1".to_owned()),
            ))
            .data("stripe_customer_id", DbValue::String("cus_123".to_owned())),
    )
    .await?;
    create_subscription_record(&adapter, "sub_active", "user_1", "active", Some("cus_123")).await?;
    openauth_core::db::DbAdapter::update(
        &adapter,
        openauth_core::db::Update::new("subscription")
            .where_clause(openauth_core::db::Where::new(
                "id",
                DbValue::String("sub_active".to_owned()),
            ))
            .data("plan", DbValue::String("starter".to_owned()))
            .data(
                "stripe_subscription_id",
                DbValue::String("stripe_sub_active".to_owned()),
            ),
    )
    .await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"plan":"pro","seats":2,"returnUrl":"/account","successUrl":"/ok","cancelUrl":"/pricing","disableRedirect":true}"#
                .to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["id"], "bps_test_123");
    assert_eq!(body["redirect"], false);
    let requests = transport.requests()?;
    assert!(requests
        .iter()
        .any(|request| request.path == "/v1/subscriptions"
            && request.body.contains("customer=cus_123")));
    let portal_request = requests
        .iter()
        .find(|request| request.path == "/v1/billing_portal/sessions")
        .ok_or("billing portal request")?;
    assert!(portal_request.body.contains("customer=cus_123"));
    assert!(portal_request.body.contains("return_url=%2Faccount"));
    assert!(portal_request
        .body
        .contains("flow_data%5Btype%5D=subscription_update_confirm"));
    assert!(portal_request.body.contains(
        "flow_data%5Bsubscription_update_confirm%5D%5Bsubscription%5D=stripe_sub_active"
    ));
    assert!(portal_request
        .body
        .contains("flow_data%5Bsubscription_update_confirm%5D%5Bitems%5D%5B0%5D%5Bid%5D=si_base"));
    assert!(portal_request.body.contains(
        "flow_data%5Bsubscription_update_confirm%5D%5Bitems%5D%5B0%5D%5Bprice%5D=price_pro"
    ));
    assert!(portal_request
        .body
        .contains("flow_data%5Bsubscription_update_confirm%5D%5Bitems%5D%5B0%5D%5Bquantity%5D=2"));
    assert!(!requests
        .iter()
        .any(|request| request.path == "/v1/checkout/sessions"));
    Ok(())
}

#[tokio::test]
async fn subscription_upgrade_org_seat_plan_portal_omits_item_quantity(
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
        SubscriptionOptions::enabled(vec![StripePlan::new("pro")
            .price_id("price_pro_monthly")
            .annual_discount_price_id("price_pro_yearly")
            .seat_price_id("price_team_seat")])
        .authorize_reference(|input, _| Box::pin(async move { Ok(input.reference_id == "org_1") })),
    );
    let plugin = stripe(options);
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
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
    openauth_core::db::DbAdapter::update(
        &adapter,
        openauth_core::db::Update::new("user")
            .where_clause(openauth_core::db::Where::new(
                "id",
                DbValue::String("user_1".to_owned()),
            ))
            .data("stripe_customer_id", DbValue::String("cus_org".to_owned())),
    )
    .await?;
    create_subscription_record(&adapter, "sub_active", "org_1", "active", Some("cus_org")).await?;
    openauth_core::db::DbAdapter::update(
        &adapter,
        openauth_core::db::Update::new("subscription")
            .where_clause(openauth_core::db::Where::new(
                "id",
                DbValue::String("sub_active".to_owned()),
            ))
            .data("plan", DbValue::String("pro".to_owned()))
            .data(
                "stripe_subscription_id",
                DbValue::String("stripe_sub_active".to_owned()),
            ),
    )
    .await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"customerType":"organization","referenceId":"org_1","plan":"pro","annual":true,"successUrl":"/ok","cancelUrl":"/pricing","disableRedirect":true}"#
                .to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let portal_request = transport
        .requests()?
        .into_iter()
        .find(|request| request.path == "/v1/billing_portal/sessions")
        .ok_or("billing portal request")?;
    assert!(portal_request.body.contains(
        "flow_data%5Bsubscription_update_confirm%5D%5Bitems%5D%5B0%5D%5Bprice%5D=price_pro_yearly"
    ));
    assert!(!portal_request.body.contains("quantity"));
    Ok(())
}

#[tokio::test]
async fn subscription_upgrade_maps_billing_portal_failure_to_plugin_error(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(ActiveUpgradeTransport::with_billing_portal_failure());
    let options = StripeOptions::new(
        StripeClient::with_transport(
            "sk_test",
            Arc::clone(&transport) as Arc<dyn StripeTransport>,
        ),
        "whsec_test",
    )
    .subscription(SubscriptionOptions::enabled(vec![
        StripePlan::new("starter").price_id("price_starter"),
        StripePlan::new("pro").price_id("price_pro"),
    ]));
    let plugin = stripe(options);
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    seed_active_starter_subscription(&adapter).await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"plan":"pro","returnUrl":"/account","successUrl":"/ok","cancelUrl":"/pricing"}"#
                .to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "FAILED_TO_FETCH_PLANS");
    Ok(())
}

#[tokio::test]
async fn subscription_upgrade_uses_direct_update_for_line_item_changes(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(ActiveUpgradeTransport::default());
    let options = StripeOptions::new(
        StripeClient::with_transport(
            "sk_test",
            Arc::clone(&transport) as Arc<dyn StripeTransport>,
        ),
        "whsec_test",
    )
    .subscription(SubscriptionOptions::enabled(vec![
        StripePlan::new("starter")
            .price_id("price_starter")
            .line_item(json!({ "price": "price_starter_events" })),
        StripePlan::new("pro")
            .price_id("price_pro")
            .line_item(json!({ "price": "price_pro_events" }))
            .proration_behavior("always_invoice"),
    ]));
    let plugin = stripe(options);
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    seed_active_starter_subscription(&adapter).await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"plan":"pro","seats":2,"returnUrl":"/account","successUrl":"/ok","cancelUrl":"/pricing"}"#
                .to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["url"], "/account");
    let requests = transport.requests()?;
    let update_request = requests
        .iter()
        .find(|request| request.path == "/v1/subscriptions/stripe_sub_active")
        .ok_or("subscription update request")?;
    assert!(update_request.body.contains("items%5B0%5D%5Bid%5D=si_base"));
    assert!(update_request
        .body
        .contains("items%5B0%5D%5Bprice%5D=price_pro"));
    assert!(update_request.body.contains("items%5B0%5D%5Bquantity%5D=2"));
    assert!(update_request
        .body
        .contains("items%5B1%5D%5Bid%5D=si_events"));
    assert!(update_request
        .body
        .contains("items%5B1%5D%5Bdeleted%5D=true"));
    assert!(update_request
        .body
        .contains("items%5B2%5D%5Bprice%5D=price_pro_events"));
    assert!(update_request
        .body
        .contains("proration_behavior=always_invoice"));
    assert!(!requests
        .iter()
        .any(|request| request.path == "/v1/billing_portal/sessions"));
    assert!(!requests
        .iter()
        .any(|request| request.path == "/v1/checkout/sessions"));
    Ok(())
}

#[tokio::test]
async fn subscription_upgrade_allows_same_local_plan_when_stripe_price_differs(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(ActiveUpgradeTransport::default());
    let options = StripeOptions::new(
        StripeClient::with_transport(
            "sk_test",
            Arc::clone(&transport) as Arc<dyn StripeTransport>,
        ),
        "whsec_test",
    )
    .subscription(SubscriptionOptions::enabled(vec![
        StripePlan::new("starter").price_id("price_starter"),
        StripePlan::new("pro").price_id("price_pro"),
    ]));
    let plugin = stripe(options);
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    seed_active_starter_subscription(&adapter).await?;
    openauth_core::db::DbAdapter::update(
        &adapter,
        openauth_core::db::Update::new("subscription")
            .where_clause(openauth_core::db::Where::new(
                "id",
                DbValue::String("sub_active".to_owned()),
            ))
            .data("plan", DbValue::String("pro".to_owned())),
    )
    .await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"plan":"pro","returnUrl":"/account","successUrl":"/ok","cancelUrl":"/pricing"}"#
                .to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let requests = transport.requests()?;
    assert!(requests
        .iter()
        .any(|request| request.path == "/v1/billing_portal/sessions"));
    Ok(())
}

#[tokio::test]
async fn subscription_upgrade_allows_same_plan_when_local_period_has_expired(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(ActiveUpgradeTransport::default());
    let options = StripeOptions::new(
        StripeClient::with_transport(
            "sk_test",
            Arc::clone(&transport) as Arc<dyn StripeTransport>,
        ),
        "whsec_test",
    )
    .subscription(SubscriptionOptions::enabled(vec![StripePlan::new(
        "starter",
    )
    .price_id("price_starter")]));
    let plugin = stripe(options);
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    seed_active_starter_subscription(&adapter).await?;
    openauth_core::db::DbAdapter::update(
        &adapter,
        openauth_core::db::Update::new("subscription")
            .where_clause(openauth_core::db::Where::new(
                "id",
                DbValue::String("sub_active".to_owned()),
            ))
            .data(
                "period_end",
                DbValue::Timestamp(OffsetDateTime::now_utc() - Duration::days(1)),
            ),
    )
    .await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"plan":"starter","returnUrl":"/account","successUrl":"/ok","cancelUrl":"/pricing"}"#
                .to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(transport
        .requests()?
        .iter()
        .any(|request| request.path == "/v1/billing_portal/sessions"));
    Ok(())
}

#[tokio::test]
async fn subscription_upgrade_schedules_period_end_change_and_stores_schedule_id(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(ActiveUpgradeTransport::default());
    let options = StripeOptions::new(
        StripeClient::with_transport(
            "sk_test",
            Arc::clone(&transport) as Arc<dyn StripeTransport>,
        ),
        "whsec_test",
    )
    .subscription(SubscriptionOptions::enabled(vec![
        StripePlan::new("starter")
            .price_id("price_starter")
            .line_item(json!({ "price": "price_starter_events" })),
        StripePlan::new("pro")
            .price_id("price_pro")
            .line_item(json!({ "price": "price_pro_events" })),
    ]));
    let plugin = stripe(options);
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    seed_active_starter_subscription(&adapter).await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"plan":"pro","scheduleAtPeriodEnd":true,"returnUrl":"/account","successUrl":"/ok","cancelUrl":"/pricing"}"#
                .to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["url"], "/account");
    let requests = transport.requests()?;
    let create_schedule = requests
        .iter()
        .find(|request| request.path == "/v1/subscription_schedules")
        .ok_or("schedule create request")?;
    assert!(create_schedule
        .body
        .contains("from_subscription=stripe_sub_active"));
    let update_schedule = requests
        .iter()
        .find(|request| request.path == "/v1/subscription_schedules/sched_new")
        .ok_or("schedule update request")?;
    assert!(update_schedule
        .body
        .contains("metadata%5Bsource%5D=%40better-auth%2Fstripe"));
    assert!(update_schedule.body.contains("end_behavior=release"));
    assert!(update_schedule
        .body
        .contains("phases%5B0%5D%5Bitems%5D%5B0%5D%5Bprice%5D=price_starter"));
    assert!(!update_schedule
        .body
        .contains("phases%5B0%5D%5Bitems%5D%5B0%5D%5Bprice%5D%5Bid%5D"));
    assert!(update_schedule
        .body
        .contains("phases%5B1%5D%5Bitems%5D%5B0%5D%5Bprice%5D=price_pro"));
    assert!(update_schedule
        .body
        .contains("phases%5B1%5D%5Bitems%5D%5B1%5D%5Bprice%5D=price_pro_events"));
    let records = adapter.records("subscription").await;
    let subscription = records
        .iter()
        .find(|record| record.get("id") == Some(&DbValue::String("sub_active".to_owned())))
        .ok_or("subscription")?;
    assert_eq!(
        subscription.get("stripe_schedule_id"),
        Some(&DbValue::String("sched_new".to_owned()))
    );
    assert_eq!(
        subscription.get("plan"),
        Some(&DbValue::String("starter".to_owned()))
    );
    assert!(!requests
        .iter()
        .any(|request| request.path == "/v1/billing_portal/sessions"));
    Ok(())
}

#[tokio::test]
async fn subscription_upgrade_releases_orphan_schedule_when_period_end_update_fails(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(ActiveUpgradeTransport::with_schedule_update_failure());
    let options = StripeOptions::new(
        StripeClient::with_transport(
            "sk_test",
            Arc::clone(&transport) as Arc<dyn StripeTransport>,
        ),
        "whsec_test",
    )
    .subscription(SubscriptionOptions::enabled(vec![
        StripePlan::new("starter")
            .price_id("price_starter")
            .line_item(json!({ "price": "price_starter_events" })),
        StripePlan::new("pro")
            .price_id("price_pro")
            .line_item(json!({ "price": "price_pro_events" })),
    ]));
    let plugin = stripe(options);
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    seed_active_starter_subscription(&adapter).await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"plan":"pro","scheduleAtPeriodEnd":true,"returnUrl":"/account","successUrl":"/ok","cancelUrl":"/pricing"}"#
                .to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "FAILED_TO_FETCH_PLANS");
    let requests = transport.requests()?;
    assert!(requests.iter().any(|request| {
        request.path == "/v1/subscription_schedules" && request.method == "POST"
    }));
    assert!(requests.iter().any(|request| {
        request.path == "/v1/subscription_schedules/sched_new" && request.method == "POST"
    }));
    assert!(requests
        .iter()
        .any(|request| request.path == "/v1/subscription_schedules/sched_new/release"));
    let records = adapter.records("subscription").await;
    let subscription = records
        .iter()
        .find(|record| record.get("id") == Some(&DbValue::String("sub_active".to_owned())))
        .ok_or("subscription")?;
    assert_eq!(subscription.get("stripe_schedule_id"), Some(&DbValue::Null));
    Ok(())
}

#[tokio::test]
async fn subscription_upgrade_persists_schedule_id_when_period_end_cleanup_release_fails(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(ActiveUpgradeTransport::with_schedule_update_and_release_failure());
    let options = StripeOptions::new(
        StripeClient::with_transport(
            "sk_test",
            Arc::clone(&transport) as Arc<dyn StripeTransport>,
        ),
        "whsec_test",
    )
    .subscription(SubscriptionOptions::enabled(vec![
        StripePlan::new("starter")
            .price_id("price_starter")
            .line_item(json!({ "price": "price_starter_events" })),
        StripePlan::new("pro")
            .price_id("price_pro")
            .line_item(json!({ "price": "price_pro_events" })),
    ]));
    let plugin = stripe(options);
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    seed_active_starter_subscription(&adapter).await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"plan":"pro","scheduleAtPeriodEnd":true,"returnUrl":"/account","successUrl":"/ok","cancelUrl":"/pricing"}"#
                .to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "FAILED_TO_FETCH_PLANS");
    let records = adapter.records("subscription").await;
    let subscription = records
        .iter()
        .find(|record| record.get("id") == Some(&DbValue::String("sub_active".to_owned())))
        .ok_or("subscription")?;
    assert_eq!(
        subscription.get("stripe_schedule_id"),
        Some(&DbValue::String("sched_new".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn subscription_upgrade_omits_quantity_for_metered_price_in_scheduled_phase(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(ActiveUpgradeTransport::default());
    let options = StripeOptions::new(
        StripeClient::with_transport(
            "sk_test",
            Arc::clone(&transport) as Arc<dyn StripeTransport>,
        ),
        "whsec_test",
    )
    .subscription(SubscriptionOptions::enabled(vec![
        StripePlan::new("starter").price_id("price_starter"),
        StripePlan::new("metered").price_id("price_metered_scheduled"),
    ]));
    let plugin = stripe(options);
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    seed_active_starter_subscription(&adapter).await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"plan":"metered","scheduleAtPeriodEnd":true,"returnUrl":"/account","successUrl":"/ok","cancelUrl":"/pricing"}"#
                .to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let requests = transport.requests()?;
    let update_schedule = requests
        .iter()
        .find(|request| request.path == "/v1/subscription_schedules/sched_new")
        .ok_or("schedule update request")?;
    assert!(update_schedule
        .body
        .contains("phases%5B1%5D%5Bitems%5D%5B0%5D%5Bprice%5D=price_metered_scheduled"));
    assert!(!update_schedule
        .body
        .contains("phases%5B1%5D%5Bitems%5D%5B0%5D%5Bquantity%5D"));
    Ok(())
}

#[tokio::test]
async fn subscription_upgrade_preserves_duplicate_line_item_multiset_delta(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(DuplicateLineItemTransport::default());
    let options = StripeOptions::new(
        StripeClient::with_transport(
            "sk_test",
            Arc::clone(&transport) as Arc<dyn StripeTransport>,
        ),
        "whsec_test",
    )
    .subscription(SubscriptionOptions::enabled(vec![
        StripePlan::new("starter")
            .price_id("price_starter")
            .line_item(json!({ "price": "price_events" }))
            .line_item(json!({ "price": "price_events" })),
        StripePlan::new("pro")
            .price_id("price_pro")
            .line_item(json!({ "price": "price_events" })),
    ]));
    let plugin = stripe(options);
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    seed_active_starter_subscription(&adapter).await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"plan":"pro","returnUrl":"/account","successUrl":"/ok","cancelUrl":"/pricing"}"#
                .to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let requests = transport.requests()?;
    let update_request = requests
        .iter()
        .find(|request| request.path == "/v1/subscriptions/stripe_sub_active")
        .ok_or("subscription update request")?;
    assert_eq!(update_request.body.matches("%5Bdeleted%5D=true").count(), 1);
    assert!(!update_request.body.contains("=price_events"));
    Ok(())
}

#[tokio::test]
async fn subscription_upgrade_does_not_add_destination_line_item_already_present(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(StaleDestinationLineItemTransport::default());
    let options = asymmetric_line_item_options(Arc::clone(&transport) as Arc<dyn StripeTransport>);
    let plugin = stripe(options);
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    seed_active_basic_subscription(&adapter).await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"plan":"premium","returnUrl":"/account","successUrl":"/ok","cancelUrl":"/pricing"}"#
                .to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let requests = transport.requests()?;
    let update_request = requests
        .iter()
        .find(|request| request.path == "/v1/subscriptions/stripe_sub_active")
        .ok_or("subscription update request")?;
    assert_eq!(
        update_request
            .body
            .matches("=price_premium_security")
            .count(),
        0
    );
    assert!(update_request
        .body
        .contains("items%5B0%5D%5Bprice%5D=price_premium_base"));
    assert!(update_request.body.contains("=price_premium_events"));
    Ok(())
}

#[tokio::test]
async fn subscription_upgrade_does_not_duplicate_destination_line_item_in_scheduled_phase(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(StaleDestinationLineItemTransport::default());
    let options = asymmetric_line_item_options(Arc::clone(&transport) as Arc<dyn StripeTransport>);
    let plugin = stripe(options);
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    seed_active_basic_subscription(&adapter).await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"plan":"premium","scheduleAtPeriodEnd":true,"returnUrl":"/account","successUrl":"/ok","cancelUrl":"/pricing"}"#
                .to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let requests = transport.requests()?;
    let update_schedule = requests
        .iter()
        .find(|request| request.path == "/v1/subscription_schedules/sched_new")
        .ok_or("schedule update request")?;
    assert_eq!(
        update_schedule
            .body
            .matches("phases%5B1%5D%5Bitems%5D")
            .count(),
        3
    );
    assert_eq!(
        update_schedule
            .body
            .matches("price_premium_security")
            .count(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn subscription_upgrade_releases_existing_plugin_schedule_before_immediate_change(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(ActiveUpgradeTransport::with_plugin_schedule());
    let options = StripeOptions::new(
        StripeClient::with_transport(
            "sk_test",
            Arc::clone(&transport) as Arc<dyn StripeTransport>,
        ),
        "whsec_test",
    )
    .subscription(SubscriptionOptions::enabled(vec![
        StripePlan::new("starter").price_id("price_starter"),
        StripePlan::new("pro").price_id("price_pro"),
    ]));
    let plugin = stripe(options);
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    seed_active_starter_subscription(&adapter).await?;
    openauth_core::db::DbAdapter::update(
        &adapter,
        openauth_core::db::Update::new("subscription")
            .where_clause(openauth_core::db::Where::new(
                "id",
                DbValue::String("sub_active".to_owned()),
            ))
            .data(
                "stripe_schedule_id",
                DbValue::String("sched_existing".to_owned()),
            ),
    )
    .await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"plan":"pro","returnUrl":"/account","successUrl":"/ok","cancelUrl":"/pricing"}"#
                .to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let requests = transport.requests()?;
    assert!(requests.iter().any(|request| {
        request.path == "/v1/subscription_schedules" && request.method == "GET"
    }));
    assert!(requests
        .iter()
        .any(|request| request.path == "/v1/subscription_schedules/sched_existing/release"));
    let records = adapter.records("subscription").await;
    let subscription = records
        .iter()
        .find(|record| record.get("id") == Some(&DbValue::String("sub_active".to_owned())))
        .ok_or("subscription")?;
    assert_eq!(subscription.get("stripe_schedule_id"), Some(&DbValue::Null));
    assert!(requests
        .iter()
        .any(|request| request.path == "/v1/billing_portal/sessions"));
    Ok(())
}

#[tokio::test]
async fn subscription_upgrade_does_not_release_external_schedule_before_immediate_change(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(ActiveUpgradeTransport::with_external_schedule());
    let options = StripeOptions::new(
        StripeClient::with_transport(
            "sk_test",
            Arc::clone(&transport) as Arc<dyn StripeTransport>,
        ),
        "whsec_test",
    )
    .subscription(SubscriptionOptions::enabled(vec![
        StripePlan::new("starter").price_id("price_starter"),
        StripePlan::new("pro").price_id("price_pro"),
    ]));
    let plugin = stripe(options);
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    seed_active_starter_subscription(&adapter).await?;
    openauth_core::db::DbAdapter::update(
        &adapter,
        openauth_core::db::Update::new("subscription")
            .where_clause(openauth_core::db::Where::new(
                "id",
                DbValue::String("sub_active".to_owned()),
            ))
            .data(
                "stripe_schedule_id",
                DbValue::String("sched_existing".to_owned()),
            ),
    )
    .await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"plan":"pro","returnUrl":"/account","successUrl":"/ok","cancelUrl":"/pricing"}"#
                .to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let requests = transport.requests()?;
    assert!(requests.iter().any(|request| {
        request.path == "/v1/subscription_schedules" && request.method == "GET"
    }));
    assert!(!requests
        .iter()
        .any(|request| request.path == "/v1/subscription_schedules/sched_existing/release"));
    Ok(())
}

#[tokio::test]
async fn subscription_upgrade_swaps_seat_item_without_duplicating_base_price(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(ActiveUpgradeTransport::with_seat_item());
    let options = StripeOptions::new(
        StripeClient::with_transport(
            "sk_test",
            Arc::clone(&transport) as Arc<dyn StripeTransport>,
        ),
        "whsec_test",
    )
    .subscription(SubscriptionOptions::enabled(vec![
        StripePlan::new("starter")
            .price_id("price_starter")
            .seat_price_id("price_starter_seats"),
        StripePlan::new("pro")
            .price_id("price_pro")
            .seat_price_id("price_pro_seats"),
    ]));
    let plugin = stripe(options);
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    seed_active_starter_subscription(&adapter).await?;
    openauth_core::db::DbAdapter::update(
        &adapter,
        openauth_core::db::Update::new("subscription")
            .where_clause(openauth_core::db::Where::new(
                "id",
                DbValue::String("sub_active".to_owned()),
            ))
            .data("seats", DbValue::Number(3)),
    )
    .await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"plan":"pro","seats":5,"returnUrl":"/account","successUrl":"/ok","cancelUrl":"/pricing"}"#
                .to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let requests = transport.requests()?;
    let update_request = requests
        .iter()
        .find(|request| request.path == "/v1/subscriptions/stripe_sub_active")
        .ok_or("subscription update request")?;
    assert!(update_request.body.contains("items%5B0%5D%5Bid%5D=si_base"));
    assert!(update_request
        .body
        .contains("items%5B0%5D%5Bprice%5D=price_pro"));
    assert!(update_request.body.contains("items%5B0%5D%5Bquantity%5D=1"));
    assert!(update_request
        .body
        .contains("items%5B1%5D%5Bid%5D=si_seats"));
    assert!(update_request
        .body
        .contains("items%5B1%5D%5Bprice%5D=price_pro_seats"));
    assert!(update_request.body.contains("items%5B1%5D%5Bquantity%5D=5"));
    assert!(!update_request.body.contains("price_starter_seats"));
    Ok(())
}

#[tokio::test]
async fn subscription_upgrade_allows_same_plan_seat_count_change(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(ActiveUpgradeTransport::with_seat_item());
    let options = StripeOptions::new(
        StripeClient::with_transport(
            "sk_test",
            Arc::clone(&transport) as Arc<dyn StripeTransport>,
        ),
        "whsec_test",
    )
    .subscription(SubscriptionOptions::enabled(vec![StripePlan::new(
        "starter",
    )
    .price_id("price_starter")
    .seat_price_id("price_starter_seats")]));
    let plugin = stripe(options);
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    seed_active_starter_subscription(&adapter).await?;
    openauth_core::db::DbAdapter::update(
        &adapter,
        openauth_core::db::Update::new("subscription")
            .where_clause(openauth_core::db::Where::new(
                "id",
                DbValue::String("sub_active".to_owned()),
            ))
            .data("seats", DbValue::Number(3)),
    )
    .await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"plan":"starter","seats":5,"returnUrl":"/account","successUrl":"/ok","cancelUrl":"/pricing"}"#
                .to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let requests = transport.requests()?;
    let update_request = requests
        .iter()
        .find(|request| request.path == "/v1/subscriptions/stripe_sub_active")
        .ok_or("subscription update request")?;
    assert!(update_request
        .body
        .contains("items%5B1%5D%5Bid%5D=si_seats"));
    assert!(update_request
        .body
        .contains("items%5B1%5D%5Bprice%5D=price_starter_seats"));
    assert!(update_request.body.contains("items%5B1%5D%5Bquantity%5D=5"));
    Ok(())
}

async fn seed_active_starter_subscription(
    adapter: &MemoryAdapter,
) -> Result<(), Box<dyn std::error::Error>> {
    openauth_core::db::DbAdapter::update(
        adapter,
        openauth_core::db::Update::new("user")
            .where_clause(openauth_core::db::Where::new(
                "id",
                DbValue::String("user_1".to_owned()),
            ))
            .data("stripe_customer_id", DbValue::String("cus_123".to_owned())),
    )
    .await?;
    create_subscription_record(adapter, "sub_active", "user_1", "active", Some("cus_123")).await?;
    openauth_core::db::DbAdapter::update(
        adapter,
        openauth_core::db::Update::new("subscription")
            .where_clause(openauth_core::db::Where::new(
                "id",
                DbValue::String("sub_active".to_owned()),
            ))
            .data("plan", DbValue::String("starter".to_owned()))
            .data(
                "stripe_subscription_id",
                DbValue::String("stripe_sub_active".to_owned()),
            ),
    )
    .await?;
    Ok(())
}

async fn seed_active_basic_subscription(
    adapter: &MemoryAdapter,
) -> Result<(), Box<dyn std::error::Error>> {
    seed_active_starter_subscription(adapter).await?;
    openauth_core::db::DbAdapter::update(
        adapter,
        openauth_core::db::Update::new("subscription")
            .where_clause(openauth_core::db::Where::new(
                "id",
                DbValue::String("sub_active".to_owned()),
            ))
            .data("plan", DbValue::String("basic".to_owned())),
    )
    .await?;
    Ok(())
}

fn asymmetric_line_item_options(transport: Arc<dyn StripeTransport>) -> StripeOptions {
    StripeOptions::new(
        StripeClient::with_transport("sk_test", transport),
        "whsec_test",
    )
    .subscription(SubscriptionOptions::enabled(vec![
        StripePlan::new("basic")
            .price_id("price_basic_base")
            .line_item(json!({ "price": "price_basic_events" })),
        StripePlan::new("premium")
            .price_id("price_premium_base")
            .line_item(json!({ "price": "price_premium_events" }))
            .line_item(json!({ "price": "price_premium_security" })),
    ]))
}
