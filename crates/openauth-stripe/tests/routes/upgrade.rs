use super::*;
use openauth_stripe::options::FreeTrialOptions;

#[tokio::test]
async fn subscription_upgrade_rejects_unauthenticated_requests(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin = stripe(
        StripeOptions::new(StripeClient::new("sk_test"), "whsec_test").subscription(
            SubscriptionOptions::enabled(vec![StripePlan::new("pro").price_id("price_pro")]),
        ),
    )
    .unwrap();
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let context = create_auth_context(OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .body(br#"{"plan":"pro","successUrl":"/ok","cancelUrl":"/pricing"}"#.to_vec())?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn subscription_upgrade_creates_local_subscription_and_checkout_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let plugin = stripe(stripe_options(Arc::clone(&transport))).unwrap();
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"plan":"pro","successUrl":"/ok","cancelUrl":"/pricing","disableRedirect":true}"#
                .to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["id"], "cs_test_123");
    assert_eq!(body["redirect"], false);
    let subscriptions = adapter.records("subscription").await;
    assert_eq!(subscriptions.len(), 1);
    assert_eq!(
        subscriptions[0].get("reference_id"),
        Some(&DbValue::String("user_1".to_owned()))
    );
    assert_eq!(
        subscriptions[0].get("status"),
        Some(&DbValue::String("incomplete".to_owned()))
    );
    let subscription_id = match subscriptions[0].get("id") {
        Some(DbValue::String(id)) => id,
        _ => return Err("subscription id missing".into()),
    };
    let requests = transport.requests()?;
    let checkout_request = requests
        .iter()
        .find(|request| request.path == "/v1/checkout/sessions")
        .ok_or("checkout request")?;
    assert!(checkout_request
        .body
        .contains("line_items%5B0%5D%5Bprice%5D=price_pro"));
    assert!(checkout_request
        .body
        .contains("customer_update%5Bname%5D=auto"));
    assert!(checkout_request
        .body
        .contains("customer_update%5Baddress%5D=auto"));
    assert!(checkout_request
        .body
        .contains("subscription_data%5Bmetadata%5D%5BuserId%5D=user_1"));
    assert!(checkout_request.body.contains(&format!(
        "subscription_data%5Bmetadata%5D%5BsubscriptionId%5D={subscription_id}"
    )));
    assert!(checkout_request
        .body
        .contains("subscription_data%5Bmetadata%5D%5BreferenceId%5D=user_1"));
    Ok(())
}

#[tokio::test]
async fn subscription_upgrade_rejects_other_reference_without_authorizer(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let plugin = stripe(stripe_options(transport)).unwrap();
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, _adapter, cookie_header) = authenticated_context().await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"plan":"pro","referenceId":"user_2","successUrl":"/ok","cancelUrl":"/pricing"}"#
                .to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "REFERENCE_ID_NOT_ALLOWED");
    Ok(())
}

#[tokio::test]
async fn subscription_upgrade_requires_verified_email_when_configured(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let options = StripeOptions::new(
        StripeClient::with_transport("sk_test", transport),
        "whsec_test",
    )
    .subscription(
        SubscriptionOptions::enabled(vec![StripePlan::new("pro").price_id("price_pro")])
            .require_email_verification(true),
    );
    let plugin = stripe(options).unwrap();
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, _adapter, cookie_header) =
        authenticated_context_with_email_verified(false).await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(br#"{"plan":"pro","successUrl":"/ok","cancelUrl":"/pricing"}"#.to_vec())?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "EMAIL_VERIFICATION_REQUIRED");
    Ok(())
}

#[tokio::test]
async fn subscription_upgrade_maps_dynamic_plan_provider_failure(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let options = StripeOptions::new(
        StripeClient::with_transport("sk_test", transport),
        "whsec_test",
    )
    .subscription(SubscriptionOptions::enabled_dynamic(|| {
        Box::pin(async { Err::<Vec<StripePlan>, _>(OpenAuthError::Api("plans failed".to_owned())) })
    }));
    let plugin = stripe(options).unwrap();
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, _adapter, cookie_header) = authenticated_context().await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(br#"{"plan":"pro","successUrl":"/ok","cancelUrl":"/pricing"}"#.to_vec())?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "FAILED_TO_FETCH_PLANS");
    Ok(())
}

#[tokio::test]
async fn subscription_upgrade_rejects_same_active_plan_and_interval(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let plugin = stripe(stripe_options(Arc::clone(&transport))).unwrap();
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    create_subscription_record(&adapter, "sub_active", "user_1", "active", Some("cus_123")).await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(br#"{"plan":"pro","successUrl":"/ok","cancelUrl":"/pricing"}"#.to_vec())?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "ALREADY_SUBSCRIBED_PLAN");
    assert!(transport
        .requests()?
        .iter()
        .all(|request| request.path != "/v1/checkout/sessions"));
    Ok(())
}

#[tokio::test]
async fn subscription_upgrade_creates_checkout_when_local_active_has_no_stripe_subscription(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let plugin = stripe(stripe_options(Arc::clone(&transport))).unwrap();
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
    create_subscription_record(&adapter, "sub_local", "user_1", "active", Some("cus_123")).await?;
    openauth_core::db::DbAdapter::update(
        &adapter,
        openauth_core::db::Update::new("subscription")
            .where_clause(openauth_core::db::Where::new(
                "id",
                DbValue::String("sub_local".to_owned()),
            ))
            .data("stripe_subscription_id", DbValue::Null),
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
    assert!(transport
        .requests()?
        .iter()
        .any(|request| request.path == "/v1/checkout/sessions"));
    Ok(())
}

#[tokio::test]
async fn subscription_upgrade_rejects_cross_reference_subscription_id_before_stripe(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let plugin = stripe(stripe_options(Arc::clone(&transport))).unwrap();
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    create_subscription_record(&adapter, "sub_other", "user_2", "active", Some("cus_other"))
        .await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"plan":"pro","subscriptionId":"stripe_sub_other","successUrl":"/ok","cancelUrl":"/pricing"}"#
                .to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "SUBSCRIPTION_NOT_FOUND");
    assert!(transport.requests()?.is_empty());
    Ok(())
}

#[tokio::test]
async fn subscription_upgrade_allows_monthly_to_annual_same_plan(
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
        .price_id("price_pro_monthly")
        .annual_discount_price_id("price_pro_yearly")]));
    let plugin = stripe(options).unwrap();
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    create_subscription_record(&adapter, "sub_active", "user_1", "active", Some("cus_123")).await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"plan":"pro","annual":true,"successUrl":"/ok","cancelUrl":"/pricing"}"#.to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let requests = transport.requests()?;
    let portal_request = requests
        .iter()
        .find(|request| request.path == "/v1/billing_portal/sessions")
        .ok_or("billing portal request")?;
    assert!(portal_request
        .body
        .contains("flow_data%5Btype%5D=subscription_update_confirm"));
    assert!(portal_request.body.contains(
        "flow_data%5Bsubscription_update_confirm%5D%5Bitems%5D%5B0%5D%5Bprice%5D=price_pro_yearly"
    ));
    assert!(!requests
        .iter()
        .any(|request| request.path == "/v1/checkout/sessions"));
    Ok(())
}

#[tokio::test]
async fn subscription_upgrade_uses_requested_seats_for_licensed_price(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let plugin = stripe(stripe_options(Arc::clone(&transport))).unwrap();
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(br#"{"plan":"pro","seats":3,"successUrl":"/ok","cancelUrl":"/pricing"}"#.to_vec())?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        adapter.records("subscription").await[0].get("seats"),
        Some(&DbValue::Number(3))
    );
    let requests = transport.requests()?;
    let checkout_request = requests
        .iter()
        .find(|request| request.path == "/v1/checkout/sessions")
        .ok_or("checkout request")?;
    assert!(checkout_request
        .body
        .contains("line_items%5B0%5D%5Bquantity%5D=3"));
    Ok(())
}

#[tokio::test]
async fn subscription_upgrade_omits_quantity_for_metered_base_price(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let options = StripeOptions::new(
        StripeClient::with_transport(
            "sk_test",
            Arc::clone(&transport) as Arc<dyn StripeTransport>,
        ),
        "whsec_test",
    )
    .subscription(SubscriptionOptions::enabled(vec![StripePlan::new(
        "metered",
    )
    .price_id("price_metered")]));
    let plugin = stripe(options).unwrap();
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, _adapter, cookie_header) = authenticated_context().await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"plan":"metered","seats":3,"successUrl":"/ok","cancelUrl":"/pricing"}"#.to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let requests = transport.requests()?;
    let checkout_request = requests
        .iter()
        .find(|request| request.path == "/v1/checkout/sessions")
        .ok_or("checkout request")?;
    assert!(checkout_request
        .body
        .contains("line_items%5B0%5D%5Bprice%5D=price_metered"));
    assert!(!checkout_request
        .body
        .contains("line_items%5B0%5D%5Bquantity%5D"));
    Ok(())
}

#[tokio::test]
async fn subscription_upgrade_adds_seat_price_line_item() -> Result<(), Box<dyn std::error::Error>>
{
    let transport = Arc::new(CaptureTransport::default());
    let options = StripeOptions::new(
        StripeClient::with_transport(
            "sk_test",
            Arc::clone(&transport) as Arc<dyn StripeTransport>,
        ),
        "whsec_test",
    )
    .subscription(SubscriptionOptions::enabled(vec![StripePlan::new("team")
        .price_id("price_team_base")
        .seat_price_id("price_team_seat")]));
    let plugin = stripe(options).unwrap();
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, _adapter, cookie_header) = authenticated_context().await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(br#"{"plan":"team","seats":5,"successUrl":"/ok","cancelUrl":"/pricing"}"#.to_vec())?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let requests = transport.requests()?;
    let checkout_request = requests
        .iter()
        .find(|request| request.path == "/v1/checkout/sessions")
        .ok_or("checkout request")?;
    assert!(checkout_request
        .body
        .contains("line_items%5B0%5D%5Bprice%5D=price_team_base"));
    assert!(checkout_request
        .body
        .contains("line_items%5B0%5D%5Bquantity%5D=1"));
    assert!(checkout_request
        .body
        .contains("line_items%5B1%5D%5Bprice%5D=price_team_seat"));
    assert!(checkout_request
        .body
        .contains("line_items%5B1%5D%5Bquantity%5D=5"));
    Ok(())
}

#[tokio::test]
async fn subscription_upgrade_for_organization_uses_member_count_for_seat_quantity(
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
        SubscriptionOptions::enabled(vec![StripePlan::new("team")
            .price_id("price_team_base")
            .seat_price_id("price_team_seat")])
        .authorize_reference(|input, _| {
            Box::pin(async move {
                Ok(input.reference_id == "org_1"
                    && input.action
                        == openauth_stripe::options::AuthorizeReferenceAction::UpgradeSubscription)
            })
        }),
    );
    let plugin = stripe(options).unwrap();
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
    for member_id in ["mem_1", "mem_2", "mem_3"] {
        adapter
            .create(
                Create::new("member")
                    .data("id", DbValue::String(member_id.to_owned()))
                    .data("organization_id", DbValue::String("org_1".to_owned()))
                    .data("user_id", DbValue::String(format!("user_{member_id}")))
                    .force_allow_id(),
            )
            .await?;
    }
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"customerType":"organization","referenceId":"org_1","plan":"team","seats":9,"successUrl":"/ok","cancelUrl":"/pricing"}"#.to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let subscriptions = adapter.records("subscription").await;
    assert_eq!(subscriptions[0].get("seats"), Some(&DbValue::Number(3)));
    let requests = transport.requests()?;
    let checkout_request = requests
        .iter()
        .find(|request| request.path == "/v1/checkout/sessions")
        .ok_or("checkout request")?;
    assert!(checkout_request
        .body
        .contains("line_items%5B0%5D%5Bquantity%5D=1"));
    assert!(checkout_request
        .body
        .contains("line_items%5B1%5D%5Bprice%5D=price_team_seat"));
    assert!(checkout_request
        .body
        .contains("line_items%5B1%5D%5Bquantity%5D=3"));
    assert!(!checkout_request
        .body
        .contains("line_items%5B1%5D%5Bquantity%5D=9"));
    Ok(())
}

#[tokio::test]
async fn subscription_upgrade_for_organization_seat_only_plan_does_not_duplicate_price(
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
        SubscriptionOptions::enabled(vec![StripePlan::new("starter")
            .price_id("price_same")
            .seat_price_id("price_same")
            .line_item(json!({ "price": "price_meter_api" }))])
        .authorize_reference(|input, _| {
            Box::pin(async move {
                Ok(input.reference_id == "org_1"
                    && input.action
                        == openauth_stripe::options::AuthorizeReferenceAction::UpgradeSubscription)
            })
        }),
    );
    let plugin = stripe(options).unwrap();
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
    adapter
        .create(
            Create::new("member")
                .data("id", DbValue::String("mem_1".to_owned()))
                .data("organization_id", DbValue::String("org_1".to_owned()))
                .data("user_id", DbValue::String("user_1".to_owned()))
                .force_allow_id(),
        )
        .await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"customerType":"organization","referenceId":"org_1","plan":"starter","successUrl":"/ok","cancelUrl":"/pricing"}"#.to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let requests = transport.requests()?;
    let checkout_request = requests
        .iter()
        .find(|request| request.path == "/v1/checkout/sessions")
        .ok_or("checkout request")?;
    assert!(checkout_request
        .body
        .contains("line_items%5B0%5D%5Bprice%5D=price_same"));
    assert!(checkout_request
        .body
        .contains("line_items%5B0%5D%5Bquantity%5D=1"));
    assert!(checkout_request
        .body
        .contains("line_items%5B1%5D%5Bprice%5D=price_meter_api"));
    assert!(!checkout_request
        .body
        .contains("line_items%5B1%5D%5Bprice%5D=price_same"));
    assert!(!checkout_request
        .body
        .contains("line_items%5B2%5D%5Bprice%5D=price_meter_api"));
    Ok(())
}

#[tokio::test]
async fn subscription_upgrade_allows_other_reference_with_authorizer(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let plugin = stripe(stripe_options_with_authorized_references(Arc::clone(
        &transport,
    )))
    .unwrap();
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"plan":"pro","referenceId":"user_2","successUrl":"/ok","cancelUrl":"/pricing"}"#
                .to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let subscriptions = adapter.records("subscription").await;
    assert_eq!(subscriptions.len(), 1);
    assert_eq!(
        subscriptions[0].get("reference_id"),
        Some(&DbValue::String("user_2".to_owned()))
    );
    let requests = transport.requests()?;
    let checkout_request = requests
        .iter()
        .find(|request| request.path == "/v1/checkout/sessions")
        .ok_or("checkout request")?;
    assert!(checkout_request
        .body
        .contains("subscription_data%5Bmetadata%5D%5BuserId%5D=user_1"));
    assert!(checkout_request
        .body
        .contains("subscription_data%5Bmetadata%5D%5BreferenceId%5D=user_2"));
    Ok(())
}

#[tokio::test]
async fn subscription_upgrade_for_organization_uses_organization_customer(
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
                            == openauth_stripe::options::AuthorizeReferenceAction::UpgradeSubscription)
                })
            }),
    );
    let plugin = stripe(options).unwrap();
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
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"customerType":"organization","referenceId":"org_1","plan":"pro","successUrl":"/ok","cancelUrl":"/pricing"}"#
                .to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let subscriptions = adapter.records("subscription").await;
    assert_eq!(
        subscriptions[0].get("reference_id"),
        Some(&DbValue::String("org_1".to_owned()))
    );
    assert_eq!(
        subscriptions[0].get("stripe_customer_id"),
        Some(&DbValue::String("cus_org".to_owned()))
    );
    let requests = transport.requests()?;
    let checkout_request = requests
        .iter()
        .find(|request| request.path == "/v1/checkout/sessions")
        .ok_or("checkout request")?;
    assert!(checkout_request.body.contains("customer=cus_org"));
    assert!(checkout_request
        .body
        .contains("subscription_data%5Bmetadata%5D%5BuserId%5D=user_1"));
    assert!(checkout_request
        .body
        .contains("subscription_data%5Bmetadata%5D%5BreferenceId%5D=org_1"));
    assert!(!requests
        .iter()
        .any(|request| request.path == "/v1/customers"));
    Ok(())
}

#[tokio::test]
async fn subscription_upgrade_for_organization_returns_not_found_without_stripe_request(
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
                    Ok(input.reference_id == "org_missing"
                        && input.action
                            == openauth_stripe::options::AuthorizeReferenceAction::UpgradeSubscription)
                })
            }),
    );
    let plugin = stripe(options).unwrap();
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, _adapter, cookie_header) = authenticated_context().await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"customerType":"organization","referenceId":"org_missing","plan":"pro","successUrl":"/ok","cancelUrl":"/pricing"}"#
                .to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "ORGANIZATION_NOT_FOUND");
    assert!(transport.requests()?.is_empty());
    Ok(())
}

#[tokio::test]
async fn subscription_upgrade_forwards_metadata_without_overriding_internal_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let plugin = stripe(stripe_options(Arc::clone(&transport))).unwrap();
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, _adapter, cookie_header) = authenticated_context().await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"plan":"pro","successUrl":"/ok","cancelUrl":"/pricing","metadata":{"campaign":"spring","userId":"evil","__proto__":"polluted"}}"#
                .to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let requests = transport.requests()?;
    let checkout_request = requests
        .iter()
        .find(|request| request.path == "/v1/checkout/sessions")
        .ok_or("checkout request")?;
    assert!(checkout_request
        .body
        .contains("metadata%5Bcampaign%5D=spring"));
    assert!(checkout_request
        .body
        .contains("subscription_data%5Bmetadata%5D%5Bcampaign%5D=spring"));
    assert!(checkout_request
        .body
        .contains("metadata%5BuserId%5D=user_1"));
    assert!(!checkout_request.body.contains("evil"));
    assert!(!checkout_request.body.contains("__proto__"));
    Ok(())
}

#[tokio::test]
async fn subscription_upgrade_uses_lookup_key_locale_trial_success_wrapper_and_checkout_params(
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
        SubscriptionOptions::enabled(vec![StripePlan::new("pro")
            .lookup_key("pro_lookup")
            .free_trial(FreeTrialOptions::new(14))])
        .get_checkout_session_params(|input, _, context| {
            assert_eq!(context.base_url, "http://localhost:3000");
            Box::pin(async move {
                assert_eq!(input.plan.name(), "pro");
                assert_eq!(input.subscription.reference_id, "user_1");
                Ok(json!({
                    "allow_promotion_codes": true,
                    "metadata": {
                        "hookField": "hookValue",
                        "userId": "attacker"
                    },
                    "subscription_data": {
                        "description": "custom subscription",
                        "metadata": {
                            "subscriptionHook": "yes",
                            "referenceId": "attacker"
                        }
                    }
                }))
            })
        }),
    );
    let plugin = stripe(options).unwrap();
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, _adapter, cookie_header) = authenticated_context().await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"plan":"pro","locale":"es","successUrl":"/done","cancelUrl":"/pricing","metadata":{"campaign":"spring"}}"#
                .to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let requests = transport.requests()?;
    let price_lookup = requests
        .iter()
        .find(|request| request.path == "/v1/prices")
        .ok_or("price lookup request")?;
    assert!(price_lookup.body.contains("lookup_keys%5B0%5D=pro_lookup"));
    assert!(price_lookup.body.contains("active=true"));
    let checkout_request = requests
        .iter()
        .find(|request| request.path == "/v1/checkout/sessions")
        .ok_or("checkout request")?;
    assert!(checkout_request
        .body
        .contains("line_items%5B0%5D%5Bprice%5D=price_from_lookup"));
    assert!(checkout_request.body.contains("locale=es"));
    assert!(checkout_request.body.contains("allow_promotion_codes=true"));
    assert!(checkout_request
        .body
        .contains("subscription_data%5Btrial_period_days%5D=14"));
    assert!(checkout_request
        .body
        .contains("subscription_data%5Bdescription%5D=custom+subscription"));
    assert!(checkout_request
        .body
        .contains("metadata%5BhookField%5D=hookValue"));
    assert!(checkout_request
        .body
        .contains("subscription_data%5Bmetadata%5D%5BsubscriptionHook%5D=yes"));
    assert!(checkout_request
        .body
        .contains("metadata%5Bcampaign%5D=spring"));
    assert!(checkout_request
        .body
        .contains("metadata%5BuserId%5D=user_1"));
    assert!(checkout_request
        .body
        .contains("subscription_data%5Bmetadata%5D%5BreferenceId%5D=user_1"));
    assert!(!checkout_request.body.contains("attacker"));
    assert!(checkout_request.body.contains(
        "success_url=http%3A%2F%2Flocalhost%3A3000%2Fsubscription%2Fsuccess%3FcallbackURL%3D%252Fdone%26checkoutSessionId%3D%7BCHECKOUT_SESSION_ID%7D"
    ));
    Ok(())
}

#[tokio::test]
async fn subscription_upgrade_resolves_dynamic_plan_provider(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let options = StripeOptions::new(
        StripeClient::with_transport(
            "sk_test",
            Arc::clone(&transport) as Arc<dyn StripeTransport>,
        ),
        "whsec_test",
    )
    .subscription(SubscriptionOptions::enabled_dynamic(|| {
        Box::pin(async { Ok(vec![StripePlan::new("pro").price_id("price_pro")]) })
    }));
    let plugin = stripe(options).unwrap();
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, _adapter, cookie_header) = authenticated_context().await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(br#"{"plan":"pro","successUrl":"/ok","cancelUrl":"/pricing"}"#.to_vec())?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let requests = transport.requests()?;
    assert!(requests.iter().any(|request| {
        request.path == "/v1/checkout/sessions"
            && request
                .body
                .contains("line_items%5B0%5D%5Bprice%5D=price_pro")
    }));
    Ok(())
}

#[tokio::test]
async fn subscription_upgrade_skips_free_trial_after_reference_has_trialed(
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
        .free_trial(FreeTrialOptions::new(14))]));
    let plugin = stripe(options).unwrap();
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    create_subscription_record(
        &adapter,
        "sub_trialed",
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
                DbValue::String("sub_trialed".to_owned()),
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
    let requests = transport.requests()?;
    let checkout_request = requests
        .iter()
        .find(|request| request.path == "/v1/checkout/sessions")
        .ok_or("checkout request")?;
    assert!(!checkout_request.body.contains("trial_period_days"));
    Ok(())
}
