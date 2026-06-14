#![allow(clippy::unwrap_used)]

use super::*;
struct LazyCustomerCreateTransport {
    requests: Mutex<Vec<StripeRequest>>,
}

impl StripeTransport for LazyCustomerCreateTransport {
    fn send<'a>(&'a self, request: StripeRequest) -> StripeTransportFuture<'a> {
        let response = match (request.method.as_str(), request.path.as_str()) {
            ("GET", "/v1/customers/search") => json!({ "object": "list", "data": [] }),
            ("POST", "/v1/customers") => json!({ "id": "cus_lazy", "object": "customer" }),
            ("GET", "/v1/prices/price_pro") => json!({
                "id": "price_pro",
                "recurring": { "interval": "month", "usage_type": "licensed" }
            }),
            ("POST", "/v1/checkout/sessions") => json!({
                "id": "cs_lazy",
                "url": "https://checkout.stripe.test/session"
            }),
            _ => json!({ "object": "list", "data": [] }),
        };
        let _ = self.requests.lock().map(|mut r| r.push(request));
        Box::pin(async move {
            Ok(StripeResponse {
                status: 200,
                body: response,
            })
        })
    }
}

#[tokio::test]
async fn upgrade_lazy_customer_create_forwards_request_metadata(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(LazyCustomerCreateTransport {
        requests: Mutex::new(Vec::new()),
    });
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
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, _adapter, cookie_header) = authenticated_context().await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"plan":"pro","successUrl":"/ok","cancelUrl":"/pricing","metadata":{"tier":"enterprise"}}"#
                .to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let requests = transport.requests.lock().unwrap();
    let create_customer = requests
        .iter()
        .find(|request| request.method == "POST" && request.path == "/v1/customers")
        .ok_or("customer create")?;
    assert!(create_customer
        .body
        .contains("metadata%5Btier%5D=enterprise"));
    Ok(())
}

#[tokio::test]
async fn upgrade_strips_user_injected_stripe_customer_id_from_checkout_metadata(
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
            br#"{"plan":"pro","successUrl":"/ok","cancelUrl":"/pricing","disableRedirect":true,"metadata":{"stripeCustomerId":"cus_victim","campaign":"q2"}}"#
                .to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let requests = transport.requests()?;
    let checkout_request = requests
        .iter()
        .find(|request| request.path == "/v1/checkout/sessions")
        .ok_or("checkout request")?;
    assert!(!checkout_request.body.contains("stripeCustomerId"));
    assert!(!checkout_request.body.contains("cus_victim"));
    assert!(checkout_request
        .body
        .contains("subscription_data%5Bmetadata%5D%5Bcampaign%5D=q2"));
    Ok(())
}
