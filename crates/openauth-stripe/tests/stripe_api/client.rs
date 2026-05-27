use openauth_stripe::stripe_api::{
    StripeClient, StripeRequest, StripeResponse, StripeTransport, StripeTransportFuture,
};
use serde_json::json;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct CaptureTransport {
    requests: Mutex<Vec<StripeRequest>>,
}

impl StripeTransport for CaptureTransport {
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
                body: json!({ "id": "cus_123", "object": "customer" }),
            })
        })
    }
}

#[tokio::test]
async fn client_sends_form_encoded_authenticated_requests() -> Result<(), Box<dyn std::error::Error>>
{
    let transport = Arc::new(CaptureTransport::default());
    let client = StripeClient::with_transport("sk_test_123", transport.clone());

    let response = client
        .create_customer(json!({
            "email": "ada@example.com",
            "metadata": { "userId": "user_1" }
        }))
        .await?;

    assert_eq!(response["id"], "cus_123");
    let requests = transport
        .requests
        .lock()
        .map_err(|error| error.to_string())?;
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[0].path, "/v1/customers");
    assert_eq!(
        requests[0].headers.get("Authorization").map(String::as_str),
        Some("Bearer sk_test_123")
    );
    assert_eq!(
        requests[0].headers.get("Content-Type").map(String::as_str),
        Some("application/x-www-form-urlencoded")
    );
    assert!(requests[0].body.contains("email=ada%40example.com"));
    Ok(())
}

#[tokio::test]
async fn client_supports_api_version_lookup_prices_and_subscription_schedules(
) -> Result<(), Box<dyn std::error::Error>> {
    #[derive(Default)]
    struct ScheduleCaptureTransport {
        requests: Mutex<Vec<StripeRequest>>,
    }

    impl StripeTransport for ScheduleCaptureTransport {
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
                    body: json!({ "id": "ok", "object": "ok" }),
                })
            })
        }
    }

    let transport = Arc::new(ScheduleCaptureTransport::default());
    let client = StripeClient::with_transport("sk_test_123", transport.clone())
        .api_version("2026-04-22.dahlia");

    client.price_by_lookup_key("starter_monthly").await?;
    client
        .list_subscription_schedules(json!({ "customer": "cus_123" }))
        .await?;
    client.retrieve_subscription_schedule("sched_123").await?;

    let requests = transport
        .requests
        .lock()
        .map_err(|error| error.to_string())?;
    assert_eq!(requests[0].method, "GET");
    assert_eq!(requests[0].path, "/v1/prices");
    assert!(requests[0]
        .body
        .contains("lookup_keys%5B0%5D=starter_monthly"));
    assert!(requests[0].body.contains("active=true"));
    assert!(requests[0].body.contains("limit=1"));
    assert_eq!(
        requests[0]
            .headers
            .get("Stripe-Version")
            .map(String::as_str),
        Some("2026-04-22.dahlia")
    );
    assert_eq!(requests[1].method, "GET");
    assert_eq!(requests[1].path, "/v1/subscription_schedules");
    assert!(requests[1].body.contains("customer=cus_123"));
    assert_eq!(requests[2].method, "GET");
    assert_eq!(requests[2].path, "/v1/subscription_schedules/sched_123");
    Ok(())
}
