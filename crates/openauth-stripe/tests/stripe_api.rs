use openauth_stripe::stripe_api::{
    encode_form, StripeClient, StripeRequest, StripeResponse, StripeTransport,
};
use serde_json::json;
use std::sync::{Arc, Mutex};

#[test]
fn form_encoder_uses_stripe_bracket_notation() {
    let encoded = encode_form(&json!({
        "customer": "cus_123",
        "line_items": [
            { "price": "price_base", "quantity": 1 },
            { "price": "price_metered" }
        ],
        "subscription_data": {
            "metadata": {
                "subscriptionId": "sub_local"
            }
        }
    }));

    assert!(encoded.contains("customer=cus_123"));
    assert!(encoded.contains("line_items%5B0%5D%5Bprice%5D=price_base"));
    assert!(encoded.contains("line_items%5B0%5D%5Bquantity%5D=1"));
    assert!(encoded.contains("line_items%5B1%5D%5Bprice%5D=price_metered"));
    assert!(encoded.contains("subscription_data%5Bmetadata%5D%5BsubscriptionId%5D=sub_local"));
}

#[test]
fn form_encoder_handles_schedule_phases_empty_strings_and_null_omission() {
    let encoded = encode_form(&json!({
        "cancel_at": "",
        "metadata": {
            "source": "@better-auth/stripe",
            "ignored": null
        },
        "phases": [
            {
                "items": [
                    { "price": "price_current", "quantity": 1 }
                ],
                "start_date": 1,
                "end_date": 2
            },
            {
                "items": [
                    { "price": "price_next" }
                ],
                "proration_behavior": "none"
            }
        ]
    }));

    assert!(encoded.contains("cancel_at="));
    assert!(encoded.contains("metadata%5Bsource%5D=%40better-auth%2Fstripe"));
    assert!(!encoded.contains("ignored"));
    assert!(encoded.contains("phases%5B0%5D%5Bitems%5D%5B0%5D%5Bprice%5D=price_current"));
    assert!(encoded.contains("phases%5B1%5D%5Bitems%5D%5B0%5D%5Bprice%5D=price_next"));
    assert!(encoded.contains("phases%5B1%5D%5Bproration_behavior%5D=none"));
}

#[tokio::test]
async fn client_sends_form_encoded_authenticated_requests() -> Result<(), Box<dyn std::error::Error>>
{
    #[derive(Default)]
    struct CaptureTransport {
        requests: Mutex<Vec<StripeRequest>>,
    }

    impl StripeTransport for CaptureTransport {
        fn send<'a>(
            &'a self,
            request: StripeRequest,
        ) -> openauth_stripe::stripe_api::StripeTransportFuture<'a> {
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
    struct CaptureTransport {
        requests: Mutex<Vec<StripeRequest>>,
    }

    impl StripeTransport for CaptureTransport {
        fn send<'a>(
            &'a self,
            request: StripeRequest,
        ) -> openauth_stripe::stripe_api::StripeTransportFuture<'a> {
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

    let transport = Arc::new(CaptureTransport::default());
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
