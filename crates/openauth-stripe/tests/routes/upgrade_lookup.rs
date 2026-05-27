#![allow(clippy::unwrap_used)]

use super::*;
use crate::common::assertions::assert_error_code;
use crate::common::harness::{authenticated_context, plugin_endpoint, upgrade_request};
use openauth_stripe::options::{StripeOptions, StripePlan, SubscriptionOptions};
use openauth_stripe::stripe;
use openauth_stripe::stripe_api::{StripeApiError, StripeRequest, StripeResponse, StripeTransport};

struct FailingLookupTransport;

impl StripeTransport for FailingLookupTransport {
    fn send<'a>(
        &'a self,
        request: StripeRequest,
    ) -> openauth_stripe::stripe_api::StripeTransportFuture<'a> {
        let _ = request;
        Box::pin(async move {
            Err(StripeApiError::Transport(
                "lookup transport unavailable".to_owned(),
            ))
        })
    }
}

struct EmptyLookupTransport;

impl StripeTransport for EmptyLookupTransport {
    fn send<'a>(
        &'a self,
        request: StripeRequest,
    ) -> openauth_stripe::stripe_api::StripeTransportFuture<'a> {
        let body = if request.path == "/v1/prices" {
            json!({ "object": "list", "data": [] })
        } else {
            json!({ "id": "ok" })
        };
        Box::pin(async move { Ok(StripeResponse { status: 200, body }) })
    }
}

#[tokio::test]
async fn lookup_transport_failure_returns_failed_to_fetch_plans(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(FailingLookupTransport);
    let options = StripeOptions::new(
        StripeClient::with_transport("sk_test", transport),
        "whsec_test",
    )
    .subscription(SubscriptionOptions::enabled(vec![
        StripePlan::new("pro").lookup_key("pro_lookup")
    ]));
    let plugin = stripe(options);
    let endpoint = plugin_endpoint(&plugin, "/subscription/upgrade").ok_or("upgrade endpoint")?;
    let (context, _adapter, cookie_header) = authenticated_context().await?;
    let request = upgrade_request(
        &cookie_header,
        br#"{"plan":"pro","successUrl":"/ok","cancelUrl":"/pricing"}"#,
    )?;

    let response = (endpoint.handler)(&context, request).await?;
    assert_eq!(response.status(), http::StatusCode::BAD_GATEWAY);
    assert_error_code(response.body(), "FAILED_TO_FETCH_PLANS")?;
    Ok(())
}

#[tokio::test]
async fn empty_lookup_result_returns_subscription_plan_not_found(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(EmptyLookupTransport);
    let options = StripeOptions::new(
        StripeClient::with_transport("sk_test", transport),
        "whsec_test",
    )
    .subscription(SubscriptionOptions::enabled(vec![
        StripePlan::new("pro").lookup_key("pro_lookup")
    ]));
    let plugin = stripe(options);
    let endpoint = plugin_endpoint(&plugin, "/subscription/upgrade").ok_or("upgrade endpoint")?;
    let (context, _adapter, cookie_header) = authenticated_context().await?;
    let request = upgrade_request(
        &cookie_header,
        br#"{"plan":"pro","successUrl":"/ok","cancelUrl":"/pricing"}"#,
    )?;

    let response = (endpoint.handler)(&context, request).await?;
    assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
    assert_error_code(response.body(), "SUBSCRIPTION_PLAN_NOT_FOUND")?;
    Ok(())
}
