#![allow(clippy::unwrap_used)]

use super::*;
use crate::common::assertions::assert_error_code;
use crate::common::harness::{
    authenticated_context, plugin_endpoint, stripe_plugin, upgrade_request,
};

#[tokio::test]
async fn unknown_plan_returns_subscription_plan_not_found_json(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let plugin = stripe_plugin(transport);
    let endpoint = plugin_endpoint(&plugin, "/subscription/upgrade").ok_or("upgrade endpoint")?;
    let (context, _adapter, cookie_header) = authenticated_context().await?;
    let request = upgrade_request(
        &cookie_header,
        br#"{"plan":"missing","successUrl":"/ok","cancelUrl":"/pricing"}"#,
    )?;

    let response = (endpoint.handler)(&context, request).await?;
    assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
    assert_error_code(response.body(), "SUBSCRIPTION_PLAN_NOT_FOUND")?;
    Ok(())
}

#[tokio::test]
async fn plan_without_price_or_lookup_returns_plan_not_found(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let options = StripeOptions::new(
        StripeClient::with_transport("sk_test", transport),
        "whsec_test",
    )
    .subscription(SubscriptionOptions::enabled(vec![StripePlan::new("empty")]));
    let plugin = stripe(options);
    let endpoint = plugin_endpoint(&plugin, "/subscription/upgrade").ok_or("upgrade endpoint")?;
    let (context, _adapter, cookie_header) = authenticated_context().await?;
    let request = upgrade_request(
        &cookie_header,
        br#"{"plan":"empty","successUrl":"/ok","cancelUrl":"/pricing"}"#,
    )?;

    let response = (endpoint.handler)(&context, request).await?;
    assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
    assert_error_code(response.body(), "SUBSCRIPTION_PLAN_NOT_FOUND")?;
    Ok(())
}

#[tokio::test]
async fn invalid_customer_type_returns_invalid_request_body(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let plugin = stripe_plugin(transport);
    let endpoint = plugin_endpoint(&plugin, "/subscription/upgrade").ok_or("upgrade endpoint")?;
    let (context, _adapter, cookie_header) = authenticated_context().await?;
    let request = upgrade_request(
        &cookie_header,
        br#"{"plan":"pro","customerType":"team","successUrl":"/ok","cancelUrl":"/pricing"}"#,
    )?;

    let response = (endpoint.handler)(&context, request).await?;
    assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
    assert_error_code(response.body(), "INVALID_REQUEST_BODY")?;
    Ok(())
}
