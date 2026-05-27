#![allow(clippy::unwrap_used)]

use super::*;
use crate::common::assertions::assert_error_code;
use crate::common::harness::{authenticated_context, plugin_endpoint, upgrade_request};
use openauth_stripe::options::{FreeTrialOptions, StripeOptions, StripePlan, SubscriptionOptions};
use openauth_stripe::stripe;

#[tokio::test]
async fn rejects_zero_day_trial() -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let options = StripeOptions::new(
        StripeClient::with_transport("sk_test", transport),
        "whsec_test",
    )
    .subscription(SubscriptionOptions::enabled(vec![StripePlan::new("pro")
        .price_id("price_pro")
        .free_trial(FreeTrialOptions::new(0))]));
    let plugin = stripe(options);
    let endpoint = plugin_endpoint(&plugin, "/subscription/upgrade").ok_or("upgrade endpoint")?;
    let (context, _adapter, cookie_header) = authenticated_context().await?;
    let request = upgrade_request(
        &cookie_header,
        br#"{"plan":"pro","successUrl":"/ok","cancelUrl":"/pricing"}"#,
    )?;

    let response = (endpoint.handler)(&context, request).await?;
    assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
    assert_error_code(response.body(), "INVALID_REQUEST_BODY")?;
    Ok(())
}
