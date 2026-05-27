#![allow(clippy::unwrap_used)]

use super::*;
use crate::common::harness::{authenticated_context, create_subscription_record};
use openauth_stripe::options::{StripeOptions, StripePlan, SubscriptionOptions};
use openauth_stripe::stripe;
use serde_json::json;

#[tokio::test]
async fn list_includes_nested_limits_object() -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let options = StripeOptions::new(
        StripeClient::with_transport("sk_test", transport),
        "whsec_test",
    )
    .subscription(SubscriptionOptions::enabled(vec![StripePlan::new("pro")
        .price_id("price_pro")
        .group("teams")
        .limits(json!({ "projects": 10, "nested": { "rate": 5 } }))]));
    let plugin = stripe(options);
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
    assert_eq!(response.status(), http::StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(response.body())?;
    let limits = body[0]
        .get("limits")
        .ok_or("limits should be present on list response")?;
    assert_eq!(limits["projects"], 10);
    assert_eq!(limits["nested"]["rate"], 5);
    assert_eq!(
        body[0].get("group").and_then(|value| value.as_str()),
        Some("teams")
    );
    Ok(())
}
