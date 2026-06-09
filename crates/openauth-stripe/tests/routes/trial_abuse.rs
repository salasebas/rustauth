#![allow(clippy::unwrap_used)]

use super::*;
use crate::common::webhook::signed_webhook_request;
use openauth_stripe::options::{FreeTrialOptions, StripeOptions, StripePlan, SubscriptionOptions};
use time::OffsetDateTime;

#[tokio::test]
async fn upgrade_with_explicit_incomplete_subscription_skips_trial_when_reference_trialed(
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
        .free_trial(FreeTrialOptions::new(7))]));
    let plugin = stripe(options).unwrap();
    let endpoint = plugin
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
    create_subscription_record(
        &adapter,
        "sub_incomplete_new",
        "user_1",
        "incomplete",
        Some("cus_123"),
    )
    .await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"plan":"pro","subscriptionId":"stripe_sub_incomplete_new","successUrl":"/ok","cancelUrl":"/pricing"}"#
                .to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let checkout_request = transport
        .requests()?
        .into_iter()
        .find(|request| request.path == "/v1/checkout/sessions")
        .ok_or("checkout request")?;
    assert!(!checkout_request.body.contains("trial_period_days"));
    Ok(())
}

#[tokio::test]
async fn upgrade_skips_trial_after_deleted_webhook_propagates_trial_timestamps(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let plugin = stripe(
        StripeOptions::new(
            StripeClient::with_transport(
                "sk_test",
                Arc::clone(&transport) as Arc<dyn StripeTransport>,
            ),
            "whsec_test",
        )
        .subscription(SubscriptionOptions::enabled(vec![StripePlan::new(
            "starter",
        )
        .price_id("price_pro")
        .free_trial(FreeTrialOptions::new(7))])),
    )
    .unwrap();
    let upgrade_endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let webhook_endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/stripe/webhook")
        .ok_or("webhook endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    create_subscription_record(
        &adapter,
        "sub_trial_abuse_old",
        "user_1",
        "canceled",
        Some("cus_trial_abuse"),
    )
    .await?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let trial_start = now - 3 * 24 * 60 * 60;
    let trial_end = now + 4 * 24 * 60 * 60;
    let payload = format!(
        r#"{{"id":"evt_trial_abuse","type":"customer.subscription.deleted","data":{{"object":{{"id":"stripe_sub_trial_abuse_old","customer":"cus_trial_abuse","status":"canceled","trial_start":{trial_start},"trial_end":{trial_end},"cancel_at_period_end":false,"canceled_at":{now},"ended_at":{now},"items":{{"data":[{{"id":"si_old","price":{{"id":"price_pro","recurring":{{"interval":"month","usage_type":"licensed"}}}},"quantity":1,"current_period_start":{trial_start},"current_period_end":{trial_end}}}]}}}}}}}}"#
    );
    let webhook_request = signed_webhook_request("whsec_test", payload.as_bytes())?;
    let webhook_response = (webhook_endpoint.handler)(&context, webhook_request).await?;
    assert_eq!(webhook_response.status(), StatusCode::OK);
    let records = adapter.records("subscription").await;
    let updated = records
        .iter()
        .find(|record| record.get("id") == Some(&DbValue::String("sub_trial_abuse_old".to_owned())))
        .ok_or("subscription")?;
    assert!(updated
        .get("trial_start")
        .is_some_and(|value| !matches!(value, DbValue::Null)));
    let upgrade_request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(br#"{"plan":"starter","successUrl":"/ok","cancelUrl":"/pricing"}"#.to_vec())?;
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
