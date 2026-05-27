#![allow(clippy::unwrap_used)]

use super::*;
use crate::common::assertions::{assert_error_code, assert_ok_status};
use crate::common::harness::{
    authenticated_context, create_subscription_record, plugin_endpoint, stripe_plugin,
};
use http::StatusCode;
use openauth_core::db::{DbValue, Update, Where};
use openauth_stripe::stripe_api::{StripeRequest, StripeResponse, StripeTransport};
use time::OffsetDateTime;

#[derive(Default)]
struct AlreadyCanceledPortalTransport {
    requests: Mutex<Vec<StripeRequest>>,
}

impl StripeTransport for AlreadyCanceledPortalTransport {
    fn send<'a>(&'a self, request: StripeRequest) -> StripeTransportFuture<'a> {
        let response = match request.path.as_str() {
            "/v1/subscriptions" => Ok(json!({
                "object": "list",
                "data": [{
                    "id": "stripe_sub_active",
                    "object": "subscription",
                    "status": "active",
                    "cancel_at_period_end": false,
                    "cancel_at": 1702592000
                }]
            })),
            "/v1/billing_portal/sessions" => Err(StripeResponse {
                status: 400,
                body: json!({
                    "error": {
                        "code": "subscription_already_canceled",
                        "message": "This subscription is already set to be canceled"
                    }
                }),
            }),
            "/v1/subscriptions/stripe_sub_active" => Ok(json!({
                "id": "stripe_sub_active",
                "object": "subscription",
                "status": "active",
                "cancel_at_period_end": false,
                "cancel_at": 1702592000,
                "canceled_at": 1700000000
            })),
            _ => Ok(json!({ "id": "ok" })),
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
            match response {
                Ok(body) => Ok(StripeResponse { status: 200, body }),
                Err(response) => Ok(response),
            }
        })
    }
}

#[derive(Default)]
struct UnrelatedPortalErrorTransport;

impl StripeTransport for UnrelatedPortalErrorTransport {
    fn send<'a>(&'a self, request: StripeRequest) -> StripeTransportFuture<'a> {
        let response = match request.path.as_str() {
            "/v1/subscriptions" => StripeResponse {
                status: 200,
                body: json!({
                    "object": "list",
                    "data": [{
                        "id": "stripe_sub_active",
                        "status": "active"
                    }]
                }),
            },
            "/v1/billing_portal/sessions" => StripeResponse {
                status: 500,
                body: json!({
                    "error": {
                        "code": "api_error",
                        "message": "portal unavailable"
                    }
                }),
            },
            _ => StripeResponse {
                status: 200,
                body: json!({ "id": "ok" }),
            },
        };
        Box::pin(async move { Ok(response) })
    }
}

#[tokio::test]
async fn syncs_local_pending_cancel_and_returns_ok() -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(AlreadyCanceledPortalTransport::default());
    let plugin = stripe_plugin(Arc::clone(&transport) as Arc<dyn StripeTransport>);
    let endpoint = plugin_endpoint(&plugin, "/subscription/cancel").ok_or("cancel endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    create_subscription_record(&adapter, "sub_active", "user_1", "active", Some("cus_123")).await?;
    adapter
        .update(
            Update::new("subscription")
                .where_clause(Where::new("id", DbValue::String("sub_active".to_owned())))
                .data(
                    "stripe_subscription_id",
                    DbValue::String("stripe_sub_active".to_owned()),
                ),
        )
        .await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/cancel")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(br#"{"returnUrl":"/account"}"#.to_vec())?;

    let response = (endpoint.handler)(&context, request).await?;
    assert_ok_status(&response)?;

    let subscription = adapter
        .records("subscription")
        .await
        .into_iter()
        .find(|record| record.get("id") == Some(&DbValue::String("sub_active".to_owned())))
        .ok_or("subscription")?;
    assert_eq!(
        subscription.get("cancel_at"),
        Some(&DbValue::Timestamp(OffsetDateTime::from_unix_timestamp(
            1702592000
        )?))
    );
    Ok(())
}

#[tokio::test]
async fn does_not_match_unrelated_stripe_errors() -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(UnrelatedPortalErrorTransport);
    let plugin = stripe_plugin(Arc::clone(&transport) as Arc<dyn StripeTransport>);
    let endpoint = plugin_endpoint(&plugin, "/subscription/cancel").ok_or("cancel endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    create_subscription_record(&adapter, "sub_active", "user_1", "active", Some("cus_123")).await?;
    adapter
        .update(
            Update::new("subscription")
                .where_clause(Where::new("id", DbValue::String("sub_active".to_owned())))
                .data(
                    "stripe_subscription_id",
                    DbValue::String("stripe_sub_active".to_owned()),
                ),
        )
        .await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/cancel")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(br#"{"returnUrl":"/account"}"#.to_vec())?;

    let response = (endpoint.handler)(&context, request).await?;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_error_code(response.body(), "FAILED_TO_FETCH_PLANS")?;
    Ok(())
}
