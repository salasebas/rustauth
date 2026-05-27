use http::StatusCode;
use openauth_stripe::errors::StripeErrorCode;
use openauth_stripe::stripe_api::StripeApiError;

#[test]
fn transport_maps_to_failed_to_fetch_plans() {
    let (status, code) = StripeApiError::Transport("network down".to_owned())
        .plugin_response(StripeErrorCode::UnableToCreateBillingPortal);
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(code, StripeErrorCode::FailedToFetchPlans);
}

#[test]
fn portal_stripe_error_maps_to_default_plugin_code() {
    let (status, code) = StripeApiError::Stripe {
        status: 400,
        code: Some("subscription_already_canceled".to_owned()),
        message: "already set to be canceled".to_owned(),
    }
    .plugin_response(StripeErrorCode::UnableToCreateBillingPortal);
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(code, StripeErrorCode::UnableToCreateBillingPortal);
}

#[test]
fn webhook_variant_uses_plugin_code() {
    let (status, code) = StripeApiError::Webhook(StripeErrorCode::FailedToConstructStripeEvent)
        .plugin_response(StripeErrorCode::UnableToCreateBillingPortal);
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(code, StripeErrorCode::FailedToConstructStripeEvent);
}

#[test]
fn resource_missing_maps_customer_default_to_customer_not_found() {
    let (status, code) = StripeApiError::Stripe {
        status: 404,
        code: Some("resource_missing".to_owned()),
        message: "No such customer".to_owned(),
    }
    .plugin_response(StripeErrorCode::UnableToCreateCustomer);
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(code, StripeErrorCode::CustomerNotFound);
}

#[test]
fn is_already_scheduled_cancel_matches_stripe_error_code() {
    let error = StripeApiError::Stripe {
        status: 400,
        code: Some("subscription_already_canceled".to_owned()),
        message: "Subscription is canceled".to_owned(),
    };
    assert!(error.is_already_scheduled_cancel());
}

#[test]
fn stripe_server_error_maps_to_failed_to_fetch_plans() {
    let (status, code) = StripeApiError::Stripe {
        status: 503,
        code: None,
        message: "upstream unavailable".to_owned(),
    }
    .plugin_response(StripeErrorCode::UnableToCreateCustomer);
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(code, StripeErrorCode::FailedToFetchPlans);
}
