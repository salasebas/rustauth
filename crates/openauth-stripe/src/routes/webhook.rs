use http::{Method, StatusCode};
use openauth_core::api::{create_auth_endpoint, AuthEndpointOptions};
use serde_json::json;
use time::OffsetDateTime;

use crate::errors::StripeErrorCode;
use crate::logging;
use crate::models::StripeEvent;
use crate::options::StripeOptions;

use super::support::{error_response, json_response};

pub fn stripe_webhook(options: StripeOptions) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/stripe/webhook",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("handleStripeWebhook")
            .hide_from_openapi()
            .bypass_origin_security(),
        move |context, request| {
            let options = options.clone();
            Box::pin(async move {
                let Some(signature) = request
                    .headers()
                    .get("stripe-signature")
                    .and_then(|value| value.to_str().ok())
                else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        StripeErrorCode::StripeSignatureNotFound,
                    );
                };
                if options.stripe_webhook_secret.is_empty() {
                    return error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        StripeErrorCode::StripeWebhookSecretNotFound,
                    );
                }
                let now = OffsetDateTime::now_utc().unix_timestamp();
                if let Err(error) = crate::stripe_api::verify_webhook_signature(
                    request.body(),
                    signature,
                    &options.stripe_webhook_secret,
                    300,
                    now,
                ) {
                    logging::webhook_error(context, &error.to_string());
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        StripeErrorCode::FailedToConstructStripeEvent,
                    );
                }
                let event = match serde_json::from_slice::<StripeEvent>(request.body()) {
                    Ok(event) => event,
                    Err(error) => {
                        logging::webhook_error(
                            context,
                            &format!("Failed to parse Stripe event JSON: {error}"),
                        );
                        return error_response(
                            StatusCode::BAD_REQUEST,
                            StripeErrorCode::FailedToConstructStripeEvent,
                        );
                    }
                };
                crate::hooks::handle_stripe_event(context, &options, &event).await?;
                if let Some(on_event) = &options.on_event {
                    if let Err(error) = on_event(event).await {
                        logging::webhook_error(
                            context,
                            &format!("Stripe on_event hook failed: {error}"),
                        );
                        return error_response(
                            StatusCode::BAD_REQUEST,
                            StripeErrorCode::StripeWebhookError,
                        );
                    }
                }
                json_response(StatusCode::OK, &json!({ "success": true }))
            })
        },
    )
}
