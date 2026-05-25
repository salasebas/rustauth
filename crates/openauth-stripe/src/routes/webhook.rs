use http::{Method, StatusCode};
use openauth_core::api::{create_auth_endpoint, AuthEndpointOptions};
use openauth_core::error::OpenAuthError;
use serde_json::json;
use time::OffsetDateTime;

use crate::errors::StripeErrorCode;
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
                let now = OffsetDateTime::now_utc().unix_timestamp();
                crate::stripe_api::verify_webhook_signature(
                    request.body(),
                    signature,
                    &options.stripe_webhook_secret,
                    300,
                    now,
                )
                .map_err(|error| OpenAuthError::Api(error.to_string()))?;
                let event =
                    serde_json::from_slice::<StripeEvent>(request.body()).map_err(|error| {
                        OpenAuthError::InvalidRequestBody {
                            encoding: "JSON",
                            message: error.to_string(),
                        }
                    })?;
                crate::hooks::handle_stripe_event(context, &options, &event).await?;
                if let Some(on_event) = &options.on_event {
                    on_event(event)
                        .await
                        .map_err(|error| OpenAuthError::Api(error.to_string()))?;
                }
                json_response(StatusCode::OK, &json!({ "success": true }))
            })
        },
    )
}
