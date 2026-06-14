use http::{Method, StatusCode};
use rustauth_core::api::{create_auth_endpoint, AuthEndpointOptions};
use rustauth_core::db::{Create, DbAdapter, DbValue, Delete, FindOne, Where};
use rustauth_core::error::RustAuthError;
use serde_json::json;
use time::OffsetDateTime;

use crate::errors::StripeErrorCode;
use crate::logging;
use crate::models::StripeEvent;
use crate::options::StripeOptions;

use super::support::{error_response, json_response};

/// Logical model name of the durable webhook idempotency table.
const WEBHOOK_EVENT_MODEL: &str = "stripe_webhook_event";

pub fn stripe_webhook(options: StripeOptions) -> rustauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/stripe/webhook",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("handleStripeWebhook")
            .hide_from_openapi()
            .bypass_origin_security(),
        move |context, request| {
            let options = options.clone();
            async move {
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
                    logging::webhook_error(&context, &error.to_string());
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        StripeErrorCode::FailedToConstructStripeEvent,
                    );
                }
                let event = match serde_json::from_slice::<StripeEvent>(request.body()) {
                    Ok(event) => event,
                    Err(error) => {
                        logging::webhook_error(
                            &context,
                            &format!("Failed to parse Stripe event JSON: {error}"),
                        );
                        return error_response(
                            StatusCode::BAD_REQUEST,
                            StripeErrorCode::FailedToConstructStripeEvent,
                        );
                    }
                };
                // Idempotency guard: skip events we have already processed and
                // claim new ones before running side effects so Stripe retries,
                // manual resends, and concurrent duplicate deliveries do not
                // re-run built-in handlers or user hooks.
                let adapter = context.adapter();
                if let Some(adapter) = adapter.as_deref() {
                    if webhook_event_seen(adapter, &event.id).await? {
                        logging::webhook_info(
                            &context,
                            &format!(
                                "Stripe webhook: event {} already processed, skipping",
                                event.id
                            ),
                        );
                        return json_response(StatusCode::OK, &json!({ "success": true }));
                    }
                    record_webhook_event(adapter, &event).await?;
                }

                let event_id = event.id.clone();
                if crate::hooks::handle_stripe_event(&context, &options, &event)
                    .await
                    .is_err()
                {
                    // A built-in handler failed (e.g. a transient Stripe API,
                    // adapter, or deserialization error). Release the claimed
                    // idempotency row so Stripe retries and manual resends
                    // re-run the handler instead of short-circuiting on the
                    // stored event and leaving billing state stale.
                    if let Some(adapter) = adapter.as_deref() {
                        forget_webhook_event(adapter, &event_id).await;
                    }
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        StripeErrorCode::StripeWebhookError,
                    );
                }
                if let Some(on_event) = &options.on_event {
                    if let Err(error) = on_event(event).await {
                        logging::webhook_error(
                            &context,
                            &format!("Stripe on_event hook failed: {error}"),
                        );
                        // Do not leave the event marked as processed so Stripe
                        // retries can recover.
                        if let Some(adapter) = adapter.as_deref() {
                            forget_webhook_event(adapter, &event_id).await;
                        }
                        return error_response(
                            StatusCode::BAD_REQUEST,
                            StripeErrorCode::StripeWebhookError,
                        );
                    }
                }
                json_response(StatusCode::OK, &json!({ "success": true }))
            }
        },
    )
}

/// Return true when the Stripe `event.id` has already been recorded.
async fn webhook_event_seen(
    adapter: &dyn DbAdapter,
    event_id: &str,
) -> Result<bool, RustAuthError> {
    Ok(adapter
        .find_one(
            FindOne::new(WEBHOOK_EVENT_MODEL)
                .where_clause(Where::new("id", DbValue::String(event_id.to_owned()))),
        )
        .await?
        .is_some())
}

/// Persist the Stripe `event.id` so future deliveries are deduplicated. On SQL
/// adapters the primary key rejects concurrent duplicate claims.
async fn record_webhook_event(
    adapter: &dyn DbAdapter,
    event: &StripeEvent,
) -> Result<(), RustAuthError> {
    adapter
        .create(
            Create::new(WEBHOOK_EVENT_MODEL)
                .data("id", DbValue::String(event.id.clone()))
                .data("event_type", DbValue::String(event.event_type.clone()))
                .data("created_at", DbValue::Timestamp(OffsetDateTime::now_utc()))
                .force_allow_id(),
        )
        .await
        .map(|_| ())
}

/// Remove a previously claimed event so a failed delivery can be retried.
async fn forget_webhook_event(adapter: &dyn DbAdapter, event_id: &str) {
    let _ = adapter
        .delete(
            Delete::new(WEBHOOK_EVENT_MODEL)
                .where_clause(Where::new("id", DbValue::String(event_id.to_owned()))),
        )
        .await;
}
