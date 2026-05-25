use http::{Method, StatusCode};
use openauth_core::api::{
    create_auth_endpoint, parse_request_body, AuthEndpointOptions, BodyField, BodySchema,
    JsonSchemaType, OpenApiOperation,
};
use openauth_core::db::{DbAdapter, DbValue, DeleteMany, Update, Where};
use openauth_core::error::OpenAuthError;
use serde::Deserialize;
use serde_json::{json, Value};
use time::OffsetDateTime;

use super::reference::{authorize_reference_for_customer_type, ReferenceResolutionInput};
use super::support::{
    clear_subscription_cancel, clear_subscription_schedule, db_string, error_response,
    find_active_stripe_subscription, find_subscription_for_reference, json_response,
    record_has_pending_cancel, record_is_active_or_trialing, require_session,
    resolve_subscription_options_for_endpoint, stripe_list_has_active_subscription,
    validate_redirect_url,
};
use crate::errors::StripeErrorCode;
use crate::options::{AuthorizeReferenceAction, StripeOptions};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CancelSubscriptionBody {
    #[serde(default)]
    reference_id: Option<String>,
    #[serde(default)]
    subscription_id: Option<String>,
    #[serde(default)]
    customer_type: Option<String>,
    return_url: String,
    #[serde(default)]
    disable_redirect: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RestoreSubscriptionBody {
    #[serde(default)]
    reference_id: Option<String>,
    #[serde(default)]
    subscription_id: Option<String>,
    #[serde(default)]
    customer_type: Option<String>,
}

pub fn cancel_subscription(options: StripeOptions) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/subscription/cancel",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("cancelSubscription")
            .body_schema(BodySchema::object([
                BodyField::optional("referenceId", JsonSchemaType::String),
                BodyField::optional("subscriptionId", JsonSchemaType::String),
                BodyField::optional("customerType", JsonSchemaType::String),
                BodyField::new("returnUrl", JsonSchemaType::String),
                BodyField::optional("disableRedirect", JsonSchemaType::Boolean),
            ]))
            .openapi(OpenApiOperation::new("cancelSubscription")),
        move |context, request| {
            let options = options.clone();
            Box::pin(async move {
                let Some(current_session) = require_session(context, &request).await? else {
                    return error_response(StatusCode::UNAUTHORIZED, StripeErrorCode::Unauthorized);
                };
                let body: CancelSubscriptionBody = parse_request_body(&request)?;
                let subscription_options = options.subscription.as_ref().ok_or_else(|| {
                    OpenAuthError::InvalidConfig("stripe subscriptions are not enabled".to_owned())
                })?;
                let subscription_options =
                    match resolve_subscription_options_for_endpoint(subscription_options).await? {
                        Ok(subscription_options) => subscription_options,
                        Err(response) => return Ok(response),
                    };
                let Some(adapter) = context.adapter() else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        StripeErrorCode::SubscriptionNotFound,
                    );
                };
                let reference_id =
                    match authorize_reference_for_customer_type(ReferenceResolutionInput {
                        context,
                        adapter: adapter.as_ref(),
                        options: &options,
                        subscription_options: &subscription_options,
                        user: &current_session.user,
                        session: &current_session.session,
                        session_token: &current_session.session.token,
                        explicit_reference_id: body.reference_id,
                        customer_type: body.customer_type.as_deref(),
                        action: AuthorizeReferenceAction::CancelSubscription,
                    })
                    .await?
                    {
                        Ok(reference_id) => reference_id,
                        Err(failure) => return error_response(failure.status, failure.code),
                    };
                let Some(return_url) = validate_redirect_url(context, &request, body.return_url)?
                else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        StripeErrorCode::InvalidRequestBody,
                    );
                };
                let Some(subscription) = find_subscription_for_reference(
                    adapter.as_ref(),
                    &reference_id,
                    body.subscription_id.as_deref(),
                )
                .await?
                else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        StripeErrorCode::SubscriptionNotFound,
                    );
                };
                let Some(customer_id) = subscription
                    .get("stripe_customer_id")
                    .and_then(db_string)
                    .map(str::to_owned)
                else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        StripeErrorCode::SubscriptionNotFound,
                    );
                };
                let Some(stripe_subscription_id) = subscription
                    .get("stripe_subscription_id")
                    .and_then(db_string)
                    .map(str::to_owned)
                else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        StripeErrorCode::SubscriptionNotFound,
                    );
                };
                let local_subscription_id = subscription
                    .get("id")
                    .and_then(db_string)
                    .map(str::to_owned);
                let active_subscriptions = options
                    .stripe_client
                    .list_subscriptions(json!({ "customer": customer_id.clone() }))
                    .await
                    .map_err(|error| OpenAuthError::Api(error.to_string()))?;
                if !stripe_list_has_any_active_subscription(&active_subscriptions) {
                    adapter
                        .delete_many(DeleteMany::new("subscription").where_clause(Where::new(
                            "reference_id",
                            DbValue::String(reference_id),
                        )))
                        .await?;
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        StripeErrorCode::SubscriptionNotFound,
                    );
                }
                if !stripe_list_has_active_subscription(
                    &active_subscriptions,
                    &stripe_subscription_id,
                ) {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        StripeErrorCode::SubscriptionNotFound,
                    );
                }
                let portal = match options
                    .stripe_client
                    .create_billing_portal_session(json!({
                        "customer": customer_id,
                        "return_url": return_url,
                        "flow_data": {
                            "type": "subscription_cancel",
                            "subscription_cancel": {
                                "subscription": stripe_subscription_id,
                            }
                        }
                    }))
                    .await
                {
                    Ok(portal) => portal,
                    Err(error) => {
                        if stripe_error_is_already_canceled(&error)
                            && !record_has_pending_cancel(&subscription)
                        {
                            if let Some(local_subscription_id) = local_subscription_id.as_deref() {
                                sync_pending_cancel_from_stripe(
                                    adapter.as_ref(),
                                    &options,
                                    local_subscription_id,
                                    &stripe_subscription_id,
                                )
                                .await?;
                            }
                        }
                        return Err(OpenAuthError::Api(error.to_string()));
                    }
                };
                json_response(
                    StatusCode::OK,
                    &json!({
                        "url": portal.get("url").and_then(Value::as_str),
                        "redirect": !body.disable_redirect,
                    }),
                )
            })
        },
    )
}

fn stripe_error_is_already_canceled(error: &crate::stripe_api::StripeApiError) -> bool {
    error.to_string().contains("already set to be canceled")
}

fn stripe_list_has_any_active_subscription(list: &Value) -> bool {
    list.get("data")
        .and_then(Value::as_array)
        .is_some_and(|subscriptions| {
            subscriptions.iter().any(|subscription| {
                subscription
                    .get("status")
                    .and_then(Value::as_str)
                    .is_some_and(crate::utils::is_active_or_trialing)
            })
        })
}

async fn sync_pending_cancel_from_stripe(
    adapter: &dyn DbAdapter,
    options: &StripeOptions,
    local_subscription_id: &str,
    stripe_subscription_id: &str,
) -> Result<(), OpenAuthError> {
    let stripe_subscription = options
        .stripe_client
        .retrieve_subscription(stripe_subscription_id)
        .await
        .map_err(|error| OpenAuthError::Api(error.to_string()))?;
    adapter
        .update(
            Update::new("subscription")
                .where_clause(Where::new(
                    "id",
                    DbValue::String(local_subscription_id.to_owned()),
                ))
                .data(
                    "cancel_at_period_end",
                    DbValue::Boolean(
                        stripe_subscription
                            .get("cancel_at_period_end")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                    ),
                )
                .data(
                    "cancel_at",
                    optional_unix_timestamp(
                        stripe_subscription.get("cancel_at").and_then(Value::as_i64),
                    )?,
                )
                .data(
                    "canceled_at",
                    optional_unix_timestamp(
                        stripe_subscription
                            .get("canceled_at")
                            .and_then(Value::as_i64),
                    )?,
                ),
        )
        .await?;
    Ok(())
}

pub fn restore_subscription(options: StripeOptions) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/subscription/restore",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("restoreSubscription")
            .body_schema(BodySchema::object([
                BodyField::optional("referenceId", JsonSchemaType::String),
                BodyField::optional("subscriptionId", JsonSchemaType::String),
                BodyField::optional("customerType", JsonSchemaType::String),
            ]))
            .openapi(OpenApiOperation::new("restoreSubscription")),
        move |context, request| {
            let options = options.clone();
            Box::pin(async move {
                let Some(current_session) = require_session(context, &request).await? else {
                    return error_response(StatusCode::UNAUTHORIZED, StripeErrorCode::Unauthorized);
                };
                let body: RestoreSubscriptionBody = parse_request_body(&request)?;
                let subscription_options = options.subscription.as_ref().ok_or_else(|| {
                    OpenAuthError::InvalidConfig("stripe subscriptions are not enabled".to_owned())
                })?;
                let subscription_options =
                    match resolve_subscription_options_for_endpoint(subscription_options).await? {
                        Ok(subscription_options) => subscription_options,
                        Err(response) => return Ok(response),
                    };
                let Some(adapter) = context.adapter() else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        StripeErrorCode::SubscriptionNotFound,
                    );
                };
                let reference_id =
                    match authorize_reference_for_customer_type(ReferenceResolutionInput {
                        context,
                        adapter: adapter.as_ref(),
                        options: &options,
                        subscription_options: &subscription_options,
                        user: &current_session.user,
                        session: &current_session.session,
                        session_token: &current_session.session.token,
                        explicit_reference_id: body.reference_id,
                        customer_type: body.customer_type.as_deref(),
                        action: AuthorizeReferenceAction::RestoreSubscription,
                    })
                    .await?
                    {
                        Ok(reference_id) => reference_id,
                        Err(failure) => return error_response(failure.status, failure.code),
                    };
                let Some(subscription) = find_subscription_for_reference(
                    adapter.as_ref(),
                    &reference_id,
                    body.subscription_id.as_deref(),
                )
                .await?
                else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        StripeErrorCode::SubscriptionNotFound,
                    );
                };
                if !record_is_active_or_trialing(&subscription) {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        StripeErrorCode::SubscriptionNotActive,
                    );
                }
                let Some(local_subscription_id) = subscription
                    .get("id")
                    .and_then(db_string)
                    .map(str::to_owned)
                else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        StripeErrorCode::SubscriptionNotFound,
                    );
                };
                let Some(customer_id) = subscription
                    .get("stripe_customer_id")
                    .and_then(db_string)
                    .map(str::to_owned)
                else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        StripeErrorCode::SubscriptionNotFound,
                    );
                };
                let Some(stripe_subscription_id) = subscription
                    .get("stripe_subscription_id")
                    .and_then(db_string)
                    .map(str::to_owned)
                else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        StripeErrorCode::SubscriptionNotFound,
                    );
                };
                if let Some(schedule_id) = subscription
                    .get("stripe_schedule_id")
                    .and_then(db_string)
                    .map(str::to_owned)
                {
                    let schedule = options
                        .stripe_client
                        .retrieve_subscription_schedule(&schedule_id)
                        .await
                        .map_err(|error| OpenAuthError::Api(error.to_string()))?;
                    if schedule.get("status").and_then(Value::as_str) == Some("active") {
                        options
                            .stripe_client
                            .release_subscription_schedule(&schedule_id)
                            .await
                            .map_err(|error| OpenAuthError::Api(error.to_string()))?;
                    }
                    clear_subscription_schedule(adapter.as_ref(), &local_subscription_id).await?;
                    let released = options
                        .stripe_client
                        .retrieve_subscription(&stripe_subscription_id)
                        .await
                        .map_err(|error| OpenAuthError::Api(error.to_string()))?;
                    return json_response(StatusCode::OK, &released);
                }
                if !record_has_pending_cancel(&subscription) {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        StripeErrorCode::SubscriptionNotPendingChange,
                    );
                }
                let active_subscriptions = options
                    .stripe_client
                    .list_subscriptions(json!({ "customer": customer_id }))
                    .await
                    .map_err(|error| OpenAuthError::Api(error.to_string()))?;
                let Some(active_subscription) =
                    find_active_stripe_subscription(&active_subscriptions, &stripe_subscription_id)
                else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        StripeErrorCode::SubscriptionNotFound,
                    );
                };
                let update_params = if active_subscription
                    .get("cancel_at")
                    .and_then(Value::as_i64)
                    .is_some()
                {
                    json!({ "cancel_at": "" })
                } else {
                    json!({ "cancel_at_period_end": false })
                };
                let restored = options
                    .stripe_client
                    .update_subscription(&stripe_subscription_id, update_params)
                    .await
                    .map_err(|error| OpenAuthError::Api(error.to_string()))?;
                clear_subscription_cancel(adapter.as_ref(), &local_subscription_id).await?;
                json_response(StatusCode::OK, &restored)
            })
        },
    )
}

fn optional_unix_timestamp(value: Option<i64>) -> Result<DbValue, OpenAuthError> {
    value
        .map(|timestamp| {
            OffsetDateTime::from_unix_timestamp(timestamp)
                .map(DbValue::Timestamp)
                .map_err(|error| OpenAuthError::Api(error.to_string()))
        })
        .unwrap_or(Ok(DbValue::Null))
}
