use http::{Method, StatusCode};
use openauth_core::api::{
    create_auth_endpoint, parse_request_body, AuthEndpointOptions, BodyField, BodySchema,
    JsonSchemaType, OpenApiOperation,
};
use openauth_core::db::{DbRecord, DbValue, FindOne, Update, Where};
use openauth_core::error::OpenAuthError;
use serde_json::{json, Value};
use time::OffsetDateTime;

use super::reference::{authorize_reference_for_customer_type, ReferenceResolutionInput};
use super::support::{
    active_subscription_customer, active_subscription_records, db_string, error_response,
    json_response, query_param, redirect_response, require_session,
    resolve_subscription_options_for_endpoint, subscription_record_to_json, validate_redirect_url,
};
use crate::errors::StripeErrorCode;
use crate::metadata::SubscriptionMetadata;
use crate::models::StripeSubscription;
use crate::options::{AuthorizeReferenceAction, StripeOptions};
use crate::utils::{get_plan_by_name, resolve_plan_item, resolve_quantity};

pub fn list_active_subscriptions(options: StripeOptions) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/subscription/list",
        Method::GET,
        AuthEndpointOptions::new().operation_id("listActiveSubscriptions"),
        move |context, request| {
            let options = options.clone();
            Box::pin(async move {
                let Some(current_session) = require_session(context, &request).await? else {
                    return error_response(StatusCode::UNAUTHORIZED, StripeErrorCode::Unauthorized);
                };
                let subscription_options = options.subscription.as_ref().ok_or_else(|| {
                    OpenAuthError::InvalidConfig("stripe subscriptions are not enabled".to_owned())
                })?;
                let subscription_options =
                    match resolve_subscription_options_for_endpoint(subscription_options).await? {
                        Ok(subscription_options) => subscription_options,
                        Err(response) => return Ok(response),
                    };
                let Some(adapter) = context.adapter() else {
                    return json_response(StatusCode::OK, &Vec::<Value>::new());
                };
                let customer_type = query_param(&request, "customerType");
                let reference_id =
                    match authorize_reference_for_customer_type(ReferenceResolutionInput {
                        context,
                        adapter: adapter.as_ref(),
                        options: &options,
                        subscription_options: &subscription_options,
                        user: &current_session.user,
                        session: &current_session.session,
                        session_token: &current_session.session.token,
                        explicit_reference_id: query_param(&request, "referenceId"),
                        customer_type: customer_type.as_deref(),
                        action: AuthorizeReferenceAction::ListSubscription,
                    })
                    .await?
                    {
                        Ok(reference_id) => reference_id,
                        Err(failure) => return error_response(failure.status, failure.code),
                    };
                let records = active_subscription_records(adapter.as_ref(), &reference_id).await?;
                let subscriptions = records
                    .into_iter()
                    .map(|record| {
                        subscription_record_with_plan_metadata(record, &subscription_options)
                    })
                    .collect::<Vec<_>>();
                json_response(StatusCode::OK, &subscriptions)
            })
        },
    )
}

fn subscription_record_with_plan_metadata(
    record: DbRecord,
    subscription_options: &crate::options::SubscriptionOptions,
) -> Value {
    let plan_name = record
        .get("plan")
        .and_then(|value| db_string(value))
        .map(str::to_owned);
    let billing_interval = record
        .get("billing_interval")
        .and_then(|value| db_string(value))
        .map(str::to_owned);
    let mut value = subscription_record_to_json(record);
    if let (Some(plan_name), Value::Object(map)) = (plan_name, &mut value) {
        if let Some(plan) = get_plan_by_name(subscription_options, &plan_name) {
            if let Some(limits) = &plan.limits {
                map.insert("limits".to_owned(), limits.clone());
            }
            let price_id = if billing_interval.as_deref() == Some("year") {
                plan.annual_discount_price_id
                    .as_ref()
                    .or(plan.price_id.as_ref())
            } else {
                plan.price_id.as_ref()
            };
            if let Some(price_id) = price_id {
                map.insert("priceId".to_owned(), Value::String(price_id.clone()));
            }
        }
    }
    value
}

pub fn subscription_success(options: StripeOptions) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/subscription/success",
        Method::GET,
        AuthEndpointOptions::new()
            .operation_id("handleSubscriptionSuccess")
            .openapi(OpenApiOperation::new("handleSubscriptionSuccess")),
        move |context, request| {
            let options = options.clone();
            Box::pin(async move {
                let callback =
                    query_param(&request, "callbackURL").unwrap_or_else(|| "/".to_owned());
                let Some(callback) = validate_redirect_url(context, &request, callback)? else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        StripeErrorCode::InvalidRequestBody,
                    );
                };
                let mut callback = callback;
                let Some(current_session) = require_session(context, &request).await? else {
                    return redirect_response(&callback);
                };
                let Some(checkout_session_id) = query_param(&request, "checkoutSessionId") else {
                    return redirect_response(&callback);
                };
                callback = callback.replace("{CHECKOUT_SESSION_ID}", &checkout_session_id);
                let Some(adapter) = context.adapter() else {
                    return redirect_response(&callback);
                };
                let Some(subscription_options) = options.subscription.as_ref() else {
                    return redirect_response(&callback);
                };
                let subscription_options =
                    match resolve_subscription_options_for_endpoint(subscription_options).await? {
                        Ok(subscription_options) => subscription_options,
                        Err(response) => return Ok(response),
                    };
                let Ok(checkout_session) = options
                    .stripe_client
                    .retrieve_checkout_session(&checkout_session_id)
                    .await
                else {
                    return redirect_response(&callback);
                };
                let metadata = checkout_session
                    .get("metadata")
                    .and_then(Value::as_object)
                    .map(|metadata| {
                        metadata
                            .iter()
                            .filter_map(|(key, value)| {
                                value.as_str().map(|value| (key.clone(), value.to_owned()))
                            })
                            .collect::<std::collections::BTreeMap<_, _>>()
                    })
                    .unwrap_or_default();
                let Some(subscription_id) = SubscriptionMetadata::get(&metadata).subscription_id
                else {
                    return redirect_response(&callback);
                };
                let Some(subscription) =
                    adapter
                        .find_one(FindOne::new("subscription").where_clause(Where::new(
                            "id",
                            DbValue::String(subscription_id.clone()),
                        )))
                        .await?
                else {
                    return redirect_response(&callback);
                };
                if super::support::record_is_active_or_trialing(&subscription) {
                    return redirect_response(&callback);
                }
                let Some(customer_id) = subscription
                    .get("stripe_customer_id")
                    .and_then(|value| db_string(value))
                    .map(str::to_owned)
                else {
                    let _ = current_session;
                    return redirect_response(&callback);
                };
                let Ok(stripe_subscriptions) = options
                    .stripe_client
                    .list_subscriptions(json!({
                        "customer": customer_id,
                        "status": "active",
                    }))
                    .await
                else {
                    return redirect_response(&callback);
                };
                let Some(stripe_subscription_value) = stripe_subscriptions
                    .get("data")
                    .and_then(Value::as_array)
                    .and_then(|subscriptions| subscriptions.first())
                    .cloned()
                else {
                    return redirect_response(&callback);
                };
                let Ok(stripe_subscription) =
                    serde_json::from_value::<StripeSubscription>(stripe_subscription_value)
                else {
                    return redirect_response(&callback);
                };
                let Some(resolved) =
                    resolve_plan_item(&subscription_options, &stripe_subscription.items.data)
                else {
                    return redirect_response(&callback);
                };
                let Some(plan) = resolved.plan else {
                    return redirect_response(&callback);
                };
                update_subscription_from_stripe(
                    adapter.as_ref(),
                    &subscription,
                    &stripe_subscription,
                    plan.name.to_lowercase(),
                    resolved
                        .item
                        .price
                        .recurring
                        .as_ref()
                        .map(|recurring| recurring.interval.clone()),
                    resolve_quantity(
                        &stripe_subscription.items.data,
                        resolved.item,
                        plan.seat_price_id.as_deref(),
                    ),
                )
                .await?;
                redirect_response(&callback)
            })
        },
    )
}

async fn update_subscription_from_stripe(
    adapter: &dyn openauth_core::db::DbAdapter,
    subscription: &DbRecord,
    stripe_subscription: &StripeSubscription,
    plan: String,
    billing_interval: Option<String>,
    seats: i64,
) -> Result<(), OpenAuthError> {
    let Some(subscription_id) = subscription.get("id").and_then(|value| db_string(value)) else {
        return Ok(());
    };
    let first_item = stripe_subscription.items.data.first();
    let mut update = Update::new("subscription")
        .where_clause(Where::new(
            "id",
            DbValue::String(subscription_id.to_owned()),
        ))
        .data(
            "status",
            DbValue::String(stripe_subscription.status.clone()),
        )
        .data("plan", DbValue::String(plan))
        .data(
            "stripe_subscription_id",
            DbValue::String(stripe_subscription.id.clone()),
        )
        .data(
            "cancel_at_period_end",
            DbValue::Boolean(stripe_subscription.cancel_at_period_end),
        )
        .data(
            "cancel_at",
            optional_unix_timestamp(stripe_subscription.cancel_at)?,
        )
        .data(
            "canceled_at",
            optional_unix_timestamp(stripe_subscription.canceled_at)?,
        )
        .data("seats", DbValue::Number(seats));
    if let Some(interval) = billing_interval {
        update = update.data("billing_interval", DbValue::String(interval));
    }
    if let Some(item) = first_item {
        update = update
            .data(
                "period_start",
                optional_unix_timestamp(item.current_period_start)?,
            )
            .data(
                "period_end",
                optional_unix_timestamp(item.current_period_end)?,
            );
    }
    if stripe_subscription.trial_start.is_some() || stripe_subscription.trial_end.is_some() {
        update = update
            .data(
                "trial_start",
                optional_unix_timestamp(stripe_subscription.trial_start)?,
            )
            .data(
                "trial_end",
                optional_unix_timestamp(stripe_subscription.trial_end)?,
            );
    }
    adapter.update(update).await?;
    Ok(())
}

fn optional_unix_timestamp(timestamp: Option<i64>) -> Result<DbValue, OpenAuthError> {
    let Some(timestamp) = timestamp else {
        return Ok(DbValue::Null);
    };
    OffsetDateTime::from_unix_timestamp(timestamp)
        .map(DbValue::Timestamp)
        .map_err(|error| OpenAuthError::Api(error.to_string()))
}

pub fn create_billing_portal(options: StripeOptions) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/subscription/billing-portal",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("createBillingPortal")
            .body_schema(BodySchema::object([
                BodyField::optional("locale", JsonSchemaType::String),
                BodyField::optional("referenceId", JsonSchemaType::String),
                BodyField::optional("customerType", JsonSchemaType::String),
                BodyField::optional("returnUrl", JsonSchemaType::String),
                BodyField::optional("disableRedirect", JsonSchemaType::Boolean),
            ]))
            .openapi(OpenApiOperation::new("createBillingPortal")),
        move |context, request| {
            let options = options.clone();
            Box::pin(async move {
                let Some(current_session) = require_session(context, &request).await? else {
                    return error_response(StatusCode::UNAUTHORIZED, StripeErrorCode::Unauthorized);
                };
                let body: Value = parse_request_body(&request)?;
                let subscription_options = options.subscription.as_ref().ok_or_else(|| {
                    OpenAuthError::InvalidConfig("stripe subscriptions are not enabled".to_owned())
                })?;
                let subscription_options =
                    match resolve_subscription_options_for_endpoint(subscription_options).await? {
                        Ok(subscription_options) => subscription_options,
                        Err(response) => return Ok(response),
                    };
                let customer_type = body
                    .get("customerType")
                    .and_then(Value::as_str)
                    .unwrap_or("user");
                let Some(adapter) = context.adapter() else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        StripeErrorCode::CustomerNotFound,
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
                        explicit_reference_id: body
                            .get("referenceId")
                            .and_then(Value::as_str)
                            .map(str::to_owned),
                        customer_type: Some(customer_type),
                        action: AuthorizeReferenceAction::BillingPortal,
                    })
                    .await?
                    {
                        Ok(reference_id) => reference_id,
                        Err(failure) => return error_response(failure.status, failure.code),
                    };
                let Some(return_url) = validate_redirect_url(
                    context,
                    &request,
                    body.get("returnUrl")
                        .and_then(Value::as_str)
                        .unwrap_or("/")
                        .to_owned(),
                )?
                else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        StripeErrorCode::InvalidRequestBody,
                    );
                };
                let customer = if customer_type == "organization" {
                    crate::customers::organization_customer_id(adapter.as_ref(), &reference_id)
                        .await?
                        .or(active_subscription_customer(adapter.as_ref(), &reference_id).await?)
                } else {
                    user_customer_id(adapter.as_ref(), &current_session.user.id)
                        .await?
                        .or(active_subscription_customer(adapter.as_ref(), &reference_id).await?)
                };
                let Some(customer) = customer else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        StripeErrorCode::CustomerNotFound,
                    );
                };
                let disable_redirect = body
                    .get("disableRedirect")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let mut params = json!({
                    "customer": customer,
                    "return_url": return_url,
                });
                if let Some(locale) = body.get("locale").and_then(Value::as_str) {
                    if let Value::Object(map) = &mut params {
                        map.insert("locale".to_owned(), Value::String(locale.to_owned()));
                    }
                }
                let portal = match options
                    .stripe_client
                    .create_billing_portal_session(params)
                    .await
                {
                    Ok(portal) => portal,
                    Err(_) => {
                        return error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            StripeErrorCode::UnableToCreateBillingPortal,
                        );
                    }
                };
                let mut response = portal;
                if let Value::Object(map) = &mut response {
                    map.insert("redirect".to_owned(), Value::Bool(!disable_redirect));
                }
                json_response(StatusCode::OK, &response)
            })
        },
    )
}

async fn user_customer_id(
    adapter: &dyn openauth_core::db::DbAdapter,
    user_id: &str,
) -> Result<Option<String>, OpenAuthError> {
    Ok(adapter
        .find_one(
            FindOne::new("user")
                .where_clause(Where::new("id", DbValue::String(user_id.to_owned()))),
        )
        .await?
        .and_then(|record| {
            record
                .get("stripe_customer_id")
                .and_then(|value| db_string(value))
                .map(str::to_owned)
        }))
}
