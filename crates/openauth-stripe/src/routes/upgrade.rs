use http::{Method, StatusCode};
use openauth_core::api::{
    create_auth_endpoint, parse_request_body, AuthEndpointOptions, BodyField, BodySchema,
    JsonSchemaType, OpenApiOperation,
};
use openauth_core::db::{DbAdapter, DbRecord, DbValue, FindMany, Where};
use openauth_core::error::OpenAuthError;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use time::OffsetDateTime;

use super::reference::{authorize_reference_for_customer_type, ReferenceResolutionInput};
use super::support::{
    active_subscription_records, create_incomplete_subscription, db_string, error_response,
    find_subscription_for_reference, json_response, reference_has_ever_trialed, require_session,
    resolve_subscription_options_for_endpoint, validate_redirect_url,
};
use crate::errors::StripeErrorCode;
use crate::metadata::SubscriptionMetadata;
use crate::models::{StripeSubscription, Subscription};
use crate::options::{AuthorizeReferenceAction, CheckoutSessionParamsInput, StripeOptions};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpgradeSubscriptionBody {
    plan: String,
    #[serde(default)]
    annual: bool,
    #[serde(default)]
    reference_id: Option<String>,
    #[serde(default)]
    success_url: Option<String>,
    #[serde(default)]
    cancel_url: Option<String>,
    #[serde(default)]
    disable_redirect: bool,
    #[serde(default)]
    metadata: Option<Value>,
    #[serde(default)]
    seats: Option<i64>,
    #[serde(default)]
    subscription_id: Option<String>,
    #[serde(default)]
    customer_type: Option<String>,
    #[serde(default)]
    locale: Option<String>,
    #[serde(default)]
    return_url: Option<String>,
    #[serde(default)]
    schedule_at_period_end: bool,
}

pub fn upgrade_subscription(options: StripeOptions) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/subscription/upgrade",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("upgradeSubscription")
            .body_schema(BodySchema::object([
                BodyField::new("plan", JsonSchemaType::String),
                BodyField::optional("annual", JsonSchemaType::Boolean),
                BodyField::optional("referenceId", JsonSchemaType::String),
                BodyField::optional("successUrl", JsonSchemaType::String),
                BodyField::optional("cancelUrl", JsonSchemaType::String),
                BodyField::optional("disableRedirect", JsonSchemaType::Boolean),
                BodyField::optional("metadata", JsonSchemaType::Object),
                BodyField::optional("seats", JsonSchemaType::Number),
                BodyField::optional("subscriptionId", JsonSchemaType::String),
                BodyField::optional("customerType", JsonSchemaType::String),
                BodyField::optional("locale", JsonSchemaType::String),
                BodyField::optional("returnUrl", JsonSchemaType::String),
                BodyField::optional("scheduleAtPeriodEnd", JsonSchemaType::Boolean),
            ]))
            .openapi(OpenApiOperation::new("upgradeSubscription")),
        move |context, request| {
            let options = options.clone();
            Box::pin(async move {
                let Some(current_session) = require_session(context, &request).await? else {
                    return error_response(StatusCode::UNAUTHORIZED, StripeErrorCode::Unauthorized);
                };
                let body: UpgradeSubscriptionBody = parse_request_body(&request)?;
                let subscription_options = options.subscription.as_ref().ok_or_else(|| {
                    OpenAuthError::InvalidConfig("stripe subscriptions are not enabled".to_owned())
                })?;
                let subscription_options =
                    match resolve_subscription_options_for_endpoint(subscription_options).await? {
                        Ok(subscription_options) => subscription_options,
                        Err(response) => return Ok(response),
                    };
                if subscription_options.require_email_verification
                    && !current_session.user.email_verified
                {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        StripeErrorCode::EmailVerificationRequired,
                    );
                }
                let requested_seats = body.seats.unwrap_or(1);
                if requested_seats < 1 {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        StripeErrorCode::InvalidRequestBody,
                    );
                }
                let customer_type = body.customer_type.as_deref().unwrap_or("user");
                if !matches!(customer_type, "user" | "organization") {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        StripeErrorCode::InvalidRequestBody,
                    );
                }
                let customer_type = customer_type.to_owned();
                if let Some(return_url) = body.return_url.as_ref() {
                    if validate_redirect_url(context, &request, return_url.clone())?.is_none() {
                        return error_response(
                            StatusCode::BAD_REQUEST,
                            StripeErrorCode::InvalidRequestBody,
                        );
                    }
                }
                let plan = crate::utils::get_plan_by_name(&subscription_options, &body.plan)
                    .ok_or_else(|| {
                        OpenAuthError::Api(
                            StripeErrorCode::SubscriptionPlanNotFound
                                .message()
                                .to_owned(),
                        )
                    })?;
                let price_id = resolve_plan_price_id(&options, plan, body.annual).await;
                let Some(price_id) = price_id else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        StripeErrorCode::SubscriptionPlanNotFound,
                    );
                };
                let billing_interval = if body.annual { "year" } else { "month" };
                let adapter = context.adapter().ok_or_else(|| {
                    OpenAuthError::InvalidConfig(
                        "stripe subscriptions require an adapter".to_owned(),
                    )
                })?;
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
                        customer_type: Some(customer_type.as_str()),
                        action: AuthorizeReferenceAction::UpgradeSubscription,
                    })
                    .await?
                    {
                        Ok(reference_id) => reference_id,
                        Err(failure) => return error_response(failure.status, failure.code),
                    };
                let seats = effective_seats(
                    adapter.as_ref(),
                    customer_type.as_str(),
                    &reference_id,
                    plan,
                    requested_seats,
                )
                .await?;
                let Some(success_url) = validate_redirect_url(
                    context,
                    &request,
                    body.success_url.unwrap_or_else(|| "/".to_owned()),
                )?
                else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        StripeErrorCode::InvalidRequestBody,
                    );
                };
                let Some(cancel_url) = validate_redirect_url(
                    context,
                    &request,
                    body.cancel_url.unwrap_or_else(|| "/".to_owned()),
                )?
                else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        StripeErrorCode::InvalidRequestBody,
                    );
                };
                let explicit_subscription = if let Some(subscription_id) = body.subscription_id {
                    let Some(subscription) = find_subscription_for_reference(
                        adapter.as_ref(),
                        &reference_id,
                        Some(&subscription_id),
                    )
                    .await?
                    else {
                        return error_response(
                            StatusCode::BAD_REQUEST,
                            StripeErrorCode::SubscriptionNotFound,
                        );
                    };
                    Some(subscription)
                } else {
                    None
                };
                let active_subscriptions = if let Some(subscription) = explicit_subscription {
                    if super::support::record_is_active_or_trialing(&subscription) {
                        vec![subscription]
                    } else {
                        Vec::new()
                    }
                } else {
                    active_subscription_records(adapter.as_ref(), &reference_id).await?
                };
                let mut already_subscribed = false;
                for subscription in &active_subscriptions {
                    let same_plan = subscription
                        .get("plan")
                        .and_then(db_string)
                        .is_some_and(|stored_plan| stored_plan.eq_ignore_ascii_case(&plan.name));
                    let same_interval = subscription.get("billing_interval").and_then(db_string)
                        == Some(billing_interval);
                    let same_seats = subscription.get("seats").and_then(|value| match value {
                        openauth_core::db::DbValue::Number(seats) => Some(*seats),
                        _ => None,
                    }) == Some(seats);
                    let subscription_still_valid = subscription
                        .get("period_end")
                        .and_then(db_timestamp)
                        .map_or(true, |period_end| period_end > OffsetDateTime::now_utc());
                    if same_plan && same_interval && same_seats && subscription_still_valid {
                        already_subscribed = stripe_subscription_matches_requested_price(
                            &options,
                            &subscription_options,
                            subscription,
                            &price_id,
                            billing_interval,
                        )
                        .await?
                        .unwrap_or(false);
                        if already_subscribed {
                            break;
                        }
                    }
                }
                if already_subscribed {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        StripeErrorCode::AlreadySubscribedPlan,
                    );
                }
                let customer_id = if customer_type == "organization" {
                    match crate::customers::ensure_organization_customer(
                        adapter.as_ref(),
                        &options,
                        crate::options::CustomerCreateContext::from_auth_context(context),
                        &reference_id,
                    )
                    .await
                    {
                        Ok(customer_id) => customer_id,
                        Err(OpenAuthError::Api(message))
                            if message == StripeErrorCode::OrganizationNotFound.message() =>
                        {
                            return error_response(
                                StatusCode::BAD_REQUEST,
                                StripeErrorCode::OrganizationNotFound,
                            );
                        }
                        Err(_) => {
                            return error_response(
                                StatusCode::BAD_REQUEST,
                                StripeErrorCode::UnableToCreateCustomer,
                            );
                        }
                    }
                } else {
                    match crate::customers::ensure_user_customer(
                        adapter.as_ref(),
                        &options,
                        crate::options::CustomerCreateContext::from_auth_context(context),
                        &current_session.user,
                    )
                    .await
                    {
                        Ok(customer_id) => customer_id,
                        Err(_) => {
                            return error_response(
                                StatusCode::BAD_REQUEST,
                                StripeErrorCode::UnableToCreateCustomer,
                            );
                        }
                    }
                };
                if let Some(active_subscription) = active_subscriptions.iter().find(|record| {
                    record
                        .get("stripe_subscription_id")
                        .and_then(db_string)
                        .is_some()
                }) {
                    return super::active_upgrade::handle(
                        super::active_upgrade::ActiveUpgradeInput {
                            context,
                            request: &request,
                            adapter: adapter.as_ref(),
                            options: &options,
                            subscription_options: &subscription_options,
                            local_subscription: active_subscription,
                            plan,
                            price_id: &price_id,
                            customer_id: &customer_id,
                            seats,
                            return_url: body.return_url,
                            disable_redirect: body.disable_redirect,
                            schedule_at_period_end: body.schedule_at_period_end,
                        },
                    )
                    .await;
                }
                let subscription_id = create_incomplete_subscription(
                    adapter.as_ref(),
                    &plan.name,
                    &reference_id,
                    Some(&customer_id),
                    body.annual,
                    seats,
                )
                .await?;
                let subscription = checkout_subscription(
                    &subscription_id,
                    &plan.name,
                    &reference_id,
                    &customer_id,
                    body.annual,
                    seats,
                );
                let custom_checkout_params =
                    if let Some(get_params) = &subscription_options.get_checkout_session_params {
                        get_params(
                            CheckoutSessionParamsInput {
                                user: current_session.user.clone(),
                                session: current_session.session.clone(),
                                plan: plan.clone(),
                                subscription: subscription.clone(),
                            },
                            &request,
                            context,
                        )
                        .await?
                    } else {
                        Value::Object(Map::new())
                    };
                let has_ever_trialed =
                    reference_has_ever_trialed(adapter.as_ref(), &reference_id).await?;
                let trial_period_days = plan
                    .free_trial
                    .as_ref()
                    .and_then(|free_trial| (!has_ever_trialed).then_some(free_trial.days));
                let metadata = SubscriptionMetadata::new(
                    &current_session.user.id,
                    &subscription_id,
                    &reference_id,
                )
                .merge_user_metadata(body.metadata.unwrap_or(Value::Null))
                .into_map();
                let mut line_items = checkout_line_items(
                    &options.stripe_client,
                    &price_id,
                    plan.seat_price_id.as_deref(),
                    seats,
                )
                .await;
                line_items.extend(plan.line_items.iter().cloned());
                let success_url = checkout_success_url(context, &success_url);
                let checkout_params = checkout_session_params(CheckoutSessionBuild {
                    success_url,
                    cancel_url,
                    customer_id,
                    customer_type,
                    reference_id,
                    metadata,
                    line_items,
                    locale: body.locale,
                    trial_period_days,
                    custom_params: custom_checkout_params,
                })?;
                let checkout = options
                    .stripe_client
                    .create_checkout_session(checkout_params)
                    .await
                    .map_err(|error| OpenAuthError::Api(error.to_string()))?;
                let mut response = checkout;
                if let Value::Object(map) = &mut response {
                    map.insert("redirect".to_owned(), Value::Bool(!body.disable_redirect));
                }
                json_response(StatusCode::OK, &response)
            })
        },
    )
}

async fn resolve_plan_price_id(
    options: &StripeOptions,
    plan: &crate::options::StripePlan,
    annual: bool,
) -> Option<String> {
    let (price_id, lookup_key) = if annual {
        (
            plan.annual_discount_price_id
                .as_ref()
                .or(plan.price_id.as_ref()),
            plan.annual_discount_lookup_key
                .as_ref()
                .or(plan.lookup_key.as_ref()),
        )
    } else {
        (plan.price_id.as_ref(), plan.lookup_key.as_ref())
    };
    if let Some(lookup_key) = lookup_key {
        if let Ok(prices) = options.stripe_client.price_by_lookup_key(lookup_key).await {
            if let Some(resolved) = prices
                .get("data")
                .and_then(Value::as_array)
                .and_then(|prices| prices.first())
                .and_then(|price| price.get("id"))
                .and_then(Value::as_str)
            {
                return Some(resolved.to_owned());
            }
        }
    }
    price_id.cloned()
}

fn db_timestamp(value: &DbValue) -> Option<OffsetDateTime> {
    match value {
        DbValue::Timestamp(value) => Some(*value),
        _ => None,
    }
}

async fn stripe_subscription_matches_requested_price(
    options: &StripeOptions,
    subscription_options: &crate::options::SubscriptionOptions,
    subscription: &DbRecord,
    price_id: &str,
    billing_interval: &str,
) -> Result<Option<bool>, OpenAuthError> {
    let Some(stripe_subscription_id) = subscription
        .get("stripe_subscription_id")
        .and_then(db_string)
    else {
        return Ok(None);
    };
    let Some(customer_id) = subscription.get("stripe_customer_id").and_then(db_string) else {
        return Ok(None);
    };
    let stripe_subscriptions = options
        .stripe_client
        .list_subscriptions(json!({ "customer": customer_id }))
        .await
        .map_err(|error| OpenAuthError::Api(error.to_string()))?;
    let Some(stripe_subscription_value) = stripe_subscriptions
        .get("data")
        .and_then(Value::as_array)
        .and_then(|subscriptions| {
            subscriptions.iter().find(|subscription| {
                subscription.get("id").and_then(Value::as_str) == Some(stripe_subscription_id)
            })
        })
        .cloned()
    else {
        return Ok(Some(false));
    };
    let stripe_subscription =
        serde_json::from_value::<StripeSubscription>(stripe_subscription_value)
            .map_err(|error| OpenAuthError::Api(error.to_string()))?;
    let Some(resolved) =
        crate::utils::resolve_plan_item(subscription_options, &stripe_subscription.items.data)
    else {
        return Ok(Some(false));
    };
    let interval_matches = resolved
        .item
        .price
        .recurring
        .as_ref()
        .map_or(true, |recurring| recurring.interval == billing_interval);
    Ok(Some(resolved.item.price.id == price_id && interval_matches))
}

async fn effective_seats(
    adapter: &dyn DbAdapter,
    customer_type: &str,
    reference_id: &str,
    plan: &crate::options::StripePlan,
    requested_seats: i64,
) -> Result<i64, OpenAuthError> {
    if customer_type != "organization" || plan.seat_price_id.is_none() {
        return Ok(requested_seats);
    }
    let member_count = adapter
        .find_many(FindMany::new("member").where_clause(Where::new(
            "organization_id",
            DbValue::String(reference_id.to_owned()),
        )))
        .await?
        .len() as i64;
    Ok(member_count.max(1))
}

fn checkout_subscription(
    id: &str,
    plan: &str,
    reference_id: &str,
    stripe_customer_id: &str,
    annual: bool,
    seats: i64,
) -> Subscription {
    Subscription {
        id: id.to_owned(),
        plan: plan.to_owned(),
        reference_id: reference_id.to_owned(),
        stripe_customer_id: Some(stripe_customer_id.to_owned()),
        stripe_subscription_id: None,
        status: "incomplete".to_owned(),
        period_start: None,
        period_end: None,
        trial_start: None,
        trial_end: None,
        cancel_at_period_end: false,
        cancel_at: None,
        canceled_at: None,
        ended_at: None,
        seats: Some(seats),
        billing_interval: Some(if annual { "year" } else { "month" }.to_owned()),
        stripe_schedule_id: None,
    }
}

struct CheckoutSessionBuild {
    success_url: String,
    cancel_url: String,
    customer_id: String,
    customer_type: String,
    reference_id: String,
    metadata: std::collections::BTreeMap<String, String>,
    line_items: Vec<Value>,
    locale: Option<String>,
    trial_period_days: Option<i64>,
    custom_params: Value,
}

fn checkout_session_params(input: CheckoutSessionBuild) -> Result<Value, OpenAuthError> {
    let mut root = match input.custom_params {
        Value::Null => Map::new(),
        Value::Object(object) => object,
        _ => {
            return Err(OpenAuthError::Api(
                "checkout session params must be a JSON object".to_owned(),
            ));
        }
    };
    let custom_metadata = root.remove("metadata").unwrap_or(Value::Null);
    let custom_subscription_data = root.remove("subscription_data").unwrap_or(Value::Null);
    let mut subscription_data = match custom_subscription_data {
        Value::Null => Map::new(),
        Value::Object(object) => object,
        _ => {
            return Err(OpenAuthError::Api(
                "checkout session subscription_data must be a JSON object".to_owned(),
            ));
        }
    };
    let custom_subscription_metadata = subscription_data.remove("metadata").unwrap_or(Value::Null);

    let metadata = merge_checkout_metadata(input.metadata.clone(), custom_metadata);
    let subscription_metadata =
        merge_checkout_metadata(input.metadata, custom_subscription_metadata);
    if let Some(trial_period_days) = input.trial_period_days {
        subscription_data.insert("trial_period_days".to_owned(), json!(trial_period_days));
    }
    subscription_data.insert("metadata".to_owned(), json!(subscription_metadata));

    root.insert("mode".to_owned(), Value::String("subscription".to_owned()));
    root.insert("success_url".to_owned(), Value::String(input.success_url));
    root.insert("cancel_url".to_owned(), Value::String(input.cancel_url));
    root.insert("customer".to_owned(), Value::String(input.customer_id));
    root.insert(
        "customer_update".to_owned(),
        json!(if input.customer_type == "organization" {
            json!({ "address": "auto" })
        } else {
            json!({ "name": "auto", "address": "auto" })
        }),
    );
    root.insert(
        "client_reference_id".to_owned(),
        Value::String(input.reference_id),
    );
    root.insert("line_items".to_owned(), Value::Array(input.line_items));
    if let Some(locale) = input.locale {
        root.insert("locale".to_owned(), Value::String(locale));
    }
    root.insert(
        "subscription_data".to_owned(),
        Value::Object(subscription_data),
    );
    root.insert("metadata".to_owned(), json!(metadata));
    Ok(Value::Object(root))
}

fn merge_checkout_metadata(
    base: std::collections::BTreeMap<String, String>,
    custom: Value,
) -> std::collections::BTreeMap<String, String> {
    let mut metadata = SubscriptionMetadata::new(
        base.get("userId").cloned().unwrap_or_default(),
        base.get("subscriptionId").cloned().unwrap_or_default(),
        base.get("referenceId").cloned().unwrap_or_default(),
    );
    metadata = metadata.merge_user_metadata(json!(base));
    metadata.merge_user_metadata(custom).into_map()
}

fn checkout_success_url(
    context: &openauth_core::context::AuthContext,
    callback_url: &str,
) -> String {
    let encoded_callback =
        url::form_urlencoded::byte_serialize(callback_url.as_bytes()).collect::<String>();
    format!(
        "{}/subscription/success?callbackURL={encoded_callback}&checkoutSessionId={{CHECKOUT_SESSION_ID}}",
        context.base_url.trim_end_matches('/')
    )
}

async fn checkout_line_items(
    stripe_client: &crate::stripe_api::StripeClient,
    price_id: &str,
    seat_price_id: Option<&str>,
    seats: i64,
) -> Vec<Value> {
    if seat_price_id == Some(price_id) {
        return vec![json!({
            "price": price_id,
            "quantity": seats,
        })];
    }
    let is_metered = is_metered_price(stripe_client, price_id).await;
    let mut base = json!({ "price": price_id });
    if !is_metered {
        let quantity = if seat_price_id.is_some() { 1 } else { seats };
        if let Value::Object(map) = &mut base {
            map.insert("quantity".to_owned(), json!(quantity));
        }
    }
    let mut line_items = vec![base];
    if let Some(seat_price_id) = seat_price_id {
        line_items.push(json!({
            "price": seat_price_id,
            "quantity": seats
        }));
    }
    line_items
}

pub(super) async fn is_metered_price(
    stripe_client: &crate::stripe_api::StripeClient,
    price_id: &str,
) -> bool {
    stripe_client
        .retrieve_price(price_id)
        .await
        .ok()
        .and_then(|price| {
            price
                .get("recurring")
                .and_then(|recurring| recurring.get("usage_type"))
                .and_then(Value::as_str)
                .map(|usage_type| usage_type == "metered")
        })
        .unwrap_or(false)
}
