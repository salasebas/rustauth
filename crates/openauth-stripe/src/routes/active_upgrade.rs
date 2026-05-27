use http::StatusCode;
use openauth_core::api::{ApiRequest, ApiResponse};
use openauth_core::context::AuthContext;
use openauth_core::db::{DbAdapter, DbRecord, DbValue, Update, Where};
use openauth_core::error::OpenAuthError;
use serde_json::{json, Value};

use super::support::{
    db_string, error_response, json_response, respond_stripe_api_error, validate_redirect_url,
};
use crate::errors::StripeErrorCode;
use crate::models::{StripeSubscription, StripeSubscriptionItem};
use crate::options::{StripeOptions, StripePlan, SubscriptionOptions};

pub(super) struct ActiveUpgradeInput<'a> {
    pub context: &'a AuthContext,
    pub request: &'a ApiRequest,
    pub adapter: &'a dyn DbAdapter,
    pub options: &'a StripeOptions,
    pub subscription_options: &'a SubscriptionOptions,
    pub local_subscription: &'a DbRecord,
    pub plan: &'a StripePlan,
    pub price_id: &'a str,
    pub customer_id: &'a str,
    pub seats: i64,
    pub return_url: Option<String>,
    pub disable_redirect: bool,
    pub schedule_at_period_end: bool,
}

pub(super) async fn handle(input: ActiveUpgradeInput<'_>) -> Result<ApiResponse, OpenAuthError> {
    let Some(stripe_subscription_id) = input
        .local_subscription
        .get("stripe_subscription_id")
        .and_then(db_string)
        .map(str::to_owned)
    else {
        return error_response(
            StatusCode::BAD_REQUEST,
            StripeErrorCode::SubscriptionNotFound,
        );
    };
    let active_stripe_subscriptions = match input
        .options
        .stripe_client
        .list_subscriptions(json!({ "customer": input.customer_id }))
        .await
    {
        Ok(active_stripe_subscriptions) => active_stripe_subscriptions,
        Err(error) => {
            return respond_stripe_api_error(error, StripeErrorCode::SubscriptionNotFound)
        }
    };
    let Some(active_stripe_subscription) = active_stripe_subscriptions
        .get("data")
        .and_then(Value::as_array)
        .and_then(|subscriptions| {
            subscriptions.iter().find(|subscription| {
                subscription.get("id").and_then(Value::as_str)
                    == Some(stripe_subscription_id.as_str())
            })
        })
        .cloned()
    else {
        return error_response(
            StatusCode::BAD_REQUEST,
            StripeErrorCode::SubscriptionNotFound,
        );
    };
    let active_stripe_subscription =
        match serde_json::from_value::<StripeSubscription>(active_stripe_subscription) {
            Ok(subscription) => subscription,
            Err(_) => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    StripeErrorCode::SubscriptionNotFound,
                );
            }
        };
    let Some(current_item) = crate::utils::resolve_plan_item(
        input.subscription_options,
        &active_stripe_subscription.items.data,
    )
    .map(|resolved| resolved.item)
    .or_else(|| active_stripe_subscription.items.data.first()) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            StripeErrorCode::SubscriptionNotFound,
        );
    };
    if let Some(response) =
        release_plugin_schedule_if_needed(&input, &active_stripe_subscription).await?
    {
        return Ok(response);
    }
    let return_url = validate_redirect_url(
        input.context,
        input.request,
        input.return_url.clone().unwrap_or_else(|| "/".to_owned()),
    )?
    .unwrap_or_else(|| "/".to_owned());
    if input.schedule_at_period_end {
        return schedule_period_end_change(
            input,
            &active_stripe_subscription,
            current_item,
            &return_url,
        )
        .await;
    }
    if has_direct_subscription_update_changes(
        input.local_subscription,
        input.subscription_options,
        input.plan,
        input.seats,
    ) {
        return direct_subscription_update(
            input,
            &active_stripe_subscription,
            current_item,
            &return_url,
        )
        .await;
    }
    billing_portal_update(input, current_item, &stripe_subscription_id, &return_url).await
}

async fn release_plugin_schedule_if_needed(
    input: &ActiveUpgradeInput<'_>,
    active_subscription: &StripeSubscription,
) -> Result<Option<ApiResponse>, OpenAuthError> {
    if active_subscription.schedule.is_none() {
        return Ok(None);
    }
    let schedules = match input
        .options
        .stripe_client
        .list_subscription_schedules(json!({
            "customer": input.customer_id,
        }))
        .await
    {
        Ok(schedules) => schedules,
        Err(_) => return Ok(None),
    };
    let Some(schedule_id) = schedules
        .get("data")
        .and_then(Value::as_array)
        .and_then(|schedules| {
            schedules.iter().find_map(|schedule| {
                let matches_subscription = schedule_subscription_id(schedule).as_deref()
                    == Some(active_subscription.id.as_str());
                let is_active = schedule.get("status").and_then(Value::as_str) == Some("active");
                let is_plugin_owned = schedule
                    .get("metadata")
                    .and_then(|metadata| metadata.get("source"))
                    .and_then(Value::as_str)
                    == Some("@better-auth/stripe");
                (matches_subscription && is_active && is_plugin_owned)
                    .then(|| {
                        schedule
                            .get("id")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    })
                    .flatten()
            })
        })
    else {
        return Ok(None);
    };
    if let Err(error) = input
        .options
        .stripe_client
        .release_subscription_schedule(&schedule_id)
        .await
    {
        return Ok(Some(respond_stripe_api_error(
            error,
            StripeErrorCode::SubscriptionNotFound,
        )?));
    }
    if let Some(local_subscription_id) = input.local_subscription.get("id").and_then(db_string) {
        input
            .adapter
            .update(
                Update::new("subscription")
                    .where_clause(Where::new(
                        "id",
                        DbValue::String(local_subscription_id.to_owned()),
                    ))
                    .data("stripe_schedule_id", DbValue::Null),
            )
            .await?;
    }
    Ok(None)
}

fn schedule_subscription_id(schedule: &Value) -> Option<String> {
    match schedule.get("subscription")? {
        Value::String(subscription) => Some(subscription.clone()),
        Value::Object(subscription) => subscription
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_owned),
        _ => None,
    }
}

async fn billing_portal_update(
    input: ActiveUpgradeInput<'_>,
    current_item: &StripeSubscriptionItem,
    stripe_subscription_id: &str,
    return_url: &str,
) -> Result<ApiResponse, OpenAuthError> {
    let mut update_item = json!({
        "id": current_item.id,
        "price": input.price_id,
    });
    let auto_managed_seats = input.plan.seat_price_id.is_some();
    if !super::upgrade::is_metered_price(&input.options.stripe_client, input.price_id).await
        && !auto_managed_seats
    {
        if let Value::Object(map) = &mut update_item {
            map.insert("quantity".to_owned(), json!(input.seats));
        }
    }
    let portal = match input
        .options
        .stripe_client
        .create_billing_portal_session(json!({
            "customer": input.customer_id,
            "return_url": return_url,
            "flow_data": {
                "type": "subscription_update_confirm",
                "after_completion": {
                    "type": "redirect",
                    "redirect": {
                        "return_url": return_url,
                    }
                },
                "subscription_update_confirm": {
                    "subscription": stripe_subscription_id,
                    "items": [update_item],
                }
            }
        }))
        .await
    {
        Ok(portal) => portal,
        Err(error) => {
            return respond_stripe_api_error(error, StripeErrorCode::UnableToCreateBillingPortal);
        }
    };
    let mut response = portal;
    if let Value::Object(map) = &mut response {
        map.insert("redirect".to_owned(), Value::Bool(!input.disable_redirect));
    }
    json_response(StatusCode::OK, &response)
}

async fn direct_subscription_update(
    input: ActiveUpgradeInput<'_>,
    active_subscription: &StripeSubscription,
    current_item: &StripeSubscriptionItem,
    return_url: &str,
) -> Result<ApiResponse, OpenAuthError> {
    let is_metered =
        super::upgrade::is_metered_price(&input.options.stripe_client, input.price_id).await;
    let items = direct_update_items(&input, active_subscription, current_item, is_metered);
    let proration = input
        .plan
        .proration_behavior
        .as_deref()
        .unwrap_or("create_prorations");
    if let Err(error) = input
        .options
        .stripe_client
        .update_subscription(
            &active_subscription.id,
            json!({
                "items": items,
                "proration_behavior": proration,
            }),
        )
        .await
    {
        return respond_stripe_api_error(error, StripeErrorCode::UnableToCreateBillingPortal);
    }
    if let Some(local_subscription_id) = input.local_subscription.get("id").and_then(db_string) {
        input
            .adapter
            .update(
                Update::new("subscription")
                    .where_clause(Where::new(
                        "id",
                        DbValue::String(local_subscription_id.to_owned()),
                    ))
                    .data(
                        "plan",
                        DbValue::String(input.plan.name.to_ascii_lowercase()),
                    )
                    .data("seats", DbValue::Number(input.seats)),
            )
            .await?;
    }
    json_response(
        StatusCode::OK,
        &json!({
            "url": return_url,
            "redirect": !input.disable_redirect,
        }),
    )
}

async fn schedule_period_end_change(
    input: ActiveUpgradeInput<'_>,
    active_subscription: &StripeSubscription,
    current_item: &StripeSubscriptionItem,
    return_url: &str,
) -> Result<ApiResponse, OpenAuthError> {
    let schedule = match input
        .options
        .stripe_client
        .create_subscription_schedule(json!({
            "from_subscription": active_subscription.id,
        }))
        .await
    {
        Ok(schedule) => schedule,
        Err(error) => {
            return respond_stripe_api_error(error, StripeErrorCode::UnableToCreateBillingPortal)
        }
    };
    let Some(schedule_id) = schedule.get("id").and_then(Value::as_str) else {
        return error_response(
            StatusCode::BAD_GATEWAY,
            StripeErrorCode::UnableToCreateBillingPortal,
        );
    };
    let Some(current_phase) = schedule
        .get("phases")
        .and_then(Value::as_array)
        .and_then(|phases| phases.first())
    else {
        return error_response(
            StatusCode::BAD_GATEWAY,
            StripeErrorCode::UnableToCreateBillingPortal,
        );
    };
    let current_items = normalize_schedule_phase_items(current_phase);
    let start_date = current_phase
        .get("start_date")
        .cloned()
        .unwrap_or(Value::Null);
    let end_date = current_phase
        .get("end_date")
        .cloned()
        .unwrap_or(Value::Null);
    let is_metered =
        super::upgrade::is_metered_price(&input.options.stripe_client, input.price_id).await;
    let new_items = scheduled_phase_items(&input, active_subscription, current_item, is_metered);
    if let Err(error) = input
        .options
        .stripe_client
        .update_subscription_schedule(
            schedule_id,
            json!({
                "metadata": {
                    "source": "@better-auth/stripe",
                },
                "end_behavior": "release",
                "phases": [
                    {
                        "items": current_items,
                        "start_date": start_date,
                        "end_date": end_date,
                    },
                    {
                        "items": new_items,
                        "start_date": end_date,
                        "proration_behavior": "none",
                    }
                ]
            }),
        )
        .await
    {
        return respond_stripe_api_error(error, StripeErrorCode::UnableToCreateBillingPortal);
    }
    if let Some(local_subscription_id) = input.local_subscription.get("id").and_then(db_string) {
        input
            .adapter
            .update(
                Update::new("subscription")
                    .where_clause(Where::new(
                        "id",
                        DbValue::String(local_subscription_id.to_owned()),
                    ))
                    .data(
                        "stripe_schedule_id",
                        DbValue::String(schedule_id.to_owned()),
                    ),
            )
            .await?;
    }
    json_response(
        StatusCode::OK,
        &json!({
            "url": return_url,
            "redirect": !input.disable_redirect,
        }),
    )
}

fn direct_update_items(
    input: &ActiveUpgradeInput<'_>,
    active_subscription: &StripeSubscription,
    current_item: &StripeSubscriptionItem,
    is_metered: bool,
) -> Vec<Value> {
    let old_plan = input
        .local_subscription
        .get("plan")
        .and_then(db_string)
        .and_then(|plan| crate::utils::get_plan_by_name(input.subscription_options, plan));
    let old_counts = old_plan
        .map(|plan| line_item_price_counts(&plan.line_items))
        .unwrap_or_default();
    let new_counts = line_item_price_counts(&input.plan.line_items);
    let mut remove_quota = line_item_delta(&old_counts, &new_counts);
    let mut add_quota = line_item_delta(&new_counts, &old_counts);
    let mut items = Vec::new();
    for item in &active_subscription.items.data {
        if item.id == current_item.id {
            let mut update = json!({
                "id": item.id,
                "price": input.price_id,
            });
            if !is_metered {
                let quantity = if input.plan.seat_price_id.as_deref().is_some()
                    && input.plan.seat_price_id.as_deref() != Some(input.price_id)
                {
                    1
                } else {
                    input.seats
                };
                if let Value::Object(map) = &mut update {
                    map.insert("quantity".to_owned(), json!(quantity));
                }
            }
            items.push(update);
        } else if old_plan
            .and_then(|plan| plan.seat_price_id.as_deref())
            .is_some_and(|seat_price_id| seat_price_id == item.price.id)
        {
            if let Some(seat_price_id) = input.plan.seat_price_id.as_deref() {
                if seat_price_id != input.price_id {
                    items.push(json!({
                        "id": item.id,
                        "price": seat_price_id,
                        "quantity": input.seats,
                    }));
                }
            } else {
                items.push(json!({
                    "id": item.id,
                    "deleted": true,
                }));
            }
        } else if remove_quota.get_mut(&item.price.id).is_some_and(|quota| {
            if *quota > 0 {
                *quota -= 1;
                true
            } else {
                false
            }
        }) {
            items.push(json!({
                "id": item.id,
                "deleted": true,
            }));
        } else if let Some(quota) = add_quota.get_mut(&item.price.id) {
            if *quota > 0 {
                *quota -= 1;
            }
        }
    }
    for (price, count) in add_quota {
        for _ in 0..count {
            items.push(json!({ "price": price }));
        }
    }
    if let Some(seat_price_id) = input.plan.seat_price_id.as_deref() {
        let already_updated = items.iter().any(|item| {
            item.get("price").and_then(Value::as_str) == Some(seat_price_id)
                || item.get("id").and_then(Value::as_str).is_some_and(|id| {
                    active_subscription.items.data.iter().any(|active_item| {
                        active_item.id == id && active_item.price.id == seat_price_id
                    })
                })
        });
        if seat_price_id != input.price_id && !already_updated {
            items.push(json!({
                "price": seat_price_id,
                "quantity": input.seats,
            }));
        }
    }
    items
}

fn scheduled_phase_items(
    input: &ActiveUpgradeInput<'_>,
    active_subscription: &StripeSubscription,
    current_item: &StripeSubscriptionItem,
    is_metered: bool,
) -> Vec<Value> {
    direct_update_items(input, active_subscription, current_item, is_metered)
        .into_iter()
        .filter_map(|item| {
            let object = item.as_object()?;
            if object
                .get("deleted")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                return None;
            }
            let mut scheduled = serde_json::Map::new();
            let price = object.get("price")?;
            scheduled.insert("price".to_owned(), price.clone());
            if let Some(quantity) = object.get("quantity") {
                scheduled.insert("quantity".to_owned(), quantity.clone());
            }
            Some(Value::Object(scheduled))
        })
        .collect()
}

fn normalize_schedule_phase_items(phase: &Value) -> Value {
    let items = phase
        .get("items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| {
            let price = schedule_item_price_id(item)?;
            let mut normalized = serde_json::Map::new();
            normalized.insert("price".to_owned(), Value::String(price));
            if let Some(quantity) = item.get("quantity").cloned() {
                normalized.insert("quantity".to_owned(), quantity);
            }
            Some(Value::Object(normalized))
        })
        .collect::<Vec<_>>();
    Value::Array(items)
}

fn schedule_item_price_id(item: &Value) -> Option<String> {
    match item.get("price")? {
        Value::String(price) => Some(price.clone()),
        Value::Object(price) => price.get("id").and_then(Value::as_str).map(str::to_owned),
        _ => None,
    }
}

fn has_direct_subscription_update_changes(
    local_subscription: &DbRecord,
    subscription_options: &SubscriptionOptions,
    plan: &StripePlan,
    seats: i64,
) -> bool {
    let old_prices = local_subscription
        .get("plan")
        .and_then(db_string)
        .and_then(|plan| crate::utils::get_plan_by_name(subscription_options, plan))
        .map(plan_fingerprint)
        .unwrap_or_default();
    if old_prices != plan_fingerprint(plan) {
        return true;
    }
    plan.seat_price_id.is_some()
        && local_subscription
            .get("seats")
            .and_then(|value| match value {
                DbValue::Number(seats) => Some(*seats),
                _ => None,
            })
            != Some(seats)
}

fn plan_fingerprint(plan: &StripePlan) -> Vec<String> {
    let mut prices = line_item_prices(&plan.line_items);
    if let Some(seat_price_id) = plan.seat_price_id.as_ref() {
        prices.push(format!("seat:{seat_price_id}"));
    }
    prices
}

fn line_item_prices(line_items: &[Value]) -> Vec<String> {
    line_items
        .iter()
        .filter_map(|line_item| {
            line_item
                .get("price")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect()
}

fn line_item_price_counts(line_items: &[Value]) -> std::collections::BTreeMap<String, usize> {
    let mut counts = std::collections::BTreeMap::new();
    for price in line_item_prices(line_items) {
        *counts.entry(price).or_insert(0) += 1;
    }
    counts
}

fn line_item_delta(
    left: &std::collections::BTreeMap<String, usize>,
    right: &std::collections::BTreeMap<String, usize>,
) -> std::collections::BTreeMap<String, usize> {
    left.iter()
        .filter_map(|(price, left_count)| {
            let right_count = right.get(price).copied().unwrap_or(0);
            left_count
                .checked_sub(right_count)
                .filter(|delta| *delta > 0)
                .map(|delta| (price.clone(), delta))
        })
        .collect()
}
