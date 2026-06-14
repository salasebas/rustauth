use rustauth_core::db::{Create, DbRecord, DbValue, FindOne, Update, Where};
use rustauth_core::error::RustAuthError;
use time::OffsetDateTime;

use crate::models::{StripeSubscription, Subscription};
use crate::options::StripePlan;

pub(super) fn customer_id_from_stripe_subscription(
    subscription: &StripeSubscription,
) -> Option<String> {
    match subscription.customer.as_ref()? {
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Object(object) => object
            .get("id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        _ => None,
    }
}

pub(super) async fn find_reference_by_stripe_customer_id(
    adapter: &dyn rustauth_core::db::DbAdapter,
    customer_id: &str,
    prefer_organization: bool,
) -> Result<Option<String>, RustAuthError> {
    if prefer_organization {
        if let Some(reference_id) = adapter
            .find_one(FindOne::new("organization").where_clause(Where::new(
                "stripe_customer_id",
                DbValue::String(customer_id.to_owned()),
            )))
            .await?
            .and_then(|record| record_string(&record, "id").map(str::to_owned))
        {
            return Ok(Some(reference_id));
        }
    }
    Ok(adapter
        .find_one(FindOne::new("user").where_clause(Where::new(
            "stripe_customer_id",
            DbValue::String(customer_id.to_owned()),
        )))
        .await?
        .and_then(|record| record_string(&record, "id").map(str::to_owned)))
}

pub(super) fn record_string<'a>(record: &'a DbRecord, field: &str) -> Option<&'a str> {
    match record.get(field) {
        Some(DbValue::String(value)) => Some(value.as_str()),
        _ => None,
    }
}

pub(super) fn subscription_from_record(record: &DbRecord) -> Option<Subscription> {
    Some(Subscription {
        id: record_string(record, "id")?.to_owned(),
        plan: record_string(record, "plan").unwrap_or_default().to_owned(),
        reference_id: record_string(record, "reference_id")
            .unwrap_or_default()
            .to_owned(),
        stripe_customer_id: record_string(record, "stripe_customer_id").map(str::to_owned),
        stripe_subscription_id: record_string(record, "stripe_subscription_id").map(str::to_owned),
        status: record_string(record, "status")
            .unwrap_or_default()
            .to_owned(),
        period_start: record_timestamp(record, "period_start"),
        period_end: record_timestamp(record, "period_end"),
        trial_start: record_timestamp(record, "trial_start"),
        trial_end: record_timestamp(record, "trial_end"),
        cancel_at_period_end: record_bool(record, "cancel_at_period_end").unwrap_or(false),
        cancel_at: record_timestamp(record, "cancel_at"),
        canceled_at: record_timestamp(record, "canceled_at"),
        ended_at: record_timestamp(record, "ended_at"),
        seats: record_i64(record, "seats"),
        billing_interval: record_string(record, "billing_interval").map(str::to_owned),
        stripe_schedule_id: record_string(record, "stripe_schedule_id").map(str::to_owned),
    })
}

pub(super) fn record_is_pending_cancel(record: &DbRecord) -> bool {
    record_bool(record, "cancel_at_period_end").unwrap_or(false)
        || record
            .get("cancel_at")
            .is_some_and(|value| !matches!(value, DbValue::Null))
}

fn record_bool(record: &DbRecord, field: &str) -> Option<bool> {
    match record.get(field) {
        Some(DbValue::Boolean(value)) => Some(*value),
        _ => None,
    }
}

fn record_i64(record: &DbRecord, field: &str) -> Option<i64> {
    match record.get(field) {
        Some(DbValue::Number(value)) => Some(*value),
        _ => None,
    }
}

fn record_timestamp(record: &DbRecord, field: &str) -> Option<OffsetDateTime> {
    match record.get(field) {
        Some(DbValue::Timestamp(value)) => Some(*value),
        _ => None,
    }
}

pub(super) fn optional_string(value: Option<String>) -> DbValue {
    value.map(DbValue::String).unwrap_or(DbValue::Null)
}

pub(super) fn plan_limits_value(plan: &StripePlan) -> DbValue {
    plan.limits
        .as_ref()
        .map(|limits| DbValue::Json(limits.clone()))
        .unwrap_or(DbValue::Null)
}

pub(super) fn apply_plan_limits_to_create(create: Create, plan: &StripePlan) -> Create {
    if plan.limits.is_some() {
        create.data("limits", plan_limits_value(plan))
    } else {
        create
    }
}

pub(super) fn apply_plan_limits_to_update(update: Update, plan: Option<&StripePlan>) -> Update {
    match plan.and_then(|plan| plan.limits.as_ref()) {
        Some(limits) => update.data("limits", DbValue::Json(limits.clone())),
        None => update,
    }
}

pub(super) fn optional_unix_timestamp(value: Option<i64>) -> DbValue {
    value
        .and_then(|value| OffsetDateTime::from_unix_timestamp(value).ok())
        .map(DbValue::Timestamp)
        .unwrap_or(DbValue::Null)
}

pub(super) fn optional_stripe_id(value: Option<&serde_json::Value>) -> DbValue {
    match value {
        Some(serde_json::Value::String(value)) => DbValue::String(value.clone()),
        Some(serde_json::Value::Object(object)) => object
            .get("id")
            .and_then(serde_json::Value::as_str)
            .map(|value| DbValue::String(value.to_owned()))
            .unwrap_or(DbValue::Null),
        _ => DbValue::Null,
    }
}
