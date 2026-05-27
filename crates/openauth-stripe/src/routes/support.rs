use http::{header, Response, StatusCode};
use openauth_core::api::{ApiErrorResponse, ApiRequest, ApiResponse};
use openauth_core::auth::session::{GetSessionInput, SessionAuth};
use openauth_core::context::AuthContext;
use openauth_core::crypto::random::generate_random_string;
use openauth_core::db::{Create, DbRecord, DbValue, FindMany, Update, Where};
use openauth_core::error::OpenAuthError;
use serde::Serialize;
use serde_json::{json, Value};

use crate::errors::StripeErrorCode;
use crate::options::SubscriptionOptions;
use crate::stripe_api::StripeApiError;

pub(super) async fn require_session(
    context: &AuthContext,
    request: &ApiRequest,
) -> Result<Option<openauth_core::context::request_state::CurrentSession>, OpenAuthError> {
    let Some(adapter) = context.adapter() else {
        return Ok(None);
    };
    let cookie_header = request
        .headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let Some(result) = SessionAuth::new(adapter.as_ref(), context)
        .get_session(GetSessionInput::new(cookie_header))
        .await?
    else {
        return Ok(None);
    };
    let Some(session) = result.session else {
        return Ok(None);
    };
    let Some(user) = result.user else {
        return Ok(None);
    };
    Ok(Some(
        openauth_core::context::request_state::CurrentSession { session, user },
    ))
}

pub(super) async fn resolve_subscription_options_for_endpoint(
    subscription_options: &SubscriptionOptions,
) -> Result<Result<SubscriptionOptions, ApiResponse>, OpenAuthError> {
    match subscription_options.resolve_plans().await {
        Ok(subscription_options) => Ok(Ok(subscription_options)),
        Err(_) => Ok(Err(error_response(
            StatusCode::BAD_REQUEST,
            StripeErrorCode::FailedToFetchPlans,
        )?)),
    }
}

pub(super) async fn find_subscription_for_reference(
    adapter: &dyn openauth_core::db::DbAdapter,
    reference_id: &str,
    stripe_subscription_id: Option<&str>,
) -> Result<Option<DbRecord>, OpenAuthError> {
    if let Some(stripe_subscription_id) = stripe_subscription_id {
        let subscription = adapter
            .find_many(
                FindMany::new("subscription")
                    .where_clause(Where::new(
                        "stripe_subscription_id",
                        DbValue::String(stripe_subscription_id.to_owned()),
                    ))
                    .limit(1),
            )
            .await?
            .into_iter()
            .find(|record| {
                record
                    .get("reference_id")
                    .and_then(db_string)
                    .is_some_and(|stored_reference_id| stored_reference_id == reference_id)
            });
        return Ok(subscription);
    }
    Ok(active_subscription_records(adapter, reference_id)
        .await?
        .into_iter()
        .next())
}

pub(super) fn record_is_active_or_trialing(record: &DbRecord) -> bool {
    record
        .get("status")
        .and_then(db_string)
        .is_some_and(crate::utils::is_active_or_trialing)
}

pub(super) fn record_has_pending_cancel(record: &DbRecord) -> bool {
    record
        .get("cancel_at_period_end")
        .and_then(db_bool)
        .unwrap_or(false)
        || record
            .get("cancel_at")
            .is_some_and(|value| !is_db_null(value))
}

pub(super) fn stripe_list_has_active_subscription(list: &Value, subscription_id: &str) -> bool {
    find_active_stripe_subscription(list, subscription_id).is_some()
}

pub(super) fn find_active_stripe_subscription<'a>(
    list: &'a Value,
    subscription_id: &str,
) -> Option<&'a Value> {
    list.get("data")?.as_array()?.iter().find(|subscription| {
        subscription.get("id").and_then(Value::as_str) == Some(subscription_id)
            && subscription
                .get("status")
                .and_then(Value::as_str)
                .is_some_and(crate::utils::is_active_or_trialing)
    })
}

pub(super) async fn clear_subscription_cancel(
    adapter: &dyn openauth_core::db::DbAdapter,
    subscription_id: &str,
) -> Result<(), OpenAuthError> {
    adapter
        .update(
            Update::new("subscription")
                .where_clause(Where::new(
                    "id",
                    DbValue::String(subscription_id.to_owned()),
                ))
                .data("cancel_at_period_end", DbValue::Boolean(false))
                .data("cancel_at", DbValue::Null)
                .data("canceled_at", DbValue::Null),
        )
        .await?;
    Ok(())
}

pub(super) async fn clear_subscription_schedule(
    adapter: &dyn openauth_core::db::DbAdapter,
    subscription_id: &str,
) -> Result<(), OpenAuthError> {
    adapter
        .update(
            Update::new("subscription")
                .where_clause(Where::new(
                    "id",
                    DbValue::String(subscription_id.to_owned()),
                ))
                .data("stripe_schedule_id", DbValue::Null),
        )
        .await?;
    Ok(())
}

pub(super) async fn subscription_records_for_reference(
    adapter: &dyn openauth_core::db::DbAdapter,
    reference_id: &str,
) -> Result<Vec<DbRecord>, OpenAuthError> {
    Ok(adapter
        .find_many(FindMany::new("subscription").where_clause(Where::new(
            "reference_id",
            DbValue::String(reference_id.to_owned()),
        )))
        .await?)
}

pub(super) fn find_incomplete_subscription_record(records: &[DbRecord]) -> Option<&DbRecord> {
    records.iter().find(|record| {
        record
            .get("status")
            .and_then(db_string)
            .is_some_and(|status| status == "incomplete")
    })
}

pub(super) async fn link_stripe_subscription_id(
    adapter: &dyn openauth_core::db::DbAdapter,
    local_subscription_id: &str,
    stripe_subscription_id: &str,
) -> Result<(), OpenAuthError> {
    adapter
        .update(
            Update::new("subscription")
                .where_clause(Where::new(
                    "id",
                    DbValue::String(local_subscription_id.to_owned()),
                ))
                .data(
                    "stripe_subscription_id",
                    DbValue::String(stripe_subscription_id.to_owned()),
                ),
        )
        .await?;
    Ok(())
}

pub(super) async fn reuse_or_create_incomplete_subscription(
    adapter: &dyn openauth_core::db::DbAdapter,
    plan: &str,
    reference_id: &str,
    stripe_customer_id: Option<&str>,
    annual: bool,
    seats: i64,
    local_records: &[DbRecord],
    has_active_or_trialing: bool,
) -> Result<String, OpenAuthError> {
    if !has_active_or_trialing {
        if let Some(incomplete) = find_incomplete_subscription_record(local_records) {
            let Some(local_id) = incomplete.get("id").and_then(db_string) else {
                return create_incomplete_subscription(
                    adapter,
                    plan,
                    reference_id,
                    stripe_customer_id,
                    annual,
                    seats,
                )
                .await;
            };
            let billing_interval = if annual { "year" } else { "month" };
            adapter
                .update(
                    Update::new("subscription")
                        .where_clause(Where::new("id", DbValue::String(local_id.to_owned())))
                        .data("plan", DbValue::String(plan.to_owned()))
                        .data("seats", DbValue::Number(seats))
                        .data(
                            "billing_interval",
                            DbValue::String(billing_interval.to_owned()),
                        )
                        .data(
                            "stripe_customer_id",
                            stripe_customer_id
                                .map(|customer_id| DbValue::String(customer_id.to_owned()))
                                .unwrap_or(DbValue::Null),
                        ),
                )
                .await?;
            return Ok(local_id.to_owned());
        }
    }
    create_incomplete_subscription(
        adapter,
        plan,
        reference_id,
        stripe_customer_id,
        annual,
        seats,
    )
    .await
}

pub(super) async fn create_incomplete_subscription(
    adapter: &dyn openauth_core::db::DbAdapter,
    plan: &str,
    reference_id: &str,
    stripe_customer_id: Option<&str>,
    annual: bool,
    seats: i64,
) -> Result<String, OpenAuthError> {
    let id = format!("sub_{}", generate_random_string(24));
    let billing_interval = if annual { "year" } else { "month" };
    adapter
        .create(
            Create::new("subscription")
                .data("id", DbValue::String(id.clone()))
                .data("plan", DbValue::String(plan.to_owned()))
                .data("reference_id", DbValue::String(reference_id.to_owned()))
                .data(
                    "stripe_customer_id",
                    stripe_customer_id
                        .map(|customer_id| DbValue::String(customer_id.to_owned()))
                        .unwrap_or(DbValue::Null),
                )
                .data("stripe_subscription_id", DbValue::Null)
                .data("status", DbValue::String("incomplete".to_owned()))
                .data("period_start", DbValue::Null)
                .data("period_end", DbValue::Null)
                .data("trial_start", DbValue::Null)
                .data("trial_end", DbValue::Null)
                .data("cancel_at_period_end", DbValue::Boolean(false))
                .data("cancel_at", DbValue::Null)
                .data("canceled_at", DbValue::Null)
                .data("ended_at", DbValue::Null)
                .data("seats", DbValue::Number(seats))
                .data(
                    "billing_interval",
                    DbValue::String(billing_interval.to_owned()),
                )
                .data("stripe_schedule_id", DbValue::Null)
                .force_allow_id(),
        )
        .await?;
    Ok(id)
}

pub(super) async fn reference_has_ever_trialed(
    adapter: &dyn openauth_core::db::DbAdapter,
    reference_id: &str,
) -> Result<bool, OpenAuthError> {
    let records = adapter
        .find_many(
            FindMany::new("subscription")
                .where_clause(Where::new(
                    "reference_id",
                    DbValue::String(reference_id.to_owned()),
                ))
                .limit(100),
        )
        .await?;
    Ok(records.into_iter().any(|record| {
        record
            .get("status")
            .and_then(db_string)
            .is_some_and(|status| status == "trialing")
            || record
                .get("trial_start")
                .is_some_and(|value| !is_db_null(value))
            || record
                .get("trial_end")
                .is_some_and(|value| !is_db_null(value))
    }))
}

pub(super) async fn active_subscription_records(
    adapter: &dyn openauth_core::db::DbAdapter,
    reference_id: &str,
) -> Result<Vec<DbRecord>, OpenAuthError> {
    let records = adapter
        .find_many(
            FindMany::new("subscription")
                .where_clause(Where::new(
                    "reference_id",
                    DbValue::String(reference_id.to_owned()),
                ))
                .limit(100),
        )
        .await?;
    Ok(records
        .into_iter()
        .filter(|record| {
            record
                .get("status")
                .and_then(db_string)
                .is_some_and(crate::utils::is_active_or_trialing)
        })
        .collect())
}

pub(super) async fn active_subscription_customer(
    adapter: &dyn openauth_core::db::DbAdapter,
    reference_id: &str,
) -> Result<Option<String>, OpenAuthError> {
    Ok(active_subscription_records(adapter, reference_id)
        .await?
        .into_iter()
        .find_map(|record| {
            record
                .get("stripe_customer_id")
                .and_then(db_string)
                .map(str::to_owned)
        }))
}

pub(super) fn subscription_record_to_json(record: DbRecord) -> Value {
    json!({
        "id": record.get("id").and_then(db_string),
        "plan": record.get("plan").and_then(db_string),
        "referenceId": record.get("reference_id").and_then(db_string),
        "stripeCustomerId": record.get("stripe_customer_id").and_then(db_string),
        "stripeSubscriptionId": record.get("stripe_subscription_id").and_then(db_string),
        "status": record.get("status").and_then(db_string),
        "periodStart": record.get("period_start").and_then(db_timestamp),
        "periodEnd": record.get("period_end").and_then(db_timestamp),
        "trialStart": record.get("trial_start").and_then(db_timestamp),
        "trialEnd": record.get("trial_end").and_then(db_timestamp),
        "cancelAtPeriodEnd": record
            .get("cancel_at_period_end")
            .and_then(db_bool)
            .unwrap_or(false),
        "cancelAt": record.get("cancel_at").and_then(db_timestamp),
        "canceledAt": record.get("canceled_at").and_then(db_timestamp),
        "endedAt": record.get("ended_at").and_then(db_timestamp),
        "seats": record.get("seats").and_then(db_i64),
        "billingInterval": record.get("billing_interval").and_then(db_string),
        "stripeScheduleId": record.get("stripe_schedule_id").and_then(db_string),
    })
}

pub(super) fn db_string(value: &DbValue) -> Option<&str> {
    match value {
        DbValue::String(value) => Some(value.as_str()),
        _ => None,
    }
}

fn db_bool(value: &DbValue) -> Option<bool> {
    match value {
        DbValue::Boolean(value) => Some(*value),
        _ => None,
    }
}

fn db_i64(value: &DbValue) -> Option<i64> {
    match value {
        DbValue::Number(value) => Some(*value),
        _ => None,
    }
}

fn db_timestamp(value: &DbValue) -> Option<String> {
    match value {
        DbValue::Timestamp(value) => Some(
            value
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| value.unix_timestamp().to_string()),
        ),
        _ => None,
    }
}

fn is_db_null(value: &DbValue) -> bool {
    matches!(value, DbValue::Null)
}

pub(super) fn validate_redirect_url(
    context: &AuthContext,
    request: &ApiRequest,
    url: String,
) -> Result<Option<String>, OpenAuthError> {
    if url.starts_with('/') && !url.starts_with("//") {
        return Ok(Some(url));
    }
    if context.is_trusted_origin_for_request(&url, None, Some(request))? {
        return Ok(Some(url));
    }
    Ok(None)
}

pub(super) fn query_param(request: &ApiRequest, name: &str) -> Option<String> {
    request.uri().query().and_then(|query| {
        query.split('&').find_map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (key == name).then(|| percent_decode(value))
        })
    })
}

fn percent_decode(value: &str) -> String {
    let encoded_pair = format!("value={value}");
    url::form_urlencoded::parse(encoded_pair.as_bytes())
        .map(|(_, value)| value.into_owned())
        .next()
        .unwrap_or_default()
}

pub(super) fn redirect_response(location: &str) -> Result<ApiResponse, OpenAuthError> {
    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, location)
        .body(Vec::new())
        .map_err(|error| OpenAuthError::Api(error.to_string()))
}

pub(super) fn json_response<T: Serialize>(
    status: StatusCode,
    body: &T,
) -> Result<ApiResponse, OpenAuthError> {
    let body = serde_json::to_vec(body).map_err(|error| OpenAuthError::Serialization {
        context: "serializing stripe response",
        message: error.to_string(),
    })?;
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .map_err(|error| OpenAuthError::Api(error.to_string()))
}

pub(super) fn error_response(
    status: StatusCode,
    code: StripeErrorCode,
) -> Result<ApiResponse, OpenAuthError> {
    plugin_error_response(status, code, None)
}

pub(super) fn plugin_error_response(
    status: StatusCode,
    code: StripeErrorCode,
    original_message: Option<String>,
) -> Result<ApiResponse, OpenAuthError> {
    json_response(
        status,
        &ApiErrorResponse {
            code: code.code().to_owned(),
            message: code.message().to_owned(),
            original_message,
        },
    )
}

pub(super) fn respond_stripe_api_error(
    error: StripeApiError,
    default: StripeErrorCode,
) -> Result<ApiResponse, OpenAuthError> {
    let (status, code) = error.plugin_response(default);
    plugin_error_response(status, code, stripe_original_message(&error))
}

fn stripe_original_message(error: &StripeApiError) -> Option<String> {
    match error {
        StripeApiError::Stripe { message, .. } => Some(message.clone()),
        StripeApiError::Transport(message) => Some(message.clone()),
        StripeApiError::Webhook(_) => None,
    }
}
