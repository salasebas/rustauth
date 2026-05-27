use openauth_core::context::AuthContext;
use openauth_core::db::{DbAdapter, DbValue, FindMany, FindOne, Update, Where};
use openauth_core::error::OpenAuthError;

use crate::logging;
use crate::metadata::SubscriptionMetadata;
use crate::models::{StripeCheckoutSession, StripeEvent, StripeSubscription};
use crate::options::{StripeOptions, SubscriptionLifecycleInput};

use super::support::{
    customer_id_from_stripe_subscription, optional_string, optional_unix_timestamp,
    subscription_from_record,
};

pub(super) async fn on_checkout_session_completed(
    context: &AuthContext,
    options: &StripeOptions,
    event: &StripeEvent,
) -> Result<(), OpenAuthError> {
    let Some(subscription_options) = &options.subscription else {
        return Ok(());
    };
    let subscription_options = subscription_options.resolve_plans().await?;
    if !subscription_options.enabled {
        return Ok(());
    }
    let checkout_session =
        serde_json::from_value::<StripeCheckoutSession>(event.data.object.clone())
            .map_err(|error| OpenAuthError::Api(error.to_string()))?;
    if checkout_session.mode.as_deref() == Some("setup") {
        return Ok(());
    }
    let Some(stripe_subscription_id) =
        checkout_session
            .subscription
            .as_ref()
            .and_then(|subscription| match subscription {
                serde_json::Value::String(value) => Some(value.as_str()),
                serde_json::Value::Object(object) => {
                    object.get("id").and_then(serde_json::Value::as_str)
                }
                _ => None,
            })
    else {
        return Ok(());
    };
    let stripe_subscription = options
        .stripe_client
        .retrieve_subscription(stripe_subscription_id)
        .await
        .map_err(|error| OpenAuthError::Api(error.to_string()))?;
    let stripe_subscription = serde_json::from_value::<StripeSubscription>(stripe_subscription)
        .map_err(|error| OpenAuthError::Api(error.to_string()))?;
    let Some(resolved) =
        crate::utils::resolve_plan_item(&subscription_options, &stripe_subscription.items.data)
    else {
        logging::webhook_warn(
            context,
            &format!(
                "Stripe webhook warning: Subscription {} has no items matching a configured plan",
                stripe_subscription.id
            ),
        );
        return Ok(());
    };
    let Some(plan) = resolved.plan else {
        logging::webhook_warn(
            context,
            &format!(
                "Stripe webhook warning: Subscription {} has no items matching a configured plan",
                stripe_subscription.id
            ),
        );
        return Ok(());
    };
    let Some(adapter) = context.adapter() else {
        return Ok(());
    };
    let Some(local_subscription_id) =
        resolve_local_subscription_id(adapter.as_ref(), &checkout_session).await?
    else {
        logging::webhook_warn(
            context,
            &format!(
                "Stripe webhook warning: checkout.session.completed could not resolve local subscription (session {})",
                checkout_session.id
            ),
        );
        return Ok(());
    };
    let customer_id = checkout_session
        .metadata
        .get("stripeCustomerId")
        .cloned()
        .or_else(|| {
            checkout_session
                .subscription
                .as_ref()
                .and_then(|_| customer_id_from_stripe_subscription(&stripe_subscription))
        })
        .or_else(|| {
            event
                .data
                .object
                .get("customer")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        });
    let quantity = crate::utils::resolve_quantity(
        &stripe_subscription.items.data,
        resolved.item,
        plan.seat_price_id.as_deref(),
    );
    let recurring_interval = resolved
        .item
        .price
        .recurring
        .as_ref()
        .map(|recurring| recurring.interval.clone());
    adapter
        .update(
            Update::new("subscription")
                .where_clause(Where::new(
                    "id",
                    DbValue::String(local_subscription_id.clone()),
                ))
                .data("plan", DbValue::String(plan.name.to_ascii_lowercase()))
                .data("stripe_customer_id", optional_string(customer_id))
                .data(
                    "stripe_subscription_id",
                    DbValue::String(stripe_subscription.id.clone()),
                )
                .data(
                    "status",
                    DbValue::String(stripe_subscription.status.clone()),
                )
                .data(
                    "period_start",
                    optional_unix_timestamp(resolved.item.current_period_start),
                )
                .data(
                    "period_end",
                    optional_unix_timestamp(resolved.item.current_period_end),
                )
                .data(
                    "trial_start",
                    optional_unix_timestamp(stripe_subscription.trial_start),
                )
                .data(
                    "trial_end",
                    optional_unix_timestamp(stripe_subscription.trial_end),
                )
                .data(
                    "cancel_at_period_end",
                    DbValue::Boolean(stripe_subscription.cancel_at_period_end),
                )
                .data(
                    "cancel_at",
                    optional_unix_timestamp(stripe_subscription.cancel_at),
                )
                .data(
                    "canceled_at",
                    optional_unix_timestamp(stripe_subscription.canceled_at),
                )
                .data(
                    "ended_at",
                    optional_unix_timestamp(stripe_subscription.ended_at),
                )
                .data("seats", DbValue::Number(quantity))
                .data("billing_interval", optional_string(recurring_interval)),
        )
        .await?;
    if let Some(updated_record) = adapter
        .find_one(
            FindOne::new("subscription")
                .where_clause(Where::new("id", DbValue::String(local_subscription_id))),
        )
        .await?
    {
        if let Some(local_subscription) = subscription_from_record(&updated_record) {
            if stripe_subscription.trial_start.is_some() && stripe_subscription.trial_end.is_some()
            {
                if let Some(hook) = plan
                    .free_trial
                    .as_ref()
                    .and_then(|free_trial| free_trial.on_trial_start.as_ref())
                {
                    let _ = hook(local_subscription.clone()).await;
                }
            }
            if let Some(hook) = &subscription_options.on_subscription_complete {
                let _ = hook(SubscriptionLifecycleInput {
                    event: event.clone(),
                    subscription: local_subscription,
                    stripe_subscription: Some(stripe_subscription.clone()),
                    plan: Some(plan.clone()),
                    cancellation_details: None,
                })
                .await;
            }
        }
    }
    Ok(())
}

async fn resolve_local_subscription_id(
    adapter: &dyn DbAdapter,
    checkout_session: &StripeCheckoutSession,
) -> Result<Option<String>, OpenAuthError> {
    let metadata = SubscriptionMetadata::get(&checkout_session.metadata);
    if let Some(subscription_id) = metadata.subscription_id {
        return Ok(Some(subscription_id));
    }
    let reference_id = checkout_session
        .client_reference_id
        .clone()
        .or(metadata.reference_id);
    let Some(reference_id) = reference_id else {
        return Ok(None);
    };
    let records = adapter
        .find_many(
            FindMany::new("subscription")
                .where_clause(Where::new("reference_id", DbValue::String(reference_id))),
        )
        .await?;
    Ok(records.into_iter().find_map(|record| {
        let incomplete =
            record_string(&record, "status").is_some_and(|status| status == "incomplete");
        let missing_stripe_subscription = match record.get("stripe_subscription_id") {
            None => true,
            Some(DbValue::Null) => true,
            Some(_) => false,
        };
        (incomplete || missing_stripe_subscription)
            .then(|| record_string(&record, "id").map(str::to_owned))?
    }))
}

fn record_string<'a>(record: &'a openauth_core::db::DbRecord, field: &str) -> Option<&'a str> {
    record.get(field).and_then(|value| match value {
        DbValue::String(value) => Some(value.as_str()),
        _ => None,
    })
}
