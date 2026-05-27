use openauth_core::context::AuthContext;
use openauth_core::crypto::random::generate_random_string;
use openauth_core::db::{Create, DbValue, FindMany, FindOne, Update, Where};
use openauth_core::error::OpenAuthError;

use crate::logging;
use crate::metadata::SubscriptionMetadata;
use crate::models::{StripeEvent, StripeSubscription};
use crate::options::{StripeOptions, SubscriptionLifecycleInput, SubscriptionUpdateInput};

use super::support::{
    customer_id_from_stripe_subscription, find_reference_by_stripe_customer_id, optional_string,
    optional_stripe_id, optional_unix_timestamp, record_is_pending_cancel, record_string,
    subscription_from_record,
};

pub(super) async fn on_subscription_deleted(
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
    let subscription = serde_json::from_value::<StripeSubscription>(event.data.object.clone())
        .map_err(|error| OpenAuthError::Api(error.to_string()))?;
    let Some(adapter) = context.adapter() else {
        return Ok(());
    };
    let Some(existing) = adapter
        .find_one(FindOne::new("subscription").where_clause(Where::new(
            "stripe_subscription_id",
            DbValue::String(subscription.id.clone()),
        )))
        .await?
    else {
        logging::webhook_warn(
            context,
            &format!(
                "Stripe webhook warning: Subscription not found for stripeSubscriptionId: {}",
                subscription.id
            ),
        );
        return Ok(());
    };
    let Some(local_subscription_id) = record_string(&existing, "id") else {
        return Ok(());
    };
    let local_subscription = subscription_from_record(&existing);
    let plan = crate::utils::resolve_plan_item(&subscription_options, &subscription.items.data)
        .and_then(|resolved| resolved.plan.cloned());
    adapter
        .update(
            Update::new("subscription")
                .where_clause(Where::new(
                    "id",
                    DbValue::String(local_subscription_id.to_owned()),
                ))
                .data("status", DbValue::String("canceled".to_owned()))
                .data(
                    "cancel_at_period_end",
                    DbValue::Boolean(subscription.cancel_at_period_end),
                )
                .data("cancel_at", optional_unix_timestamp(subscription.cancel_at))
                .data(
                    "canceled_at",
                    optional_unix_timestamp(subscription.canceled_at),
                )
                .data("ended_at", optional_unix_timestamp(subscription.ended_at))
                .data(
                    "trial_start",
                    optional_unix_timestamp(subscription.trial_start),
                )
                .data("trial_end", optional_unix_timestamp(subscription.trial_end))
                .data("stripe_schedule_id", DbValue::Null),
        )
        .await?;
    if let (Some(hook), Some(local_subscription)) = (
        &subscription_options.on_subscription_deleted,
        local_subscription,
    ) {
        let _ = hook(SubscriptionLifecycleInput {
            event: event.clone(),
            subscription: local_subscription,
            stripe_subscription: Some(subscription),
            plan,
            cancellation_details: None,
        })
        .await;
    }
    Ok(())
}

pub(super) async fn on_subscription_updated(
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
    let subscription = serde_json::from_value::<StripeSubscription>(event.data.object.clone())
        .map_err(|error| OpenAuthError::Api(error.to_string()))?;
    let Some(resolved) =
        crate::utils::resolve_plan_item(&subscription_options, &subscription.items.data)
    else {
        logging::webhook_warn(
            context,
            &format!(
                "Stripe webhook warning: Subscription {} has no items matching a configured plan",
                subscription.id
            ),
        );
        return Ok(());
    };
    let Some(adapter) = context.adapter() else {
        return Ok(());
    };
    let metadata = SubscriptionMetadata::get(&subscription.metadata);
    let subscription_record = if let Some(subscription_id) = metadata.subscription_id {
        adapter
            .find_one(
                FindOne::new("subscription")
                    .where_clause(Where::new("id", DbValue::String(subscription_id))),
            )
            .await?
    } else {
        adapter
            .find_one(FindOne::new("subscription").where_clause(Where::new(
                "stripe_subscription_id",
                DbValue::String(subscription.id.clone()),
            )))
            .await?
    };
    let subscription_record = match subscription_record {
        Some(subscription_record) => Some(subscription_record),
        None => {
            let customer_id = customer_id_from_stripe_subscription(&subscription);
            if let Some(customer_id) = customer_id {
                let subscriptions = adapter
                    .find_many(FindMany::new("subscription").where_clause(Where::new(
                        "stripe_customer_id",
                        DbValue::String(customer_id),
                    )))
                    .await?;
                if subscriptions.len() > 1 {
                    subscriptions.into_iter().find(|record| {
                        record_string(record, "status")
                            .is_some_and(crate::utils::is_active_or_trialing)
                    })
                } else {
                    subscriptions.into_iter().next()
                }
            } else {
                None
            }
        }
    };
    let Some(subscription_record) = subscription_record else {
        return Ok(());
    };
    let Some(local_subscription_id) = record_string(&subscription_record, "id") else {
        return Ok(());
    };
    let previous_subscription = subscription_from_record(&subscription_record);
    let was_pending_cancel = record_is_pending_cancel(&subscription_record);
    let was_trialing = record_string(&subscription_record, "status") == Some("trialing");
    let quantity = crate::utils::resolve_quantity(
        &subscription.items.data,
        resolved.item,
        resolved.plan.and_then(|plan| plan.seat_price_id.as_deref()),
    );
    let billing_interval = resolved
        .item
        .price
        .recurring
        .as_ref()
        .map(|recurring| recurring.interval.clone());
    let is_new_pending_cancel = subscription.status == "active"
        && (subscription.cancel_at_period_end || subscription.cancel_at.is_some())
        && !was_pending_cancel;
    let is_trial_end = subscription.status == "active" && was_trialing;
    let is_trial_expired = subscription.status == "incomplete_expired" && was_trialing;
    let mut update = Update::new("subscription")
        .where_clause(Where::new(
            "id",
            DbValue::String(local_subscription_id.to_owned()),
        ))
        .data("status", DbValue::String(subscription.status.clone()))
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
            optional_unix_timestamp(subscription.trial_start),
        )
        .data("trial_end", optional_unix_timestamp(subscription.trial_end))
        .data(
            "cancel_at_period_end",
            DbValue::Boolean(subscription.cancel_at_period_end),
        )
        .data("cancel_at", optional_unix_timestamp(subscription.cancel_at))
        .data(
            "canceled_at",
            optional_unix_timestamp(subscription.canceled_at),
        )
        .data("ended_at", optional_unix_timestamp(subscription.ended_at))
        .data("seats", DbValue::Number(quantity))
        .data("billing_interval", optional_string(billing_interval))
        .data(
            "stripe_schedule_id",
            optional_stripe_id(subscription.schedule.as_ref()),
        )
        .data(
            "stripe_subscription_id",
            DbValue::String(subscription.id.clone()),
        );
    if let Some(plan) = resolved.plan {
        update = update.data("plan", DbValue::String(plan.name.to_ascii_lowercase()));
    }
    adapter.update(update).await?;
    if is_new_pending_cancel {
        if let (Some(hook), Some(local_subscription)) = (
            &subscription_options.on_subscription_cancel,
            previous_subscription.clone(),
        ) {
            let _ = hook(SubscriptionLifecycleInput {
                event: event.clone(),
                subscription: local_subscription,
                stripe_subscription: Some(subscription.clone()),
                plan: resolved.plan.cloned(),
                cancellation_details: event.data.object.get("cancellation_details").cloned(),
            })
            .await;
        }
    }
    if let (Some(plan), Some(local_subscription)) = (resolved.plan, previous_subscription.clone()) {
        if is_trial_end {
            if let Some(hook) = plan
                .free_trial
                .as_ref()
                .and_then(|free_trial| free_trial.on_trial_end.as_ref())
            {
                let _ = hook(local_subscription.clone(), context).await;
            }
        }
        if is_trial_expired {
            if let Some(hook) = plan
                .free_trial
                .as_ref()
                .and_then(|free_trial| free_trial.on_trial_expired.as_ref())
            {
                let _ = hook(local_subscription, context).await;
            }
        }
    }
    if let Some(hook) = &subscription_options.on_subscription_update {
        if let Some(updated_record) = adapter
            .find_one(FindOne::new("subscription").where_clause(Where::new(
                "id",
                DbValue::String(local_subscription_id.to_owned()),
            )))
            .await?
        {
            if let Some(subscription) = subscription_from_record(&updated_record) {
                let _ = hook(SubscriptionUpdateInput {
                    event: event.clone(),
                    subscription,
                })
                .await;
            }
        }
    }
    Ok(())
}

pub(super) async fn on_subscription_created(
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
    let subscription = serde_json::from_value::<StripeSubscription>(event.data.object.clone())
        .map_err(|error| OpenAuthError::Api(error.to_string()))?;
    let Some(customer_id) = customer_id_from_stripe_subscription(&subscription) else {
        logging::webhook_warn(
            context,
            "Stripe webhook warning: customer.subscription.created event received without customer ID",
        );
        return Ok(());
    };
    let metadata = SubscriptionMetadata::get(&subscription.metadata);
    let Some(adapter) = context.adapter() else {
        return Ok(());
    };
    let existing = if let Some(subscription_id) = metadata.subscription_id {
        adapter
            .find_one(
                FindOne::new("subscription")
                    .where_clause(Where::new("id", DbValue::String(subscription_id))),
            )
            .await?
    } else {
        adapter
            .find_one(FindOne::new("subscription").where_clause(Where::new(
                "stripe_subscription_id",
                DbValue::String(subscription.id.clone()),
            )))
            .await?
    };
    if let Some(existing) = existing {
        if let Some(subscription_id) = record_string(&existing, "id") {
            logging::webhook_info(
                context,
                &format!(
                    "Stripe webhook: Subscription already exists in database (id: {subscription_id}), skipping creation"
                ),
            );
        }
        return Ok(());
    }
    let prefer_organization = options.organization.as_ref().is_some_and(|org| org.enabled);
    let Some(reference_id) =
        find_reference_by_stripe_customer_id(adapter.as_ref(), &customer_id, prefer_organization)
            .await?
    else {
        logging::webhook_warn(
            context,
            &format!(
                "Stripe webhook warning: No user or organization found with stripeCustomerId: {customer_id}"
            ),
        );
        return Ok(());
    };
    let Some(resolved) =
        crate::utils::resolve_plan_item(&subscription_options, &subscription.items.data)
    else {
        logging::webhook_warn(
            context,
            &format!(
                "Stripe webhook warning: Subscription {} has no items matching a configured plan",
                subscription.id
            ),
        );
        return Ok(());
    };
    let Some(plan) = resolved.plan else {
        logging::webhook_warn(
            context,
            &format!(
                "Stripe webhook warning: No matching plan found for subscription {}",
                subscription.id
            ),
        );
        return Ok(());
    };
    let quantity = crate::utils::resolve_quantity(
        &subscription.items.data,
        resolved.item,
        plan.seat_price_id.as_deref(),
    );
    let billing_interval = resolved
        .item
        .price
        .recurring
        .as_ref()
        .map(|recurring| recurring.interval.clone());
    let stripe_subscription_id = subscription.id.clone();
    let stripe_status = subscription.status.clone();
    let created = adapter
        .create(
            Create::new("subscription")
                .data(
                    "id",
                    DbValue::String(format!("sub_{}", generate_random_string(24))),
                )
                .data("reference_id", DbValue::String(reference_id))
                .data("stripe_customer_id", DbValue::String(customer_id))
                .data(
                    "stripe_subscription_id",
                    DbValue::String(stripe_subscription_id),
                )
                .data("status", DbValue::String(stripe_status))
                .data("plan", DbValue::String(plan.name.to_ascii_lowercase()))
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
                    optional_unix_timestamp(subscription.trial_start),
                )
                .data("trial_end", optional_unix_timestamp(subscription.trial_end))
                .data(
                    "cancel_at_period_end",
                    DbValue::Boolean(subscription.cancel_at_period_end),
                )
                .data("cancel_at", optional_unix_timestamp(subscription.cancel_at))
                .data(
                    "canceled_at",
                    optional_unix_timestamp(subscription.canceled_at),
                )
                .data("ended_at", optional_unix_timestamp(subscription.ended_at))
                .data("seats", DbValue::Number(quantity))
                .data("billing_interval", optional_string(billing_interval))
                .data("stripe_schedule_id", DbValue::Null)
                .force_allow_id(),
        )
        .await?;
    if let Some(hook) = &subscription_options.on_subscription_created {
        if let Some(local_subscription) = subscription_from_record(&created) {
            let _ = hook(SubscriptionLifecycleInput {
                event: event.clone(),
                subscription: local_subscription,
                stripe_subscription: Some(subscription.clone()),
                plan: Some(plan.clone()),
                cancellation_details: None,
            })
            .await;
        }
    }
    Ok(())
}
