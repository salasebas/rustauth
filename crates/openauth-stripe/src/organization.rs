use openauth_core::db::{Count, DbAdapter, DbRecord, DbValue, FindMany, Update, Where};
use openauth_core::error::OpenAuthError;
use openauth_core::plugin::{
    PluginDatabaseAfterInput, PluginDatabaseBeforeAction, PluginDatabaseBeforeInput,
    PluginDatabaseHook, PluginDatabaseHookContext, PluginDatabaseOperation,
};

use crate::errors::StripeErrorCode;
use crate::logging;
use crate::options::StripeOptions;
use crate::stripe_api::StripeClient;
use crate::{customers, utils};
use serde_json::json;

pub(crate) fn sync_customer_name_hook(options: StripeOptions) -> PluginDatabaseHook {
    PluginDatabaseHook::after_async(
        "stripe-sync-organization-customer-name",
        PluginDatabaseOperation::Update,
        move |context, input| {
            let options = options.clone();
            Box::pin(async move {
                let PluginDatabaseAfterInput::Update { query, result } = input else {
                    return Ok(());
                };
                if query.model != "organization" {
                    return Ok(());
                }
                let Some(result) = result else {
                    return Ok(());
                };
                if let Err(error) = customers::sync_organization_customer_name_from_record(
                    &options.stripe_client,
                    &result,
                )
                .await
                {
                    logging::hook_error(
                        &context,
                        "Failed to sync organization name to Stripe customer",
                        &error.to_string(),
                    );
                }
                Ok(())
            })
        },
    )
}

pub(crate) fn subscription_database_hooks(options: StripeOptions) -> Vec<PluginDatabaseHook> {
    vec![
        sync_seats_after_member_create_hook(options.clone()),
        sync_seats_after_member_delete_hook(options.clone()),
        sync_seats_after_member_delete_many_hook(options.clone()),
        sync_seats_after_invitation_accept_hook(options.clone()),
        block_active_delete_hook(options.clone()),
        block_active_delete_many_hook(options),
    ]
}

fn block_active_delete_hook(options: StripeOptions) -> PluginDatabaseHook {
    PluginDatabaseHook::before_async(
        "stripe-block-active-organization-delete",
        PluginDatabaseOperation::Delete,
        move |context, input| {
            let options = options.clone();
            Box::pin(async move {
                let PluginDatabaseBeforeInput::Delete { query, snapshots } = input else {
                    return Ok(PluginDatabaseBeforeAction::Continue(input));
                };
                if query.model != "organization" {
                    return Ok(PluginDatabaseBeforeAction::Continue(
                        PluginDatabaseBeforeInput::Delete { query, snapshots },
                    ));
                }
                if snapshots_have_active_subscription(context.adapter, &options, &snapshots).await?
                {
                    return Ok(active_delete_cancel());
                }
                Ok(PluginDatabaseBeforeAction::Continue(
                    PluginDatabaseBeforeInput::Delete { query, snapshots },
                ))
            })
        },
    )
}

fn block_active_delete_many_hook(options: StripeOptions) -> PluginDatabaseHook {
    PluginDatabaseHook::before_async(
        "stripe-block-active-organization-delete-many",
        PluginDatabaseOperation::DeleteMany,
        move |context, input| {
            let options = options.clone();
            Box::pin(async move {
                let PluginDatabaseBeforeInput::DeleteMany { query, snapshots } = input else {
                    return Ok(PluginDatabaseBeforeAction::Continue(input));
                };
                if query.model != "organization" {
                    return Ok(PluginDatabaseBeforeAction::Continue(
                        PluginDatabaseBeforeInput::DeleteMany { query, snapshots },
                    ));
                }
                if snapshots_have_active_subscription(context.adapter, &options, &snapshots).await?
                {
                    return Ok(active_delete_cancel());
                }
                Ok(PluginDatabaseBeforeAction::Continue(
                    PluginDatabaseBeforeInput::DeleteMany { query, snapshots },
                ))
            })
        },
    )
}

async fn snapshots_have_active_subscription(
    adapter: &dyn DbAdapter,
    options: &StripeOptions,
    snapshots: &[DbRecord],
) -> Result<bool, OpenAuthError> {
    for organization in snapshots {
        if organization_has_active_subscription(adapter, &options.stripe_client, organization)
            .await?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn active_delete_cancel() -> PluginDatabaseBeforeAction {
    PluginDatabaseBeforeAction::Cancel(OpenAuthError::Api(
        StripeErrorCode::OrganizationHasActiveSubscription
            .message()
            .to_owned(),
    ))
}

pub(crate) async fn organization_member_count(
    adapter: &dyn DbAdapter,
    organization_id: &str,
) -> Result<i64, OpenAuthError> {
    let count = adapter
        .count(Count::new("member").where_clause(Where::new(
            "organization_id",
            DbValue::String(organization_id.to_owned()),
        )))
        .await?;
    Ok(count.max(1) as i64)
}

async fn organization_has_active_subscription(
    adapter: &dyn DbAdapter,
    stripe_client: &StripeClient,
    organization: &DbRecord,
) -> Result<bool, OpenAuthError> {
    let Some(reference_id) = record_string(organization, "id") else {
        return Ok(false);
    };
    if has_active_subscription_local(adapter, reference_id).await? {
        return Ok(true);
    }
    let Some(stripe_customer_id) = record_string(organization, "stripe_customer_id") else {
        return Ok(false);
    };
    stripe_customer_has_blocking_subscription(stripe_client, stripe_customer_id).await
}

async fn has_active_subscription_local(
    adapter: &dyn DbAdapter,
    reference_id: &str,
) -> Result<bool, OpenAuthError> {
    let subscriptions = adapter
        .find_many(FindMany::new("subscription").where_clause(Where::new(
            "reference_id",
            DbValue::String(reference_id.to_owned()),
        )))
        .await?;
    Ok(subscriptions.iter().any(|subscription| {
        subscription
            .get("status")
            .and_then(|status| match status {
                DbValue::String(status) => Some(status.as_str()),
                _ => None,
            })
            .is_some_and(utils::is_non_terminal_subscription_status)
    }))
}

fn stripe_status_blocks_organization_delete(status: &str) -> bool {
    !matches!(status, "canceled" | "incomplete" | "incomplete_expired")
}

async fn stripe_customer_has_blocking_subscription(
    stripe_client: &StripeClient,
    stripe_customer_id: &str,
) -> Result<bool, OpenAuthError> {
    let list = stripe_client
        .list_subscriptions_all(json!({
            "customer": stripe_customer_id,
            "status": "all",
        }))
        .await
        .map_err(|error| OpenAuthError::Api(error.to_string()))?;
    Ok(list
        .get("data")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|subscription| {
            subscription
                .get("status")
                .and_then(serde_json::Value::as_str)
        })
        .any(stripe_status_blocks_organization_delete))
}

fn sync_seats_after_member_create_hook(options: StripeOptions) -> PluginDatabaseHook {
    PluginDatabaseHook::after_async(
        "stripe-sync-organization-seats-after-member-create",
        PluginDatabaseOperation::Create,
        move |context, input| {
            let options = options.clone();
            Box::pin(async move {
                let PluginDatabaseAfterInput::Create { query, result } = input else {
                    return Ok(());
                };
                if query.model != "member" {
                    return Ok(());
                }
                let Some(organization_id) = record_string(&result, "organization_id") else {
                    return Ok(());
                };
                log_seat_sync_error(
                    &context,
                    sync_subscription_seats(&context, &options, organization_id).await,
                );
                Ok(())
            })
        },
    )
}

fn sync_seats_after_member_delete_hook(options: StripeOptions) -> PluginDatabaseHook {
    PluginDatabaseHook::after_async(
        "stripe-sync-organization-seats-after-member-delete",
        PluginDatabaseOperation::Delete,
        move |context, input| {
            let options = options.clone();
            Box::pin(async move {
                let PluginDatabaseAfterInput::Delete { query, snapshots } = input else {
                    return Ok(());
                };
                if query.model != "member" {
                    return Ok(());
                }
                for member in snapshots {
                    let Some(organization_id) = record_string(&member, "organization_id") else {
                        continue;
                    };
                    log_seat_sync_error(
                        &context,
                        sync_subscription_seats(&context, &options, organization_id).await,
                    );
                }
                Ok(())
            })
        },
    )
}

fn sync_seats_after_member_delete_many_hook(options: StripeOptions) -> PluginDatabaseHook {
    PluginDatabaseHook::after_async(
        "stripe-sync-organization-seats-after-member-delete-many",
        PluginDatabaseOperation::DeleteMany,
        move |context, input| {
            let options = options.clone();
            Box::pin(async move {
                let PluginDatabaseAfterInput::DeleteMany {
                    query, snapshots, ..
                } = input
                else {
                    return Ok(());
                };
                if query.model != "member" {
                    return Ok(());
                }
                let mut synced = std::collections::HashSet::new();
                for member in &snapshots {
                    let Some(organization_id) = record_string(member, "organization_id") else {
                        continue;
                    };
                    if !synced.insert(organization_id.to_owned()) {
                        continue;
                    }
                    log_seat_sync_error(
                        &context,
                        sync_subscription_seats(&context, &options, organization_id).await,
                    );
                }
                Ok(())
            })
        },
    )
}

fn sync_seats_after_invitation_accept_hook(options: StripeOptions) -> PluginDatabaseHook {
    PluginDatabaseHook::after_async(
        "stripe-sync-organization-seats-after-invitation-accept",
        PluginDatabaseOperation::Update,
        move |context, input| {
            let options = options.clone();
            Box::pin(async move {
                let PluginDatabaseAfterInput::Update { query, result } = input else {
                    return Ok(());
                };
                if query.model != "invitation" {
                    return Ok(());
                }
                let status_was_set_to_accepted = record_string(&query.data, "status")
                    .is_some_and(|status| status.eq_ignore_ascii_case("accepted"));
                if !status_was_set_to_accepted {
                    return Ok(());
                }
                let Some(result) = result else {
                    return Ok(());
                };
                let result_is_accepted = record_string(&result, "status")
                    .is_some_and(|status| status.eq_ignore_ascii_case("accepted"));
                if !result_is_accepted {
                    return Ok(());
                }
                let Some(organization_id) = record_string(&result, "organization_id") else {
                    return Ok(());
                };
                log_seat_sync_error(
                    &context,
                    sync_subscription_seats(&context, &options, organization_id).await,
                );
                Ok(())
            })
        },
    )
}

fn log_seat_sync_error(
    context: &openauth_core::plugin::PluginDatabaseHookContext<'_>,
    result: Result<(), OpenAuthError>,
) {
    if let Err(error) = result {
        logging::hook_error(
            context,
            "Failed to sync seats to Stripe",
            &error.to_string(),
        );
    }
}

async fn sync_subscription_seats(
    context: &PluginDatabaseHookContext<'_>,
    options: &StripeOptions,
    organization_id: &str,
) -> Result<(), OpenAuthError> {
    let adapter = context.adapter;
    let Some(subscription_options) = options.subscription.as_ref() else {
        return Ok(());
    };
    let subscription_options = subscription_options.resolve_plans().await?;
    let subscriptions = adapter
        .find_many(FindMany::new("subscription").where_clause(Where::new(
            "reference_id",
            DbValue::String(organization_id.to_owned()),
        )))
        .await?;
    let Some(subscription) = subscriptions.into_iter().find(|subscription| {
        subscription
            .get("status")
            .and_then(|status| match status {
                DbValue::String(status) => Some(status.as_str()),
                _ => None,
            })
            .is_some_and(utils::is_active_or_trialing)
    }) else {
        return Ok(());
    };
    let Some(plan_name) = record_string(&subscription, "plan") else {
        return Ok(());
    };
    let Some(plan) = utils::get_plan_by_name(&subscription_options, plan_name) else {
        return Ok(());
    };
    let Some(seat_price_id) = plan.seat_price_id.as_deref() else {
        return Ok(());
    };
    let Some(stripe_subscription_id) = record_string(&subscription, "stripe_subscription_id")
    else {
        return Ok(());
    };
    let member_count = organization_member_count(adapter, organization_id).await?;
    let stripe_subscription = options
        .stripe_client
        .retrieve_subscription(stripe_subscription_id)
        .await
        .map_err(|error| OpenAuthError::Api(error.to_string()))?;
    let stripe_status = stripe_subscription
        .get("status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if !utils::is_active_or_trialing(stripe_status) {
        return Ok(());
    }
    let seat_quantity = member_count.max(1);
    if member_count == 0 {
        logging::hook_warn(
            context,
            "Clamped organization seat sync to 1 for active seat-priced subscription with zero members",
            organization_id,
        );
    }
    let seat_item_id = stripe_subscription
        .get("items")
        .and_then(|items| items.get("data"))
        .and_then(serde_json::Value::as_array)
        .and_then(|items| {
            items.iter().find_map(|item| {
                let price_id = item
                    .get("price")
                    .and_then(|price| price.get("id"))
                    .and_then(serde_json::Value::as_str);
                (price_id == Some(seat_price_id))
                    .then(|| item.get("id").and_then(serde_json::Value::as_str))
                    .flatten()
            })
        });
    let item_update = if let Some(seat_item_id) = seat_item_id {
        serde_json::json!({
            "id": seat_item_id,
            "quantity": seat_quantity,
        })
    } else {
        serde_json::json!({
            "price": seat_price_id,
            "quantity": seat_quantity,
        })
    };
    options
        .stripe_client
        .update_subscription(
            stripe_subscription_id,
            serde_json::json!({
                "items": [item_update],
                "proration_behavior": plan
                    .proration_behavior
                    .as_deref()
                    .unwrap_or("create_prorations"),
            }),
        )
        .await
        .map_err(|error| OpenAuthError::Api(error.to_string()))?;
    if let Some(local_subscription_id) = record_string(&subscription, "id") {
        adapter
            .update(
                Update::new("subscription")
                    .where_clause(Where::new(
                        "id",
                        DbValue::String(local_subscription_id.to_owned()),
                    ))
                    .data("seats", DbValue::Number(seat_quantity)),
            )
            .await?;
    }
    Ok(())
}

fn record_string<'a>(record: &'a DbRecord, field: &str) -> Option<&'a str> {
    match record.get(field) {
        Some(DbValue::String(value)) => Some(value.as_str()),
        _ => None,
    }
}
