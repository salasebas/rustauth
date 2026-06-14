use indexmap::IndexMap;
use rustauth_core::db::{DbField, DbFieldType, DbTable};
use rustauth_core::plugin::PluginSchemaContribution;

use crate::options::StripeOptions;

pub fn schema_contributions(options: &StripeOptions) -> Vec<PluginSchemaContribution> {
    let subscriptions_enabled = options.subscription.as_ref().is_some_and(|sub| sub.enabled);
    let mut contributions = vec![
        PluginSchemaContribution::field(
            "user",
            "stripe_customer_id",
            DbField::new("stripe_customer_id", DbFieldType::String).optional(),
        ),
        PluginSchemaContribution::table("stripe_webhook_event", webhook_event_table()),
    ];
    if options.organization.as_ref().is_some_and(|org| org.enabled) {
        contributions.push(PluginSchemaContribution::field(
            "organization",
            "stripe_customer_id",
            DbField::new("stripe_customer_id", DbFieldType::String).optional(),
        ));
    }
    let mut subscription_table = subscriptions_enabled.then(subscription_table);
    let mut custom_contributions = Vec::new();
    for contribution in &options.schema {
        match contribution {
            PluginSchemaContribution::Table {
                logical_name,
                table,
            } if logical_name == "subscription" => {
                if let Some(base_table) = subscription_table.as_mut() {
                    merge_subscription_table(base_table, table);
                }
            }
            PluginSchemaContribution::Field { table, .. }
                if table == "subscription" && !subscriptions_enabled => {}
            _ => custom_contributions.push(contribution.clone()),
        }
    }
    if let Some(subscription_table) = subscription_table {
        contributions.push(PluginSchemaContribution::table(
            "subscription",
            subscription_table,
        ));
    }
    contributions.extend(custom_contributions);
    contributions
}

fn merge_subscription_table(base: &mut DbTable, custom: &DbTable) {
    base.name = custom.name.clone();
    base.order = custom.order.or(base.order);
    for (logical_name, field) in &custom.fields {
        base.fields.insert(logical_name.clone(), field.clone());
    }
}

/// Durable record of processed Stripe webhook events, keyed by Stripe `event.id`,
/// used to make webhook delivery idempotent (skip already-processed events).
fn webhook_event_table() -> DbTable {
    table(
        "stripe_webhook_events",
        Some(71),
        [
            ("id", DbField::new("id", DbFieldType::String)),
            (
                "event_type",
                DbField::new("event_type", DbFieldType::String).indexed(),
            ),
            (
                "created_at",
                DbField::new("created_at", DbFieldType::Timestamp),
            ),
        ],
    )
}

fn subscription_table() -> DbTable {
    table(
        "subscriptions",
        Some(70),
        [
            ("id", DbField::new("id", DbFieldType::String)),
            ("plan", DbField::new("plan", DbFieldType::String).indexed()),
            (
                "reference_id",
                DbField::new("reference_id", DbFieldType::String).indexed(),
            ),
            (
                "stripe_customer_id",
                DbField::new("stripe_customer_id", DbFieldType::String)
                    .optional()
                    .indexed(),
            ),
            (
                "stripe_subscription_id",
                DbField::new("stripe_subscription_id", DbFieldType::String)
                    .optional()
                    .indexed(),
            ),
            (
                "status",
                DbField::new("status", DbFieldType::String).indexed(),
            ),
            (
                "period_start",
                DbField::new("period_start", DbFieldType::Timestamp).optional(),
            ),
            (
                "period_end",
                DbField::new("period_end", DbFieldType::Timestamp).optional(),
            ),
            (
                "trial_start",
                DbField::new("trial_start", DbFieldType::Timestamp).optional(),
            ),
            (
                "trial_end",
                DbField::new("trial_end", DbFieldType::Timestamp).optional(),
            ),
            (
                "cancel_at_period_end",
                DbField::new("cancel_at_period_end", DbFieldType::Boolean).optional(),
            ),
            (
                "cancel_at",
                DbField::new("cancel_at", DbFieldType::Timestamp).optional(),
            ),
            (
                "canceled_at",
                DbField::new("canceled_at", DbFieldType::Timestamp).optional(),
            ),
            (
                "ended_at",
                DbField::new("ended_at", DbFieldType::Timestamp).optional(),
            ),
            (
                "seats",
                DbField::new("seats", DbFieldType::Number).optional(),
            ),
            (
                "billing_interval",
                DbField::new("billing_interval", DbFieldType::String).optional(),
            ),
            (
                "stripe_schedule_id",
                DbField::new("stripe_schedule_id", DbFieldType::String).optional(),
            ),
            (
                "limits",
                DbField::new("limits", DbFieldType::Json).optional(),
            ),
        ],
    )
}

fn table<const N: usize>(name: &str, order: Option<u16>, fields: [(&str, DbField); N]) -> DbTable {
    DbTable {
        name: name.to_owned(),
        fields: fields
            .into_iter()
            .map(|(logical_name, field)| (logical_name.to_owned(), field))
            .collect::<IndexMap<_, _>>(),
        order,
    }
}
