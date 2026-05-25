use indexmap::IndexMap;
use openauth_core::db::{DbField, DbFieldType, DbTable};
use openauth_core::plugin::PluginSchemaContribution;

use crate::options::StripeOptions;

pub fn schema_contributions(options: &StripeOptions) -> Vec<PluginSchemaContribution> {
    let mut contributions = vec![PluginSchemaContribution::field(
        "user",
        "stripeCustomerId",
        DbField::new("stripe_customer_id", DbFieldType::String).optional(),
    )];
    if options.organization.as_ref().is_some_and(|org| org.enabled) {
        contributions.push(PluginSchemaContribution::field(
            "organization",
            "stripeCustomerId",
            DbField::new("stripe_customer_id", DbFieldType::String).optional(),
        ));
    }
    if options.subscription.as_ref().is_some_and(|sub| sub.enabled) {
        contributions.push(PluginSchemaContribution::table(
            "subscription",
            subscription_table(),
        ));
    }
    contributions
}

fn subscription_table() -> DbTable {
    table(
        "subscriptions",
        Some(70),
        [
            ("id", DbField::new("id", DbFieldType::String)),
            ("plan", DbField::new("plan", DbFieldType::String).indexed()),
            (
                "referenceId",
                DbField::new("reference_id", DbFieldType::String).indexed(),
            ),
            (
                "stripeCustomerId",
                DbField::new("stripe_customer_id", DbFieldType::String)
                    .optional()
                    .indexed(),
            ),
            (
                "stripeSubscriptionId",
                DbField::new("stripe_subscription_id", DbFieldType::String)
                    .optional()
                    .indexed(),
            ),
            (
                "status",
                DbField::new("status", DbFieldType::String).indexed(),
            ),
            (
                "periodStart",
                DbField::new("period_start", DbFieldType::Timestamp).optional(),
            ),
            (
                "periodEnd",
                DbField::new("period_end", DbFieldType::Timestamp).optional(),
            ),
            (
                "trialStart",
                DbField::new("trial_start", DbFieldType::Timestamp).optional(),
            ),
            (
                "trialEnd",
                DbField::new("trial_end", DbFieldType::Timestamp).optional(),
            ),
            (
                "cancelAtPeriodEnd",
                DbField::new("cancel_at_period_end", DbFieldType::Boolean).optional(),
            ),
            (
                "cancelAt",
                DbField::new("cancel_at", DbFieldType::Timestamp).optional(),
            ),
            (
                "canceledAt",
                DbField::new("canceled_at", DbFieldType::Timestamp).optional(),
            ),
            (
                "endedAt",
                DbField::new("ended_at", DbFieldType::Timestamp).optional(),
            ),
            (
                "seats",
                DbField::new("seats", DbFieldType::Number).optional(),
            ),
            (
                "billingInterval",
                DbField::new("billing_interval", DbFieldType::String).optional(),
            ),
            (
                "stripeScheduleId",
                DbField::new("stripe_schedule_id", DbFieldType::String).optional(),
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
