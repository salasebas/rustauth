use crate::models::StripeSubscriptionItem;
use crate::options::{StripePlan, SubscriptionOptions};

pub fn escape_stripe_search_value(value: &str) -> String {
    value.replace('"', "\\\"")
}

pub fn is_active_or_trialing(status: &str) -> bool {
    matches!(status, "active" | "trialing")
}

/// Subscription statuses that should block organization deletion (aligned with upstream Stripe list filter).
pub fn is_non_terminal_subscription_status(status: &str) -> bool {
    !matches!(status, "canceled" | "incomplete" | "incomplete_expired")
}

#[allow(dead_code)]
pub fn is_pending_cancel(cancel_at_period_end: bool, cancel_at: Option<i64>) -> bool {
    cancel_at_period_end || cancel_at.is_some()
}

#[derive(Debug, Clone, Copy)]
pub struct ResolvedPlanItem<'a> {
    pub item: &'a StripeSubscriptionItem,
    pub plan: Option<&'a StripePlan>,
}

pub fn get_plan_by_name<'a>(
    subscription: &'a SubscriptionOptions,
    name: &str,
) -> Option<&'a StripePlan> {
    subscription
        .plans
        .iter()
        .find(|plan| plan.name.eq_ignore_ascii_case(name))
}

pub fn resolve_plan_item<'a>(
    subscription: &'a SubscriptionOptions,
    items: &'a [StripeSubscriptionItem],
) -> Option<ResolvedPlanItem<'a>> {
    let first = items.first()?;
    for item in items {
        let plan = subscription.plans.iter().find(|plan| {
            plan.price_id.as_deref() == Some(item.price.id.as_str())
                || plan.annual_discount_price_id.as_deref() == Some(item.price.id.as_str())
                || item.price.lookup_key.as_deref().is_some_and(|lookup_key| {
                    plan.lookup_key.as_deref() == Some(lookup_key)
                        || plan.annual_discount_lookup_key.as_deref() == Some(lookup_key)
                })
        });
        if let Some(plan) = plan {
            return Some(ResolvedPlanItem {
                item,
                plan: Some(plan),
            });
        }
    }
    (items.len() == 1).then_some(ResolvedPlanItem {
        item: first,
        plan: None,
    })
}

pub fn resolve_quantity(
    items: &[StripeSubscriptionItem],
    plan_item: &StripeSubscriptionItem,
    seat_price_id: Option<&str>,
) -> i64 {
    if let Some(seat_price_id) = seat_price_id {
        if let Some(seat_item) = items.iter().find(|item| item.price.id == seat_price_id) {
            return seat_item.quantity.unwrap_or(1);
        }
    }
    plan_item.quantity.unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{StripePrice, StripeSubscriptionItem};

    #[test]
    fn escape_stripe_search_value_escapes_double_quotes() {
        assert_eq!(
            escape_stripe_search_value(r#""a" and "b""#),
            r#"\"a\" and \"b\""#
        );
    }

    #[test]
    fn resolve_plan_item_matches_by_price_id_and_lookup_key() {
        let options = SubscriptionOptions::enabled(vec![
            StripePlan::new("starter").price_id("price_starter"),
            StripePlan::new("premium").lookup_key("lookup_premium"),
        ]);
        let items = vec![
            StripeSubscriptionItem::new("si_1", StripePrice::new("price_seat")),
            StripeSubscriptionItem::new(
                "si_2",
                StripePrice::new("price_dynamic").lookup_key("lookup_premium"),
            ),
        ];

        let resolved = resolve_plan_item(&options, &items);
        assert_eq!(
            resolved.and_then(|item| item.plan.map(|plan| plan.name.as_str())),
            Some("premium")
        );
    }

    #[test]
    fn is_active_or_trialing_matches_upstream_statuses() {
        assert!(is_active_or_trialing("active"));
        assert!(is_active_or_trialing("trialing"));
        assert!(!is_active_or_trialing("canceled"));
    }

    #[test]
    fn is_pending_cancel_matches_upstream_semantics() {
        assert!(is_pending_cancel(true, None));
        assert!(is_pending_cancel(false, Some(1)));
        assert!(!is_pending_cancel(false, None));
    }
}
