use openauth_stripe::models::{StripePrice, StripeSubscriptionItem};
use openauth_stripe::options::{StripePlan, SubscriptionOptions};
use openauth_stripe::utils::{
    escape_stripe_search_value, is_active_or_trialing, resolve_plan_item,
};

#[test]
fn escape_stripe_search_value_escapes_double_quotes() {
    assert_eq!(
        escape_stripe_search_value(r#""a" and "b""#),
        r#"\"a\" and \"b\""#
    );
}

#[test]
fn resolve_plan_item_matches_by_price_id_and_lookup_key() -> Result<(), Box<dyn std::error::Error>>
{
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

    let resolved = resolve_plan_item(&options, &items).ok_or("plan should resolve")?;

    assert_eq!(resolved.item.id, "si_2");
    assert_eq!(
        resolved.plan.map(|plan| plan.name.as_str()),
        Some("premium")
    );
    Ok(())
}

#[test]
fn resolve_plan_item_returns_single_unmatched_item_without_plan(
) -> Result<(), Box<dyn std::error::Error>> {
    let options =
        SubscriptionOptions::enabled(vec![StripePlan::new("starter").price_id("price_starter")]);
    let items = vec![StripeSubscriptionItem::new(
        "si_1",
        StripePrice::new("price_unknown"),
    )];

    let resolved = resolve_plan_item(&options, &items).ok_or("single item should be returned")?;

    assert_eq!(resolved.item.id, "si_1");
    assert!(resolved.plan.is_none());
    Ok(())
}

#[test]
fn active_or_trialing_only_accepts_active_states() {
    assert!(is_active_or_trialing("active"));
    assert!(is_active_or_trialing("trialing"));
    assert!(!is_active_or_trialing("past_due"));
    assert!(!is_active_or_trialing("canceled"));
}
