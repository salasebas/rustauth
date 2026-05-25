use http::Method;
use openauth_core::db::{DbField, DbFieldType, DbTable};
use openauth_core::plugin::PluginSchemaContribution;
use openauth_stripe::options::{
    FreeTrialOptions, OrganizationStripeOptions, StripeOptions, StripePlan, SubscriptionOptions,
};
use openauth_stripe::stripe;
use openauth_stripe::stripe_api::StripeClient;
use serde_json::json;

#[test]
fn plugin_registers_webhook_without_subscription_endpoints_when_subscription_disabled() {
    let plugin = stripe(StripeOptions::new(
        StripeClient::new("sk_test"),
        "whsec_test",
    ));

    let endpoints = plugin
        .endpoints
        .iter()
        .map(|endpoint| (endpoint.method.clone(), endpoint.path.as_str()))
        .collect::<Vec<_>>();

    assert_eq!(plugin.id, "stripe");
    assert!(endpoints.contains(&(Method::POST, "/stripe/webhook")));
    assert!(!endpoints.contains(&(Method::POST, "/subscription/upgrade")));
}

#[test]
fn plugin_registers_subscription_endpoints_and_schema_when_enabled() {
    let plugin = stripe(
        StripeOptions::new(StripeClient::new("sk_test"), "whsec_test").subscription(
            SubscriptionOptions::enabled(vec![StripePlan::new("pro").price_id("price_pro")]),
        ),
    );

    let endpoints = plugin
        .endpoints
        .iter()
        .map(|endpoint| (endpoint.method.clone(), endpoint.path.as_str()))
        .collect::<Vec<_>>();

    assert!(endpoints.contains(&(Method::POST, "/subscription/upgrade")));
    assert!(endpoints.contains(&(Method::POST, "/subscription/cancel")));
    assert!(endpoints.contains(&(Method::POST, "/subscription/restore")));
    assert!(endpoints.contains(&(Method::GET, "/subscription/list")));
    assert!(endpoints.contains(&(Method::GET, "/subscription/success")));
    assert!(endpoints.contains(&(Method::POST, "/subscription/billing-portal")));
    assert!(plugin.schema.iter().any(|contribution| matches!(
        contribution,
        openauth_core::plugin::PluginSchemaContribution::Table { logical_name, .. }
            if logical_name == "subscription"
    )));
}

#[test]
fn public_option_builders_cover_stripe_callbacks_and_custom_params(
) -> Result<(), Box<dyn std::error::Error>> {
    let options = StripeOptions::new(StripeClient::new("sk_test"), "whsec_test")
        .get_customer_create_params(|input, _| {
            Box::pin(async move {
                assert_eq!(input.user.id, "user_1");
                Ok(json!({ "address": { "country": "US" } }))
            })
        })
        .on_customer_create(|input, _| {
            Box::pin(async move {
                assert_eq!(input.user.id, "user_1");
                assert_eq!(input.stripe_customer["id"], "cus_123");
                Ok(())
            })
        })
        .subscription(
            SubscriptionOptions::enabled(vec![StripePlan::new("pro")
                .price_id("price_pro")
                .free_trial(
                    FreeTrialOptions::new(14)
                        .on_trial_start(|_| Box::pin(async { Ok(()) }))
                        .on_trial_end(|_, _| Box::pin(async { Ok(()) }))
                        .on_trial_expired(|_, _| Box::pin(async { Ok(()) })),
                )])
            .get_checkout_session_params(|input, _, _| {
                Box::pin(async move {
                    assert_eq!(input.plan.name, "pro");
                    Ok(json!({ "locale": "auto" }))
                })
            })
            .on_subscription_complete(|_| Box::pin(async { Ok(()) }))
            .on_subscription_created(|_| Box::pin(async { Ok(()) }))
            .on_subscription_update(|_| Box::pin(async { Ok(()) }))
            .on_subscription_cancel(|_| Box::pin(async { Ok(()) }))
            .on_subscription_deleted(|_| Box::pin(async { Ok(()) })),
        )
        .organization(
            OrganizationStripeOptions::enabled()
                .get_customer_create_params(|input, _| {
                    Box::pin(async move {
                        assert_eq!(input.organization["id"], "org_1");
                        Ok(json!({ "email": "billing@example.com" }))
                    })
                })
                .on_customer_create(|input, _| {
                    Box::pin(async move {
                        assert_eq!(input.stripe_customer["id"], "cus_org");
                        Ok(())
                    })
                }),
        );

    assert!(options.on_customer_create.is_some());
    assert!(options.get_customer_create_params.is_some());
    let subscription = options
        .subscription
        .as_ref()
        .ok_or_else(|| std::io::Error::other("subscription options missing"))?;
    assert!(subscription.get_checkout_session_params.is_some());
    assert!(subscription.on_subscription_complete.is_some());
    assert!(subscription.plans[0].free_trial.is_some());
    let organization = options
        .organization
        .as_ref()
        .ok_or_else(|| std::io::Error::other("organization options missing"))?;
    assert!(organization.get_customer_create_params.is_some());
    assert!(organization.on_customer_create.is_some());
    Ok(())
}

#[test]
fn plugin_merges_custom_schema_but_ignores_subscription_when_disabled() {
    let plugin = stripe(
        StripeOptions::new(StripeClient::new("sk_test"), "whsec_test")
            .schema(PluginSchemaContribution::field(
                "user",
                "billingTier",
                DbField::new("billing_tier", DbFieldType::String).optional(),
            ))
            .schema(PluginSchemaContribution::table(
                "subscription",
                DbTable {
                    name: "custom_subscriptions".to_owned(),
                    fields: indexmap::IndexMap::new(),
                    order: None,
                },
            ))
            .schema(PluginSchemaContribution::field(
                "subscription",
                "externalId",
                DbField::new("external_id", DbFieldType::String).optional(),
            )),
    );

    assert!(plugin.schema.iter().any(|contribution| matches!(
        contribution,
        PluginSchemaContribution::Field { table, logical_name, .. }
            if table == "user" && logical_name == "billingTier"
    )));
    assert!(!plugin.schema.iter().any(|contribution| matches!(
        contribution,
        PluginSchemaContribution::Table { logical_name, .. } if logical_name == "subscription"
    )));
    assert!(!plugin.schema.iter().any(|contribution| matches!(
        contribution,
        PluginSchemaContribution::Field { table, .. } if table == "subscription"
    )));
}

#[test]
fn plugin_merges_custom_subscription_table_when_enabled() {
    let mut custom_fields = indexmap::IndexMap::new();
    custom_fields.insert(
        "externalId".to_owned(),
        DbField::new("external_id", DbFieldType::String).optional(),
    );
    custom_fields.insert(
        "status".to_owned(),
        DbField::new("subscription_status", DbFieldType::String).indexed(),
    );
    let plugin = stripe(
        StripeOptions::new(StripeClient::new("sk_test"), "whsec_test")
            .subscription(SubscriptionOptions::enabled(vec![
                StripePlan::new("pro").price_id("price_pro")
            ]))
            .schema(PluginSchemaContribution::table(
                "subscription",
                DbTable {
                    name: "custom_subscriptions".to_owned(),
                    fields: custom_fields,
                    order: Some(99),
                },
            )),
    );

    let subscription_tables = plugin
        .schema
        .iter()
        .filter_map(|contribution| match contribution {
            PluginSchemaContribution::Table {
                logical_name,
                table,
            } if logical_name == "subscription" => Some(table),
            _ => None,
        })
        .collect::<Vec<_>>();

    assert_eq!(subscription_tables.len(), 1);
    let table = subscription_tables[0];
    assert_eq!(table.name, "custom_subscriptions");
    assert_eq!(table.order, Some(99));
    assert!(table.fields.contains_key("plan"));
    assert!(table.fields.contains_key("stripeCustomerId"));
    assert_eq!(
        table
            .fields
            .get("externalId")
            .map(|field| field.name.as_str()),
        Some("external_id")
    );
    assert_eq!(
        table.fields.get("status").map(|field| field.name.as_str()),
        Some("subscription_status")
    );
}

#[test]
fn subscription_options_accept_dynamic_plan_provider() {
    let options = SubscriptionOptions::enabled_dynamic(|| {
        Box::pin(async {
            Ok(vec![
                StripePlan::new("dynamic-pro").price_id("price_dynamic")
            ])
        })
    });

    assert!(options.enabled);
}
