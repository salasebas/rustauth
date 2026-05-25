use http::Method;
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
