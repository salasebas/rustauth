//! Stripe integration for OpenAuth.

pub mod customers;
pub mod errors;
pub mod hooks;
pub mod metadata;
pub mod models;
pub mod options;
pub mod routes;
pub mod schema;
pub mod stripe_api;
pub mod utils;

mod organization;

use openauth_core::plugin::{
    AuthPlugin, PluginDatabaseAfterInput, PluginDatabaseHook, PluginDatabaseOperation,
};

pub use errors::{error_codes, StripeErrorCode};
pub use options::{
    FreeTrialOptions, OrganizationStripeOptions, StripeOptions, StripePlan, SubscriptionOptions,
};
pub use stripe_api::StripeClient;

/// Current crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub const UPSTREAM_PLUGIN_ID: &str = "stripe";

pub fn stripe(options: StripeOptions) -> AuthPlugin {
    stripe_with_options(options)
}

pub fn stripe_with_options(options: StripeOptions) -> AuthPlugin {
    let subscription_enabled = options.subscription.as_ref().is_some_and(|s| s.enabled);
    let mut plugin = AuthPlugin::new(UPSTREAM_PLUGIN_ID)
        .with_version(VERSION)
        .with_options(options.to_metadata())
        .with_endpoint(routes::stripe_webhook(options.clone()))
        .with_database_hook(sync_user_customer_email_hook(options.clone()));

    if options.create_customer_on_sign_up {
        plugin = plugin.with_database_hook(create_customer_on_sign_up_hook(options.clone()));
    }

    if options.organization.as_ref().is_some_and(|org| org.enabled) {
        plugin = plugin.with_database_hook(organization::sync_customer_name_hook(options.clone()));
    }

    if subscription_enabled && options.organization.as_ref().is_some_and(|org| org.enabled) {
        for hook in organization::subscription_database_hooks(options.clone()) {
            plugin = plugin.with_database_hook(hook);
        }
    }

    if subscription_enabled {
        plugin = plugin
            .with_endpoint(routes::upgrade_subscription(options.clone()))
            .with_endpoint(routes::cancel_subscription(options.clone()))
            .with_endpoint(routes::restore_subscription(options.clone()))
            .with_endpoint(routes::list_active_subscriptions(options.clone()))
            .with_endpoint(routes::subscription_success(options.clone()))
            .with_endpoint(routes::create_billing_portal(options.clone()));
    }

    for contribution in schema::schema_contributions(&options) {
        plugin = plugin.with_schema(contribution);
    }
    for error_code in errors::error_codes() {
        plugin = plugin.with_error_code(error_code);
    }
    plugin
}

fn create_customer_on_sign_up_hook(options: StripeOptions) -> PluginDatabaseHook {
    PluginDatabaseHook::after_async(
        "stripe-create-customer-on-sign-up",
        PluginDatabaseOperation::Create,
        move |context, input| {
            let options = options.clone();
            Box::pin(async move {
                let PluginDatabaseAfterInput::Create { query, result } = input else {
                    return Ok(());
                };
                if query.model != "user" {
                    return Ok(());
                }
                let _ = customers::ensure_user_customer_from_record(
                    context.adapter,
                    &options,
                    options::CustomerCreateContext::database_hook(context.request_path.clone()),
                    &result,
                )
                .await;
                Ok(())
            })
        },
    )
}

fn sync_user_customer_email_hook(options: StripeOptions) -> PluginDatabaseHook {
    PluginDatabaseHook::after_async(
        "stripe-sync-user-customer-email",
        PluginDatabaseOperation::Update,
        move |_context, input| {
            let options = options.clone();
            Box::pin(async move {
                let PluginDatabaseAfterInput::Update { query, result } = input else {
                    return Ok(());
                };
                if query.model != "user" {
                    return Ok(());
                }
                let Some(result) = result else {
                    return Ok(());
                };
                let _ = customers::sync_user_customer_email_from_record(
                    &options.stripe_client,
                    &result,
                )
                .await;
                Ok(())
            })
        },
    )
}
