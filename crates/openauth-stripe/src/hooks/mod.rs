mod checkout;
mod subscriptions;
mod support;

use openauth_core::context::AuthContext;
use openauth_core::error::OpenAuthError;

use crate::logging;
use crate::models::StripeEvent;
use crate::options::StripeOptions;

pub async fn handle_stripe_event(
    context: &AuthContext,
    options: &StripeOptions,
    event: &StripeEvent,
) -> Result<(), OpenAuthError> {
    let event_type = event.event_type.as_str();
    let result = match event_type {
        "checkout.session.completed" => {
            checkout::on_checkout_session_completed(context, options, event).await
        }
        "customer.subscription.created" => {
            subscriptions::on_subscription_created(context, options, event).await
        }
        "customer.subscription.updated" => {
            subscriptions::on_subscription_updated(context, options, event).await
        }
        "customer.subscription.deleted" => {
            subscriptions::on_subscription_deleted(context, options, event).await
        }
        _ => Ok(()),
    };
    // Surface handler failures to the caller so the webhook route can release
    // the idempotency claim and let Stripe retries recover, instead of marking
    // the event processed after a partial update.
    if let Err(error) = &result {
        logging::webhook_error(
            context,
            &format!("Stripe webhook failed ({event_type}): {error}"),
        );
    }
    result
}
