mod checkout;
mod subscriptions;
mod support;

use openauth_core::context::AuthContext;
use openauth_core::error::OpenAuthError;

use crate::models::StripeEvent;
use crate::options::StripeOptions;

pub async fn handle_stripe_event(
    context: &AuthContext,
    options: &StripeOptions,
    event: &StripeEvent,
) -> Result<(), OpenAuthError> {
    match event.event_type.as_str() {
        "checkout.session.completed" => {
            checkout::on_checkout_session_completed(context, options, event).await?;
        }
        "customer.subscription.created" => {
            subscriptions::on_subscription_created(context, options, event).await?;
        }
        "customer.subscription.updated" => {
            subscriptions::on_subscription_updated(context, options, event).await?;
        }
        "customer.subscription.deleted" => {
            subscriptions::on_subscription_deleted(context, options, event).await?;
        }
        _ => {}
    }
    Ok(())
}
