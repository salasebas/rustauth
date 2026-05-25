# openauth-stripe

Server-side Stripe billing integration for OpenAuth-RS.

## Status

This package is experimental beta software. It includes real server-side
customer, subscription, billing portal, and webhook behavior, but public APIs
may still change before a stable release.

## What It Provides

`openauth-stripe` adds a Better Auth-inspired Stripe plugin surface for
OpenAuth:

- User and organization Stripe customer linking.
- Checkout Session creation for subscription upgrades.
- Subscription cancel and restore endpoints.
- Billing portal session creation.
- Active subscription listing.
- Stripe webhook signature verification.
- Local subscription state synchronization from checkout and subscription
  lifecycle webhooks.
- Plugin schema contributions for `user.stripeCustomerId`,
  `organization.stripeCustomerId`, and the `subscription` table when enabled.
- Hook points for customer creation, checkout session parameters, raw Stripe
  events, and subscription lifecycle events.

## Basic Usage

```rust
use openauth_core::options::OpenAuthOptions;
use openauth_stripe::{
    stripe, StripeClient, StripeOptions, StripePlan, SubscriptionOptions,
};

let stripe_plugin = stripe(
    StripeOptions::new(
        StripeClient::new(std::env::var("STRIPE_SECRET_KEY")?),
        std::env::var("STRIPE_WEBHOOK_SECRET")?,
    )
    .create_customer_on_sign_up(true)
    .subscription(SubscriptionOptions::enabled(vec![
        StripePlan::new("pro").price_id("price_123"),
        StripePlan::new("team")
            .price_id("price_team_monthly")
            .annual_discount_price_id("price_team_yearly")
            .seat_price_id("price_team_seat"),
    ])),
);

let options = OpenAuthOptions {
    plugins: vec![stripe_plugin],
    ..OpenAuthOptions::default()
};
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Subscription Endpoints

When subscriptions are enabled, the plugin registers these auth endpoints:

- `POST /subscription/upgrade` creates or updates a Stripe Checkout flow.
- `POST /subscription/cancel` cancels an active subscription.
- `POST /subscription/restore` restores a pending cancellation or scheduled
  change.
- `GET /subscription/list` lists active subscriptions for the current session.
- `GET /subscription/success` reconciles a successful checkout redirect.
- `POST /subscription/billing-portal` creates a Stripe billing portal session.
- `POST /stripe/webhook` receives Stripe webhooks and bypasses origin checks so
  Stripe can call it directly.

Mount these under your OpenAuth base path. For example, an `/api/auth` base path
exposes the webhook at `/api/auth/stripe/webhook`.

## Webhooks

Configure your Stripe webhook endpoint with the signing secret passed to
`StripeOptions::new`. The handler validates the `stripe-signature` header before
parsing events.

The webhook lifecycle currently handles checkout completion and subscription
created, updated, canceled, and deleted events to keep local subscription rows in
sync. Use `StripeOptions::on_event` when you also need to observe raw Stripe
events after OpenAuth has processed them.

## Customer Linking

Set `create_customer_on_sign_up(true)` to create and persist a Stripe customer
when a user is inserted. Existing customers are looked up before creating new
ones, and user email updates are synchronized back to Stripe when a linked
customer exists.

For organization billing, enable organization support:

```rust
use openauth_stripe::{OrganizationStripeOptions, StripeOptions};

let options = StripeOptions::new(stripe_client, webhook_secret)
    .organization(OrganizationStripeOptions::enabled());
```

Organization support contributes `organization.stripeCustomerId` and uses the
organization as the billing reference when subscription requests specify
`customerType = "organization"`.

## Customization Hooks

Common extension points include:

- `StripeOptions::get_customer_create_params` to add Stripe customer fields or
  metadata.
- `StripeOptions::on_customer_create` to run side effects after customer
  creation or linking.
- `SubscriptionOptions::authorize_reference` to enforce whether the signed-in
  user can manage a user or organization billing reference.
- `SubscriptionOptions::get_checkout_session_params` to customize Checkout
  Session creation.
- `SubscriptionOptions::on_subscription_complete`,
  `on_subscription_created`, `on_subscription_update`,
  `on_subscription_cancel`, and `on_subscription_deleted` for lifecycle
  handling.
- `FreeTrialOptions` for trial start, end, and expiry hooks.

## Testing

The crate exposes `StripeTransport` so tests can inject a fake Stripe transport
without making network calls:

```rust
use openauth_stripe::stripe_api::{StripeClient, StripeTransport};
use std::sync::Arc;

let client = StripeClient::with_transport("sk_test", Arc::new(my_transport));
```

## Client SDK Scope

The Better Auth Stripe package includes a browser client helper. OpenAuth keeps
this crate server-side only: future client SDKs should be thin wrappers around
the HTTP endpoints exposed by this plugin, not browser-only logic ported into
the Rust core.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
