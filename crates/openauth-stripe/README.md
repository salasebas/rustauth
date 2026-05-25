# openauth-stripe

Server-side Stripe billing integration for OpenAuth-RS.

## What It Is

`openauth-stripe` adds Stripe customer and subscription behavior to an
OpenAuth server. It is server-side only: browser helpers should call the HTTP
endpoints exposed by this plugin.

## What It Provides

- User and organization Stripe customer linking.
- Customer creation on sign-up.
- Checkout Session creation for subscription upgrades.
- Subscription cancel and restore endpoints.
- Billing portal session creation.
- Active subscription listing.
- Stripe webhook signature verification.
- Local subscription synchronization from checkout and subscription lifecycle
  webhooks.
- Schema contributions for `user.stripeCustomerId`,
  `organization.stripeCustomerId`, and `subscription` storage.

## Quick Start

```rust
use openauth::OpenAuth;
use openauth_stripe::{
    stripe, StripeClient, StripeOptions, StripePlan, SubscriptionOptions,
};

let auth = OpenAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .base_url("https://app.example.com/api/auth")
    .plugin(stripe(
        StripeOptions::new(
            StripeClient::new(std::env::var("STRIPE_SECRET_KEY")?),
            std::env::var("STRIPE_WEBHOOK_SECRET")?,
        )
        .create_customer_on_sign_up(true)
        .subscription(SubscriptionOptions::enabled(vec![
            StripePlan::new("pro").price_id("price_pro_monthly"),
            StripePlan::new("team")
                .price_id("price_team_monthly")
                .annual_discount_price_id("price_team_yearly")
                .seat_price_id("price_team_seat"),
        ])),
    ))
    .build()?;
# let _ = auth;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Run your adapter migration flow after enabling the plugin so the Stripe fields
and subscription table exist.

## Endpoints

When subscriptions are enabled, the plugin registers:

- `POST /subscription/upgrade`
- `POST /subscription/cancel`
- `POST /subscription/restore`
- `GET /subscription/list`
- `GET /subscription/success`
- `POST /subscription/billing-portal`
- `POST /stripe/webhook`

Mount these under your OpenAuth base path. With `/api/auth`, Stripe webhooks
should target `/api/auth/stripe/webhook`.

## Webhooks

The webhook endpoint validates the `stripe-signature` header with the secret
passed to `StripeOptions::new`. It currently handles checkout completion and
subscription created, updated, canceled, and deleted events.

Use `StripeOptions::on_event` when your application needs to observe raw Stripe
events after OpenAuth has processed them.

## Organization Billing

```rust
use openauth_stripe::{OrganizationStripeOptions, StripeOptions};

let options = StripeOptions::new(stripe_client, webhook_secret)
    .organization(OrganizationStripeOptions::enabled());
```

Organization support contributes `organization.stripeCustomerId` and uses the
organization as the billing reference when requests specify
`customerType = "organization"`.

## Testing

Tests can inject a fake transport without network calls:

```rust
use openauth_stripe::stripe_api::StripeClient;
use std::sync::Arc;

let client = StripeClient::with_transport("sk_test", Arc::new(my_transport));
```

## Status

Experimental beta. Customer, subscription, billing portal, and webhook behavior
exist, but public APIs may change before stable release.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
