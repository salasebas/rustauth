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
use openauth::stripe::{
    stripe, StripeClient, StripeOptions, StripePlan, SubscriptionOptions,
};
use openauth::OpenAuth;

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
    )?)
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
passed to `StripeOptions::new`. Use the signing secret from the Stripe dashboard
as-is (including the `whsec_` prefix); the plugin uses it verbatim as the HMAC
key, matching Stripe's official libraries.
It currently handles checkout completion and subscription created, updated,
canceled, and deleted events.

Use `StripeOptions::on_event` when your application needs to observe raw Stripe
events after OpenAuth has processed them.

Database hooks that create or sync Stripe customers are best-effort: failures are
not returned to the sign-up or update flow, so monitor Stripe API errors in your
application logs if you rely on automatic customer creation.

## Organization Billing

```rust
use openauth::stripe::{OrganizationStripeOptions, StripeOptions};

let options = StripeOptions::new(stripe_client, webhook_secret)
    .organization(OrganizationStripeOptions::enabled());
```

Lifecycle hooks accept plain `async` closures (no `Box::pin` at the call site):

```rust
use openauth::stripe::{StripeOptions, SubscriptionOptions};

let options = StripeOptions::new(stripe_client, webhook_secret).subscription(
    SubscriptionOptions::enabled(vec![/* plans */])
        .on_subscription_complete(|input| async move {
            let _ = input;
            Ok(())
        }),
);
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

```bash
cargo nextest run -p openauth-stripe
```

### Test-mode smoke (manual)

For end-to-end validation against Stripe **test mode** (real API + Checkout + webhooks), use the server-side runbook — no example app required:

- [SMOKE.md](./SMOKE.md) — full checklist, env vars, DB checks, log grep patterns
- [.env.smoke.example](./.env.smoke.example) — template (copy to repo root `.env`)
- [`scripts/stripe-smoke.sh`](../../scripts/stripe-smoke.sh) — env checks and CLI/curl hints

Database hooks are **best-effort**. Built-in webhook handlers skip non-actionable
events, but retryable processing failures return an error so Stripe can retry.
During smoke, grep logs for the messages listed in SMOKE.md §10.

## Status

Experimental beta. Customer, subscription, billing portal, and webhook behavior
exist, but public APIs may change before stable release.

Stripe failures during **database hooks** (sign-up customer, email sync, seat sync)
are best-effort: they are logged and do not fail the underlying user operation,
matching Better Auth 1.6.9. Built-in webhook handlers skip non-actionable events,
but retryable processing failures and the optional `on_event` hook can fail the
webhook response.

### Webhook events handled

Built-in handlers (non-actionable skips return HTTP 200; retryable processing
failures return an error so Stripe can retry):

- `checkout.session.completed`
- `customer.subscription.created`
- `customer.subscription.updated` (includes cancel-at-period-end sync)
- `customer.subscription.deleted`

Other event types invoke `on_event` only; a failing `on_event` returns `STRIPE_WEBHOOK_ERROR`.

### Organization billing

`customerType: "organization"` requires configuring `.authorize_reference(...)` on `SubscriptionOptions`. Without it, endpoints return `AUTHORIZE_REFERENCE_REQUIRED`.

## Better Auth compatibility

Server-side Stripe billing plugin. Aligned with Better Auth 1.6.9 where it
matters; OpenAuth is not a line-by-line port.
For route-level parity, test counts, differences, and gaps, see [UPSTREAM.md](./UPSTREAM.md).

## Links

- [SMOKE.md](./SMOKE.md) — test-mode manual smoke checklist
- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
