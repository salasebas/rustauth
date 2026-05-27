# openauth-stripe — test-mode smoke checklist

Server-side manual validation for Stripe **test mode**. No example app UI is required; use your own OpenAuth server harness (Axum, Actix, etc.) with the stripe plugin enabled.

**Related:** [README](./README.md) · [ROADMAP](./ROADMAP.md) · [UPSTREAM](./UPSTREAM.md) · `scripts/stripe-smoke.sh` · `.env.smoke.example`

---

## 1. Prerequisites

| Requirement | Notes |
| --- | --- |
| Stripe account (test mode) | [Dashboard](https://dashboard.stripe.com/test) — toggle **Test mode** on |
| [Stripe CLI](https://stripe.com/docs/stripe-cli) | `stripe login`, then `stripe listen` for local webhooks |
| OpenAuth server with `openauth-stripe` | Plugin registered, DB migrated (user/org/subscription fields) |
| Plans configured in code | `StripePlan::price_id(...)` must match **test** Price IDs from Dashboard |
| HTTPS or localhost | Checkout `successUrl` / `cancelUrl` must be allowed by your app |

**Out of scope for this runbook:** example app UI, `groupId`, webhook idempotency by `event.id` (see [ROADMAP](./ROADMAP.md)).

---

## 2. Where to put environment variables

**Recommendation:** one file at the **repository root**:

```text
openauth-rs/.env          ← copy from crates/openauth-stripe/.env.smoke.example
```

Load `.env` in your server binary or process manager (e.g. `dotenvy` at startup). Do **not** commit `.env`.

| Location | Use when |
| --- | --- |
| **Repo root `.env`** (recommended) | Single place for Stripe + DB + `OPENAUTH_*` used by your smoke server |
| `crates/openauth-stripe/.env` | Only if you run a dedicated smoke binary in this crate (unusual) |
| Shell / CI secrets | Ephemeral `STRIPE_WEBHOOK_SECRET` from `stripe listen` each session |

The crate does not read these files itself; your application maps env vars into `StripeOptions::new(client, webhook_secret)` and plan `price_id`s.

---

## 3. Environment variables

| Variable | Required | Purpose | Example |
| --- | --- | --- | --- |
| `STRIPE_SECRET_KEY` | Yes | Stripe API secret (`sk_test_…`) | Dashboard → Developers → API keys |
| `STRIPE_WEBHOOK_SECRET` | Yes | Webhook signing secret (`whsec_…`) | From `stripe listen` or Dashboard webhook |
| `STRIPE_PRICE_*` | Yes (per plan) | Price IDs wired into `StripePlan` in your code | See `.env.smoke.example` |
| `OPENAUTH_SECRET` | Yes | Session signing (≥32 chars) | Your server config |
| `OPENAUTH_BASE_URL` | Yes | Public auth base URL (no trailing slash issues) | `http://127.0.0.1:3000/api/auth` |
| `DATABASE_URL` | If not SQLite | Postgres/MySQL for persistent smoke | `postgres://…` |
| `OPENAUTH_SESSION_COOKIE` | Optional | Full `Cookie` header for `scripts/stripe-smoke.sh` curl hints | After sign-in in browser |

**Mapping prices in Rust** (names are yours; env vars are suggestions):

```rust
StripePlan::new("pro").price_id(std::env::var("STRIPE_PRICE_PRO_MONTHLY")?),
StripePlan::new("team")
    .price_id(std::env::var("STRIPE_PRICE_TEAM_MONTHLY")?)
    .annual_discount_price_id(std::env::var("STRIPE_PRICE_TEAM_YEARLY")?)
    .seat_price_id(std::env::var("STRIPE_PRICE_TEAM_SEAT")?),
```

Run env checks:

```bash
chmod +x scripts/stripe-smoke.sh
./scripts/stripe-smoke.sh
```

---

## 4. Stripe Dashboard (test mode)

Create before smoke testing:

1. **Products & Prices** — at least one recurring price per plan name (`pro`, `team`, …). Copy each `price_…` into env / `StripePlan`.
2. **Customers** — usually created by OpenAuth on sign-up (`create_customer_on_sign_up(true)`); optional manual customer for debugging.
3. **Webhooks (production-like)** — optional if you use CLI only; for deployed smoke, endpoint URL = `{OPENAUTH_BASE_URL}/stripe/webhook`, events:
   - `checkout.session.completed`
   - `customer.subscription.created`
   - `customer.subscription.updated`
   - `customer.subscription.deleted`

**Local development:** prefer CLI forwarding (signing secret rotates per `stripe listen` session).

---

## 5. Local server setup

### Smoke server (no example UI)

From repo root with `.env` loaded:

```bash
set -a && source .env && set +a
cargo run -p openauth-example-stripe-smoke
```

Uses memory DB, path `/api/auth` (must match `OPENAUTH_BASE_URL`), and reads `STRIPE_*` / `OPENAUTH_*` from the environment.

The smoke server (`cargo run -p openauth-example-stripe-smoke`):

- Binds to a **free port** (not necessarily 3000).
- Starts **`stripe listen` itself** and uses the printed `whsec_…` (you do **not** need `STRIPE_WEBHOOK_SECRET` in `.env`).
- Runs a **signed webhook self-test** on startup (HTTP 200).

`stripe trigger` through the CLI may still return **400** if the forwarded body bytes differ from what Stripe signed; completing **Checkout in the browser** is the reliable end-to-end path.

1. **Migrate schema** — ensure plugin contributions exist:
   - `user.stripe_customer_id`
   - `organization.stripe_customer_id` (if org billing enabled)
   - `subscriptions` table (if `SubscriptionOptions::enabled`)

2. **Configure plugin** (minimal user billing):

```rust
.plugin(stripe(
    StripeOptions::new(
        StripeClient::new(std::env::var("STRIPE_SECRET_KEY")?),
        std::env::var("STRIPE_WEBHOOK_SECRET")?,
    )
    .create_customer_on_sign_up(true)
    .subscription(SubscriptionOptions::enabled(vec![/* plans */])),
))
```

3. **`base_url`** must match how clients call routes. Endpoints mount under that prefix, e.g. `POST {base_url}/subscription/upgrade`, `POST {base_url}/stripe/webhook`.

4. **Organization billing** (optional):

```rust
.organization(OrganizationStripeOptions::enabled())
.subscription(
    SubscriptionOptions::enabled(plans)
        .authorize_reference(|input, _| { /* return Ok(true) when allowed */ }),
)
```

5. Start server, then in a second terminal:

```bash
stripe listen --forward-to "${OPENAUTH_BASE_URL%/}/stripe/webhook"
```

Copy the printed `whsec_…` into `STRIPE_WEBHOOK_SECRET` and restart the server if the secret changed.

---

## 6. Smoke flows (checklist)

Use a fresh test user email per full pass when testing sign-up customer creation.

### 6.1 Sign-up → Stripe customer

| Step | Action | Pass criteria |
| --- | --- | --- |
| 1 | Register / create user via your auth flow | HTTP success |
| 2 | Check Stripe Dashboard → Customers | Customer with user email; metadata `userId`, `customerType: user` (if set by plugin) |
| 3 | Check DB `user` row | `stripe_customer_id` populated (`cus_…`) |
| 4 | Check logs | No `Failed to create or link Stripe customer on sign-up` (error) |

### 6.2 Upgrade → Checkout

| Step | Action | Pass criteria |
| --- | --- | --- |
| 1 | `POST /subscription/upgrade` with session cookie, body e.g. `{"plan":"pro","successUrl":"…","cancelUrl":"…","disableRedirect":true}` | `url` or checkout session in JSON |
| 2 | DB `subscription` | Row `status: incomplete`, `reference_id` = user id, `stripe_subscription_id` null until checkout completes |
| 3 | Open Checkout URL, pay with test card (§8) | Stripe Checkout succeeds |
| 4 | Redirect to `successUrl` or call `GET /subscription/success?…` | Active/trialing subscription reflected |

**Org upgrade:** set `"customerType":"organization"` and `"referenceId":"<org_id>"` after `authorize_reference` allows it; verify org `stripe_customer_id` and metadata `organizationId`.

### 6.3 Webhooks — `checkout.session.completed`

| Step | Action | Pass criteria |
| --- | --- | --- |
| 1 | Complete checkout (or `stripe trigger checkout.session.completed` with matching fixtures) | CLI shows `200` to webhook URL |
| 2 | DB `subscription` | `stripe_subscription_id` set, `status` matches Stripe (`active` / `trialing`), periods and `seats` updated |
| 3 | Logs | No `Stripe webhook failed (checkout.session.completed)`; warnings only if misconfigured plan |

### 6.4 Webhooks — `customer.subscription.created`

| Step | Action | Pass criteria |
| --- | --- | --- |
| 1 | Subscription created outside checkout (Dashboard/API) linked to existing `stripe_customer_id` | New `subscription` row or skip log if duplicate |
| 2 | Logs | `Stripe webhook: Subscription already exists in database` (info) when duplicate; warn if no `stripeCustomerId` match |

### 6.5 Webhooks — `customer.subscription.updated`

| Step | Action | Pass criteria |
| --- | --- | --- |
| 1 | Change plan/seats in Stripe or via portal | DB `status`, `seats`, `cancel_at_period_end`, period fields updated |
| 2 | Schedule cancel at period end | `cancel_at_period_end` true, `cancel_at` set |
| 3 | Logs | No `Stripe webhook failed (customer.subscription.updated)` |

### 6.6 Webhooks — `customer.subscription.deleted`

| Step | Action | Pass criteria |
| --- | --- | --- |
| 1 | Cancel subscription immediately in Stripe | DB `status: canceled`, `ended_at` / `canceled_at` as applicable |
| 2 | Logs | Warn `Subscription not found for stripeSubscriptionId` only if DB never had row |

### 6.7 Cancel at period end (API)

| Step | Action | Pass criteria |
| --- | --- | --- |
| 1 | `POST /subscription/cancel` with `returnUrl`, optional `subscriptionId` | Portal or billing flow URL (unless `disableRedirect`) |
| 2 | DB + Stripe | `cancel_at_period_end` true; restore still possible |

### 6.8 Restore

| Step | Action | Pass criteria |
| --- | --- | --- |
| 1 | `POST /subscription/restore` | Stripe subscription no longer set to cancel at period end |
| 2 | DB | `cancel_at` cleared where applicable |

### 6.9 List subscriptions

| Step | Action | Pass criteria |
| --- | --- | --- |
| 1 | `GET /subscription/list` (optional `?customerType=organization&referenceId=…`) | JSON array with plan, status, limits/priceId if configured |
| 2 | Cross-user | Other user’s `referenceId` rejected (403) when `authorize_reference` denies |

### 6.10 Billing portal

| Step | Action | Pass criteria |
| --- | --- | --- |
| 1 | `POST /subscription/billing-portal` with `returnUrl` | Stripe Billing Portal URL |
| 2 | Manage payment method / cancel in portal | Webhooks update DB (§6.5–6.6) |

### 6.11 Organization customer + `authorizeReference`

| Step | Action | Pass criteria |
| --- | --- | --- |
| 1 | Create organization | Org row exists |
| 2 | Upgrade with `customerType: organization` without hook | `AUTHORIZE_REFERENCE_REQUIRED` |
| 3 | With hook returning true | Checkout uses org customer; metadata `organizationId` |
| 4 | Update org name | Stripe customer name updated (or log warn on failure) |

### 6.12 Seat sync (org + `seat_price_id`)

| Step | Action | Pass criteria |
| --- | --- | --- |
| 1 | Active/trialing org subscription with seat pricing | Baseline `seats` in DB |
| 2 | Add/remove member or accept invitation | Stripe subscription quantity updated |
| 3 | Logs | No `Failed to sync seats to Stripe` (error); seat sync skipped silently if sub not active/trialing |

### 6.13 Trial paths (if configured)

| Step | Action | Pass criteria |
| --- | --- | --- |
| 1 | Plan with `FreeTrialOptions::new(days)` | Checkout includes trial; first subscription `trialing` |
| 2 | User who already trialed (`trial_start` in DB) | Upgrade skips trial (no `trial_period_days` in session) |
| 3 | Trial end webhook path | Status moves to `active`; optional hooks fire |

### 6.14 Email sync

| Step | Action | Pass criteria |
| --- | --- | --- |
| 1 | Update user email in DB | Stripe customer email updated |
| 2 | Logs | No `Failed to sync email to Stripe customer` |

### 6.15 User profile update (metadata)

| Step | Action | Pass criteria |
| --- | --- | --- |
| 1 | Upgrade with custom `metadata` in body | Passed through to Checkout/Customer as configured |

---

## 7. HTTP reference (authenticated routes)

All subscription routes require a valid session unless your stack differs. Paths are relative to `OPENAUTH_BASE_URL`.

| Method | Path | Body / query highlights |
| --- | --- | --- |
| `POST` | `/subscription/upgrade` | `plan`, `successUrl`, `cancelUrl`, optional `referenceId`, `customerType`, `seats`, `annual`, `disableRedirect` |
| `POST` | `/subscription/cancel` | `returnUrl`, optional `subscriptionId`, `customerType` |
| `POST` | `/subscription/restore` | optional `subscriptionId`, `referenceId`, `customerType` |
| `GET` | `/subscription/list` | `?referenceId=&customerType=` |
| `GET` | `/subscription/success` | Stripe redirect query params |
| `POST` | `/subscription/billing-portal` | `returnUrl`, optional `referenceId`, `customerType` |
| `POST` | `/stripe/webhook` | Raw body + `Stripe-Signature` (no session) |

---

## 8. Stripe test cards (appendix)

| Card | Scenario |
| --- | --- |
| `4242 4242 4242 4242` | Success (any future expiry, any CVC) |
| `4000 0025 0000 3155` | Requires 3D Secure authentication |
| `4000 0000 0000 9995` | Declined |

More: [Stripe testing docs](https://docs.stripe.com/testing).

---

## 9. Verify database state

Table names follow your adapter; logical models:

### `user`

| Field | After sign-up | After checkout |
| --- | --- | --- |
| `stripe_customer_id` | `cus_…` | unchanged |
| `email` | set | synced to Stripe on update |

### `organization` (if enabled)

| Field | Expected |
| --- | --- |
| `stripe_customer_id` | Set on first org checkout or customer ensure |
| `name` | Synced to Stripe customer display name |

### `subscription` (`subscriptions` table)

| Field | Expected |
| --- | --- |
| `reference_id` | User id or organization id |
| `plan` | Lowercase plan name (`pro`, `team`) |
| `status` | `incomplete` → `trialing` / `active` → `canceled` |
| `stripe_customer_id` | `cus_…` |
| `stripe_subscription_id` | `sub_…` after checkout/webhook |
| `period_start` / `period_end` | Unix timestamps from Stripe items |
| `trial_start` / `trial_end` | Set when trialing |
| `cancel_at_period_end` | Boolean |
| `cancel_at` / `canceled_at` / `ended_at` | Set when canceling |
| `seats` | Quantity (org seat plans) |
| `billing_interval` | `month` / `year` |
| `stripe_schedule_id` | Optional, when schedules used |

**SQLite example** (adjust path):

```sql
SELECT id, email, stripe_customer_id FROM user WHERE email = 'you@example.com';
SELECT id, reference_id, plan, status, stripe_subscription_id, seats
  FROM subscriptions WHERE reference_id = 'user_…';
```

---

## 10. Log lines to watch

Best-effort hooks and webhook handlers **log and continue** (HTTP 200 for valid webhooks). Grep your app logs for these strings.

### Startup (plugin init)

| Level | Message |
| --- | --- |
| warn | `stripe_webhook_secret is empty` |
| error | `seatPriceId is configured on a plan but stripe organization option is not enabled` |

### Database hooks

| Level | Message | Meaning |
| --- | --- | --- |
| error | `Failed to create or link Stripe customer on sign-up` | Stripe down, bad key, or adapter issue |
| error | `Failed to sync email to Stripe customer` | Email update succeeded in DB but not Stripe |
| error | `Failed to sync organization name to Stripe customer` | Org rename not reflected in Stripe |
| error | `Failed to sync seats to Stripe` | Member/invite change did not update subscription quantity |
| warn | `Stripe customers.search failed, falling back to customers.list` | Search API failed; fallback used |

### Webhook handlers

| Level | Message | Meaning |
| --- | --- | --- |
| error | `Stripe webhook failed (checkout.session.completed): …` | Handler error (still 200 if signature OK) |
| error | `Stripe webhook failed (customer.subscription.…): …` | Same for lifecycle events |
| error | `Failed to construct Stripe event` / parse errors | Bad signature or body (returns 4xx) |
| error | `Stripe on_event hook failed: …` | Custom `on_event` returned error (4xx) |
| warn | `Stripe webhook warning: …` | Skipped work (missing plan, unknown customer, unresolved checkout) |
| info | `Stripe webhook: Subscription already exists in database (id: …), skipping creation` | Idempotent skip |

### Fatal to the HTTP request (not best-effort)

- Missing `Stripe-Signature` header
- Empty webhook secret at runtime
- Invalid signature

---

## 11. Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Webhook 400 signature | Wrong `STRIPE_WEBHOOK_SECRET` | Copy fresh secret from `stripe listen`; restart server |
| Webhook 500 secret not found | Empty secret in `StripeOptions` | Set env; check init warn in logs |
| Checkout succeeds, DB stays `incomplete` | Webhooks not reaching server | `stripe listen` URL must match `{base_url}/stripe/webhook` |
| `no items matching a configured plan` | Price ID mismatch | Dashboard price must equal `StripePlan::price_id` |
| `No user or organization found with stripeCustomerId` | Customer not linked in DB | Run sign-up hook or manual customer ensure |
| Upgrade 403 reference | `authorize_reference` denied | Implement hook for org/member access |
| `AUTHORIZE_REFERENCE_REQUIRED` | Org billing without hook | `.authorize_reference(...)` on `SubscriptionOptions` |
| Duplicate incomplete rows | Old bug; should reuse | Upgrade again; check tests `reuse_incomplete` |
| Seat quantity unchanged | Sub not `active`/`trialing` | Expected skip; fix subscription status first |
| Customer not on sign-up | Hook disabled or error swallowed | Enable `create_customer_on_sign_up`; grep hook error |

---

## 12. Automated tests (CI)

Integration tests use a fake `StripeTransport` (no network). Run:

```bash
cargo fmt --all
cargo clippy -p openauth-stripe --all-targets -- -D warnings
cargo nextest run -p openauth-stripe
```

Manual smoke (this document) complements but does not replace those tests.

---

## 13. Qué necesito y dónde ponerlo (resumen en español)

**Qué necesitas**

1. Cuenta Stripe en **modo test** y la [Stripe CLI](https://stripe.com/docs/stripe-cli).
2. Claves: `STRIPE_SECRET_KEY` (`sk_test_…`) y `STRIPE_WEBHOOK_SECRET` (`whsec_…` de `stripe listen` o del Dashboard).
3. Precios de test (`price_…`) creados en el Dashboard y copiados a variables `STRIPE_PRICE_*` que coincidan con tus `StripePlan` en Rust.
4. Servidor OpenAuth con el plugin `stripe`, base de datos migrada y `OPENAUTH_SECRET` + `OPENAUTH_BASE_URL` correctos.
5. Para probar rutas con `curl`: cookie de sesión tras iniciar sesión (`OPENAUTH_SESSION_COOKIE`).

**Dónde ponerlo**

| Qué | Dónde |
| --- | --- |
| Todas las variables de entorno | Archivo **`.env` en la raíz del repo** (recomendado). Plantilla: `crates/openauth-stripe/.env.smoke.example` |
| Secretos reales | **Nunca** en git; solo en `.env` local o gestor de secretos |
| `price_id` de cada plan | En tu código `StripeOptions` / `StripePlan`, leyendo `std::env::var("STRIPE_PRICE_…")` |
| URL del webhook local | Terminal: `stripe listen --forward-to http://TU_HOST/api/auth/stripe/webhook` (ajusta a tu `OPENAUTH_BASE_URL`) |

**Comprobación rápida**

```bash
cp crates/openauth-stripe/.env.smoke.example .env
# Edita .env con tus claves y price IDs
./scripts/stripe-smoke.sh
```

Sigue las secciones 6–9 de este documento para validar cada flujo y la sección 10 para revisar los logs.
