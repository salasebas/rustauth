# Stripe Upstream Server Checklist Implementation Plan

> **Guide note:** This document is a reusable implementation guide/checklist, not a requirement to copy Better Auth line by line. If a Rust implementation adds safer, more explicit, or broader behavior that fully covers the upstream intent, mark the matching item as complete.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a reusable checklist for the server-side behavior in Better Auth's upstream Stripe package.

**Architecture:** Treat `upstream/better-auth/1.6.9/repository/packages/stripe` as the behavioral source of truth. Port server behavior into idiomatic Rust around explicit types, storage contracts, validated endpoints, typed errors, webhook verification, and provider boundaries. Browser-only/client-only TypeScript details are listed only when they reveal server API surface.

**Tech Stack:** Rust workspace crates, Stripe API equivalent, OpenAuth plugin/router/storage abstractions, webhook signature verification, JSON validation, async HTTP, time/date handling.

---

## Source Scope

Upstream package inspected:

- `upstream/better-auth/1.6.9/repository/packages/stripe/src/index.ts`
- `upstream/better-auth/1.6.9/repository/packages/stripe/src/routes.ts`
- `upstream/better-auth/1.6.9/repository/packages/stripe/src/hooks.ts`
- `upstream/better-auth/1.6.9/repository/packages/stripe/src/middleware.ts`
- `upstream/better-auth/1.6.9/repository/packages/stripe/src/schema.ts`
- `upstream/better-auth/1.6.9/repository/packages/stripe/src/types.ts`
- `upstream/better-auth/1.6.9/repository/packages/stripe/src/metadata.ts`
- `upstream/better-auth/1.6.9/repository/packages/stripe/src/utils.ts`
- `upstream/better-auth/1.6.9/repository/packages/stripe/src/error-codes.ts`
- `upstream/better-auth/1.6.9/repository/packages/stripe/src/version.ts`
- `upstream/better-auth/1.6.9/repository/packages/stripe/src/client.ts` only as client API surface reference.
- `upstream/better-auth/1.6.9/repository/packages/stripe/test/*.ts`

Out of scope for Rust server core:

- [ ] `src/client.ts` client plugin implementation details, except method names and paths exposed by the server.
- [ ] Build-only files: `tsdown.config.ts`, `tsconfig.json`, `vitest.config.ts`.
- [ ] TypeScript compile-time inference tests that do not map to Rust runtime behavior.

## Dependencies To Map

- [ ] Stripe SDK/API client: upstream uses peer dependency `stripe` `^18 || ^19 || ^20 || ^21 || ^22`.
- [ ] Webhook event construction: upstream supports `constructEventAsync` for Stripe v19+ and `constructEvent` for Stripe v18.
- [ ] Runtime validation: upstream uses `zod`; Rust needs request DTO validation and typed enum parsing.
- [ ] API documentation metadata: upstream uses `zod.meta(...)` descriptions and `metadata.openapi.operationId`; Rust endpoint definitions should preserve operation names and enough request/response documentation to generate equivalent API docs.
- [ ] Deep merge/default merge: upstream uses `defu` for Stripe customer/session parameter merging; Rust needs a deterministic merge strategy where internal fields win.
- [ ] Better Auth endpoint/middleware layer: upstream uses `createAuthEndpoint`, `createAuthMiddleware`, `sessionMiddleware`, `originCheck`, `getSessionFromCtx`.
- [ ] Better Auth storage adapter: upstream assumes `findOne`, `findMany`, `create`, `update`, `deleteMany`, `count`, and internal user update.
- [ ] Better Auth organization plugin integration: upstream depends on organization records, member count, active organization session field, and organization hooks.
- [ ] Date/time conversion: upstream converts Stripe epoch seconds into dates for periods, trials, cancellations, and ended timestamps.
- [ ] Hidden endpoint metadata: upstream uses `HIDE_METADATA` for the webhook endpoint so it is not exposed like normal public auth APIs.
- [ ] Test harness equivalents: upstream tests use `vitest`, `getTestInstance`, `memoryAdapter`, organization plugin/client helpers, and Stripe API mocks; Rust needs equivalent in-memory storage, request harness, and Stripe mock/fake client boundaries.

## Dependency Function Matrix

- [ ] `stripe` SDK/customer API: customer search, paginated customer list, customer create, customer retrieve, customer update.
- [ ] `stripe` SDK/subscription API: subscription list, retrieve, update, status inspection, cancellation fields, schedule references, subscription items.
- [ ] `stripe` SDK/checkout API: checkout session create and retrieve.
- [ ] `stripe` SDK/billing portal API: portal session create, subscription update confirmation flow, subscription cancel flow.
- [ ] `stripe` SDK/subscription schedules API: list, create from subscription, update phases, retrieve, release.
- [ ] `stripe` SDK/prices API: price lookup by lookup key and retrieve by price id for metered billing detection.
- [ ] `stripe` SDK/webhooks API: raw payload signature verification and event construction.
- [ ] `defu`: user customer creation params merge, organization customer creation params merge, and preservation of internal metadata precedence.
- [ ] `zod`: request body/query validation, defaults, enum parsing, loose record metadata, and OpenAPI descriptions.
- [ ] `better-auth/api`: session extraction, session middleware, origin checks, redirects, JSON responses.
- [ ] `@better-auth/core/api`: endpoint and middleware construction.
- [ ] `@better-auth/core/error`: `APIError.from` status/code mapping.
- [ ] `@better-auth/core/db` and `better-auth/db`: plugin schema declaration and schema merging.
- [ ] `better-auth/plugins/organization`: organization records, active organization id, member records, and organization hook integration.
- [ ] `better-call`: upstream peer dependency for endpoint transport/runtime; Rust should map this to OpenAuth's router/extractor layer.

## Suggested Rust Modularization

- [ ] Keep the public entry module small: expose plugin builder, config types, public DTOs, and error codes.
- [ ] Split plugin registration and lifecycle hooks into `plugin` or equivalent.
- [ ] Split configuration and plan types into `config` or equivalent.
- [ ] Split storage models/schema mapping into `schema` or equivalent.
- [ ] Split error codes and typed errors into `error` or equivalent.
- [ ] Split metadata merge/extract/prototype-pollution-safe behavior into `metadata` or equivalent.
- [ ] Split utility functions into `utils` or focused submodules for plan resolution, Stripe price resolution, URL handling, and state predicates.
- [ ] Split auth/reference/origin middleware into `middleware` or equivalent.
- [ ] Split route handlers by endpoint instead of keeping all endpoint logic in one large file.
- [ ] Split webhook dispatcher from webhook event handlers.
- [ ] Split checkout-session webhook behavior from subscription-created, subscription-updated, and subscription-deleted behavior.
- [ ] Split organization integration and organization hook behavior from user subscription behavior.
- [ ] Split Stripe API access behind a trait/interface so tests can use fakes without live Stripe calls.
- [ ] Mirror behavior tests by domain: metadata/utils, user subscriptions, organization subscriptions, seat billing, webhooks, scheduling, metered billing, authorization.
- [ ] Avoid a single catch-all Stripe module that mixes endpoint validation, Stripe calls, storage mutations, callbacks, and webhook dispatch.

## Public Plugin Configuration

- [ ] `stripeClient` option for Stripe API access.
- [ ] `stripeWebhookSecret` option for webhook signature verification.
- [ ] `createCustomerOnSignUp` option.
- [ ] `onCustomerCreate` callback for user Stripe customers.
- [ ] `getCustomerCreateParams` callback for user Stripe customer creation params.
- [ ] `onEvent` callback for all received Stripe webhook events.
- [ ] `subscription.enabled` gate for all subscription endpoints.
- [ ] `subscription.plans` static list or async/lazy provider.
- [ ] `subscription.requireEmailVerification`.
- [ ] `subscription.onSubscriptionComplete`.
- [ ] `subscription.onSubscriptionUpdate`.
- [ ] `subscription.onSubscriptionCancel`.
- [ ] `subscription.authorizeReference`.
- [ ] `subscription.onSubscriptionDeleted`.
- [ ] `subscription.onSubscriptionCreated`.
- [ ] `subscription.getCheckoutSessionParams`.
- [ ] `organization.enabled` gate for organization Stripe customers.
- [ ] `organization.getCustomerCreateParams`.
- [ ] `organization.onCustomerCreate`.
- [ ] Custom schema override/merge behavior.
- [ ] Package/plugin version exposure.
- [ ] Stripe plugin error code exposure.

## Plan Model

- [ ] `StripePlan.name`.
- [ ] `StripePlan.priceId`.
- [ ] `StripePlan.lookupKey`.
- [ ] `StripePlan.annualDiscountPriceId`.
- [ ] `StripePlan.annualDiscountLookupKey`.
- [ ] `StripePlan.limits`.
- [ ] `StripePlan.group`.
- [ ] `StripePlan.seatPriceId`.
- [ ] `StripePlan.prorationBehavior`.
- [ ] `StripePlan.lineItems`.
- [ ] `StripePlan.freeTrial.days`.
- [ ] `StripePlan.freeTrial.onTrialStart`.
- [ ] `StripePlan.freeTrial.onTrialEnd`.
- [ ] `StripePlan.freeTrial.onTrialExpired`.
- [ ] `CheckoutSessionLocale` accepts Stripe checkout/customer-portal locale strings.
- [ ] `CheckoutSessionLineItem` supports Stripe checkout line item parameters for add-ons or usage items.
- [ ] `CustomerType` is modeled as `user | organization`.
- [ ] `AuthorizeReferenceAction` is modeled as the exact subscription action enum used by middleware.
- [ ] `WithStripeCustomerId` extension is represented for users and organizations without relying on hidden globals.
- [ ] `WithActiveOrganizationId` extension is represented for sessions when organization integration is enabled.

## Storage Schema

- [ ] Add `user.stripeCustomerId`.
- [ ] Add `organization.stripeCustomerId` only when organization integration is enabled.
- [ ] Add `subscription.plan`.
- [ ] Add `subscription.referenceId`.
- [ ] Add `subscription.stripeCustomerId`.
- [ ] Add `subscription.stripeSubscriptionId`.
- [ ] Add `subscription.status`.
- [ ] Add `subscription.periodStart`.
- [ ] Add `subscription.periodEnd`.
- [ ] Add `subscription.trialStart`.
- [ ] Add `subscription.trialEnd`.
- [ ] Add `subscription.cancelAtPeriodEnd`.
- [ ] Add `subscription.cancelAt`.
- [ ] Add `subscription.canceledAt`.
- [ ] Add `subscription.endedAt`.
- [ ] Add `subscription.seats`.
- [ ] Add `subscription.billingInterval`.
- [ ] Add `subscription.stripeScheduleId`.
- [ ] Merge custom schema fields with plugin schema.
- [ ] Omit `subscription` schema when subscriptions are disabled, even if custom schema includes it.
- [ ] Treat `Subscription.priceId` as a public/computed response field when listing subscriptions; upstream type exposes it but the DB schema does not store it.
- [ ] Treat `Subscription.groupId` as a public type concept for multiple subscriptions per reference; upstream type exposes it but the 1.6.9 DB schema does not store or use it.
- [ ] Preserve lower-case plan storage behavior so plan comparisons remain stable.

## Subscription Status Values

- [ ] `active`.
- [ ] `canceled`.
- [ ] `incomplete`.
- [ ] `incomplete_expired`.
- [ ] `past_due`.
- [ ] `paused`.
- [ ] `trialing`.
- [ ] `unpaid`.

## Error Codes

- [ ] `UNAUTHORIZED`.
- [ ] `INVALID_REQUEST_BODY`.
- [ ] `SUBSCRIPTION_NOT_FOUND`.
- [ ] `SUBSCRIPTION_PLAN_NOT_FOUND`.
- [ ] `ALREADY_SUBSCRIBED_PLAN`.
- [ ] `REFERENCE_ID_NOT_ALLOWED`.
- [ ] `CUSTOMER_NOT_FOUND`.
- [ ] `UNABLE_TO_CREATE_CUSTOMER`.
- [ ] `UNABLE_TO_CREATE_BILLING_PORTAL`.
- [ ] `STRIPE_SIGNATURE_NOT_FOUND`.
- [ ] `STRIPE_WEBHOOK_SECRET_NOT_FOUND`.
- [ ] `STRIPE_WEBHOOK_ERROR`.
- [ ] `FAILED_TO_CONSTRUCT_STRIPE_EVENT`.
- [ ] `FAILED_TO_FETCH_PLANS`.
- [ ] `EMAIL_VERIFICATION_REQUIRED`.
- [ ] `SUBSCRIPTION_NOT_ACTIVE`.
- [ ] `SUBSCRIPTION_NOT_SCHEDULED_FOR_CANCELLATION` deprecated alias behavior.
- [ ] `SUBSCRIPTION_NOT_PENDING_CHANGE`.
- [ ] `ORGANIZATION_NOT_FOUND`.
- [ ] `ORGANIZATION_SUBSCRIPTION_NOT_ENABLED`.
- [ ] `AUTHORIZE_REFERENCE_REQUIRED`.
- [ ] `ORGANIZATION_HAS_ACTIVE_SUBSCRIPTION`.
- [ ] `ORGANIZATION_REFERENCE_ID_REQUIRED`.

## Metadata Helpers And Security

- [ ] Merge customer metadata with internal fields taking final priority.
- [ ] Merge subscription metadata with internal fields taking final priority.
- [ ] Drop unsafe metadata keys: `__proto__`, `constructor`, `prototype`.
- [ ] Customer metadata keys: `userId`, `organizationId`, `customerType`.
- [ ] Customer metadata supports `customerType = user`.
- [ ] Customer metadata supports `customerType = organization`.
- [ ] Subscription metadata keys: `userId`, `subscriptionId`, `referenceId`.
- [ ] Extract typed customer metadata from Stripe metadata.
- [ ] Extract typed subscription metadata from Stripe metadata.
- [ ] Prevent user metadata from spoofing internal metadata fields.

## Utility Functions

- [ ] Resolve plans from static list.
- [ ] Resolve plans from async/lazy function.
- [ ] Error when resolving plans while subscriptions are disabled.
- [ ] Find plan by name case-insensitively.
- [ ] Determine active/trialing state.
- [ ] Determine DB pending cancellation by `cancelAtPeriodEnd` or `cancelAt`.
- [ ] Determine Stripe pending cancellation by `cancel_at_period_end` or `cancel_at`.
- [ ] Escape double quotes for Stripe search query strings.
- [ ] Resolve quantity from seat item first, then base plan item.
- [ ] Resolve matching plan item from subscription items by `priceId`.
- [ ] Resolve matching plan item by `annualDiscountPriceId`.
- [ ] Resolve matching plan item by `lookupKey`.
- [ ] Resolve matching plan item by `annualDiscountLookupKey`.
- [ ] Return first item with no plan for unmatched single-item subscriptions.
- [ ] Return no match for unmatched multi-item subscriptions.
- [ ] Resolve Stripe price by lookup key through `prices.list`.
- [ ] Resolve Stripe price by price id through `prices.retrieve`.
- [ ] Treat failed price resolution as licensed billing fallback.
- [ ] Detect metered prices by `price.recurring.usage_type == metered`.
- [ ] Convert relative return/success/cancel URLs against auth base URL.
- [ ] Preserve absolute URLs.
- [ ] Resolve default user reference id from session user id.
- [ ] Resolve organization reference id from active organization id.

## Middleware And Authorization

- [ ] Session middleware returns Stripe session with user and session.
- [ ] Reference middleware rejects missing session.
- [ ] User reference action passes when no explicit `referenceId` is provided.
- [ ] User reference action passes when explicit `referenceId` equals current user id.
- [ ] User reference action rejects explicit foreign `referenceId` without `authorizeReference`.
- [ ] User reference action calls `authorizeReference` for explicit custom references.
- [ ] User reference action rejects when `authorizeReference` returns false.
- [ ] Organization reference action requires `authorizeReference`.
- [ ] Organization reference action uses explicit `referenceId` or `session.activeOrganizationId`.
- [ ] Organization reference action rejects when no reference id is available.
- [ ] Organization reference action rejects when `authorizeReference` returns false.
- [ ] Pass action names into `authorizeReference`: `upgrade-subscription`, `list-subscription`, `cancel-subscription`, `restore-subscription`, `billing-portal`.
- [ ] Apply origin checks to upgrade success/cancel URLs.
- [ ] Apply origin checks to cancel return URL.
- [ ] Apply origin checks to billing portal return URL.
- [ ] Apply origin checks to subscription success callback URL.

## Endpoint Construction And OpenAPI

- [ ] All server routes are declared through the OpenAuth equivalent of `createAuthEndpoint`.
- [ ] Request bodies and queries are validated before business logic runs.
- [ ] Request defaults match upstream defaults before handler logic runs.
- [ ] Endpoint metadata includes OpenAPI operation id `upgradeSubscription` for `POST /subscription/upgrade`.
- [ ] Endpoint metadata includes OpenAPI operation id `cancelSubscription` for `POST /subscription/cancel`.
- [ ] Endpoint metadata includes OpenAPI operation id `restoreSubscription` for `POST /subscription/restore`.
- [ ] Endpoint metadata includes OpenAPI operation id `listActiveSubscriptions` for `GET /subscription/list`.
- [ ] Endpoint metadata includes OpenAPI operation id `handleSubscriptionSuccess` for `GET /subscription/success`.
- [ ] Endpoint metadata includes OpenAPI operation id `createBillingPortal` for `POST /subscription/billing-portal`.
- [ ] Endpoint metadata includes OpenAPI operation id `handleStripeWebhook` for `POST /stripe/webhook`.
- [ ] Webhook endpoint is marked hidden/private from normal generated public API surfaces.
- [ ] Webhook endpoint clones or preserves raw request access before body parsing.
- [ ] Webhook endpoint disables normal parsed body extraction.
- [ ] Endpoint responses preserve upstream redirect contract: JSON responses include `redirect` when `disableRedirect` can be requested.
- [ ] Redirecting endpoint behavior uses actual HTTP redirects for `/subscription/success`.
- [ ] Stripe/API errors that include a Stripe `code` preserve that code in the mapped API error when available.
- [ ] Server-facing API names are stable even if the Rust client wrapper is generated differently.

## Plugin Initialization And Database Hooks

- [ ] Register `stripe` plugin id and version.
- [ ] Always register `/stripe/webhook`.
- [ ] Expose plugin `schema` from `getSchema(options)`.
- [ ] Store original plugin options for later handler access.
- [ ] Expose `$ERROR_CODES` or Rust equivalent so callers can match stable Stripe plugin errors.
- [ ] Register subscription endpoints only when `subscription.enabled` is true.
- [ ] Do not register subscription endpoints when `subscription.enabled` is false or absent.
- [ ] Log configuration error when any plan has `seatPriceId` but organization integration is disabled.
- [ ] Resolve async plan lists for seat pricing validation and log failures.
- [ ] Detect missing organization plugin when `organization.enabled` is true.
- [ ] Preserve existing organization hooks while adding Stripe hooks.
- [ ] On user create, skip if no context.
- [ ] On user create, skip unless `createCustomerOnSignUp` is true.
- [ ] On user create, skip if user already has `stripeCustomerId`.
- [ ] On user create, search Stripe customer by email excluding organization customers.
- [ ] On user create, fall back to paginated `customers.list` when search fails.
- [ ] On user create, link existing user Stripe customer and update local user.
- [ ] On user create, create new Stripe customer with email, name, internal metadata, and custom params.
- [ ] On user create, call user `onCustomerCreate`.
- [ ] On user create, log Stripe errors without failing signup.
- [ ] On user update, retrieve Stripe customer by stored id.
- [ ] On user update, skip deleted Stripe customer.
- [ ] On user update, sync Stripe customer email when changed.
- [ ] On user update, log Stripe errors without failing update.
- [ ] Keep database hooks best-effort where upstream logs and continues, especially signup and user email sync.

## Organization Integration

- [ ] Organization customer lookup by `organization.stripeCustomerId`.
- [ ] Organization customer lookup by Stripe metadata `organizationId` and `customerType = organization`.
- [ ] Organization customer lookup falls back from `customers.search` to paginated `customers.list`.
- [ ] Organization customer creation uses organization name and internal metadata.
- [ ] Organization customer creation supports `organization.getCustomerCreateParams`.
- [ ] Organization customer creation calls `organization.onCustomerCreate`.
- [ ] Organization customer id is stored on organization record.
- [ ] Organization name update syncs to Stripe customer name.
- [ ] Organization update skips deleted Stripe customer.
- [ ] Organization deletion is blocked when Stripe has active, trialing, paused, past_due, or unpaid subscriptions.
- [ ] Organization deletion is allowed when all Stripe subscriptions are canceled, incomplete, or incomplete_expired.
- [ ] Organization billing portal resolves customer id from organization first, then active subscription fallback.
- [ ] Organization subscriptions remain separate from user subscriptions sharing the same account.
- [ ] User customer lookup must not match organization customers with same email.
- [ ] Organization customer lookup must not match user customers with organization metadata collisions.

## Seat-Based Billing

- [ ] `seatPriceId` requires organization integration for automatic seat management.
- [ ] Seat quantity is derived from member count for organization subscriptions.
- [ ] Checkout includes base plan item and seat item when base price differs from seat price.
- [ ] Checkout avoids duplicate line item when `priceId == seatPriceId`.
- [ ] Seat-only plans use seat line item quantity from member count.
- [ ] Manual `seats` request field applies to user/custom-reference subscriptions.
- [ ] Auto-managed seats do not block same-plan upgrades by same seat count.
- [ ] Immediate upgrades replace old seat price when new plan has different seat price.
- [ ] Immediate upgrades keep seat item when seat pricing is unchanged.
- [ ] Scheduled upgrades replace seat price in the next phase.
- [ ] Seat item updates use plan `prorationBehavior` or default `create_prorations`.
- [ ] Member added hook updates Stripe seat quantity.
- [ ] Member removed hook updates Stripe seat quantity.
- [ ] Invitation accepted hook updates Stripe seat quantity.
- [ ] Seat sync skips when no Stripe customer exists.
- [ ] Seat sync skips when subscriptions are disabled.
- [ ] Seat sync skips when no plan has `seatPriceId`.
- [ ] Seat sync skips when DB subscription is not active/trialing.
- [ ] Seat sync skips when Stripe subscription is not active/trialing.
- [ ] Seat sync stores updated seat count locally.
- [ ] Webhook creation persists seat count.
- [ ] Webhook update persists seat count.

## Additional Line Items And Metered Billing

- [ ] `StripePlan.lineItems` are included in new checkout sessions.
- [ ] Existing subscriptions can add line items during plan change.
- [ ] Existing subscriptions can remove line items during plan change.
- [ ] Existing subscriptions can replace line item prices during plan change.
- [ ] Duplicate line items are not added when already present.
- [ ] Scheduled plan change computes next phase line item additions/removals/replacements.
- [ ] Immediate plan change uses direct `subscriptions.update` when multiple items must change.
- [ ] Simple single-item plan change uses Billing Portal update confirmation.
- [ ] Metered base prices omit `quantity` in checkout session.
- [ ] Metered prices omit `quantity` in Billing Portal upgrade flow.
- [ ] Metered prices omit `quantity` in direct subscription upgrade flow.
- [ ] Metered prices omit `quantity` in scheduled upgrade phase.

## Subscription Upgrade Endpoint

Endpoint: `POST /subscription/upgrade` (`upgradeSubscription`).

- [ ] Implement route through endpoint constructor with method `POST`.
- [ ] Attach OpenAPI operation id `upgradeSubscription`.
- [ ] Use session middleware, reference middleware, and origin check middleware.
- [ ] Request body validates `plan`.
- [ ] Request body validates optional `annual`.
- [ ] Request body validates optional `referenceId`.
- [ ] Request body validates optional `subscriptionId`.
- [ ] Request body validates optional `customerType = user | organization`.
- [ ] Request body validates optional user metadata.
- [ ] Request body validates optional `seats`.
- [ ] Request body validates optional checkout `locale`.
- [ ] Request body defaults `successUrl` to `/`.
- [ ] Request body defaults `cancelUrl` to `/`.
- [ ] Request body validates optional `returnUrl`.
- [ ] Request body defaults `scheduleAtPeriodEnd` to false.
- [ ] Request body defaults `disableRedirect` to false.
- [ ] Reject upgrade when email verification is required and user email is not verified.
- [ ] Reject unknown plan.
- [ ] If `subscriptionId` is provided, require matching local subscription.
- [ ] If `subscriptionId` is provided, reject subscriptions owned by another reference id.
- [ ] Resolve or create organization Stripe customer when `customerType = organization`.
- [ ] Resolve or create user Stripe customer when `customerType = user`.
- [ ] Link existing Stripe customer instead of creating duplicate.
- [ ] Store Stripe customer id locally after customer resolution.
- [ ] Load local subscriptions by reference id.
- [ ] Fetch active/trialing Stripe subscriptions for the customer.
- [ ] Resolve current Stripe plan item.
- [ ] Reuse incomplete local subscription when no active/trialing subscription exists.
- [ ] Resolve requested price by annual setting and lookup key.
- [ ] Reject when no usable price id exists.
- [ ] Reject already subscribed same active plan, same seats, same price, and valid period.
- [ ] Release existing plugin-created subscription schedule before new changes.
- [ ] Do not release schedules created outside the plugin.
- [ ] For scheduled change, create subscription schedule from current subscription.
- [ ] For scheduled change, create a second phase at period end.
- [ ] For scheduled change, set schedule metadata `source = @better-auth/stripe`.
- [ ] For scheduled change, store `stripeScheduleId` locally.
- [ ] For scheduled change, return `returnUrl`.
- [ ] For immediate multi-item change, update Stripe subscription directly.
- [ ] For immediate multi-item change, update local plan and seats.
- [ ] For simple active subscription change, create Billing Portal `subscription_update_confirm` flow.
- [ ] For new checkout, create local incomplete subscription if needed.
- [ ] For new checkout, call `getCheckoutSessionParams`.
- [ ] For new checkout, prevent multiple free trials for the same reference.
- [ ] For new checkout, add free trial days only when eligible.
- [ ] For new checkout, set Stripe Checkout customer or customer email.
- [ ] For new checkout, set customer update behavior.
- [ ] For new checkout, set locale.
- [ ] For new checkout, build success URL through `/subscription/success`.
- [ ] For new checkout, include encoded `callbackURL` query parameter in success URL.
- [ ] For new checkout, include `checkoutSessionId={CHECKOUT_SESSION_ID}` query parameter in success URL.
- [ ] For new checkout, preserve literal `{CHECKOUT_SESSION_ID}` placeholder.
- [ ] For new checkout, set cancel URL.
- [ ] For new checkout, include base price line item when not seat-only.
- [ ] For new checkout, include seat line item for auto-managed seats.
- [ ] For new checkout, include plan additional line items.
- [ ] For new checkout, set subscription metadata with internal fields protected.
- [ ] For new checkout, set checkout session metadata with internal fields protected.
- [ ] For new checkout, set `client_reference_id`.
- [ ] Response includes Stripe Checkout session plus `redirect`.

## Subscription Cancel Endpoint

Endpoint: `POST /subscription/cancel` (`cancelSubscription`).

- [ ] Implement route through endpoint constructor with method `POST`.
- [ ] Attach OpenAPI operation id `cancelSubscription`.
- [ ] Use session middleware, reference middleware, and origin check middleware.
- [ ] Request body validates optional `referenceId`.
- [ ] Request body validates optional `subscriptionId`.
- [ ] Request body validates optional `customerType = user | organization`.
- [ ] Request body validates `returnUrl`.
- [ ] Request body defaults `disableRedirect` to false.
- [ ] Find subscription by Stripe subscription id when provided.
- [ ] Otherwise find active/trialing subscription for reference id.
- [ ] Reject subscription id owned by another reference id.
- [ ] Reject missing local subscription or missing Stripe customer id.
- [ ] Fetch active/trialing Stripe subscriptions for customer.
- [ ] Delete local subscriptions for reference id when Stripe has no active subscriptions.
- [ ] Require matching active Stripe subscription.
- [ ] Create Billing Portal `subscription_cancel` session.
- [ ] Return portal URL and `redirect`.
- [ ] If Stripe says already scheduled for cancellation, sync `cancelAtPeriodEnd`, `cancelAt`, and `canceledAt` from Stripe when local state missed the webhook.

## Subscription Restore Endpoint

Endpoint: `POST /subscription/restore` (`restoreSubscription`).

- [ ] Implement route through endpoint constructor with method `POST`.
- [ ] Attach OpenAPI operation id `restoreSubscription`.
- [ ] Use session middleware and reference middleware.
- [ ] Request body validates optional `referenceId`.
- [ ] Request body validates optional `subscriptionId`.
- [ ] Request body validates optional `customerType = user | organization`.
- [ ] Find subscription by Stripe subscription id when provided.
- [ ] Otherwise find active/trialing subscription for reference id.
- [ ] Reject subscription id owned by another reference id.
- [ ] Reject missing local subscription or missing Stripe customer id.
- [ ] Reject non-active/non-trialing local subscription.
- [ ] Reject when neither cancellation nor schedule is pending.
- [ ] If `stripeScheduleId` exists, retrieve schedule.
- [ ] If schedule is active, release it.
- [ ] Clear local `stripeScheduleId`.
- [ ] Return Stripe subscription after schedule release.
- [ ] If pending cancel has `cancel_at`, clear it with Stripe.
- [ ] If pending cancel has `cancel_at_period_end`, clear it with Stripe.
- [ ] Clear local `cancelAtPeriodEnd`, `cancelAt`, and `canceledAt`.
- [ ] Return updated Stripe subscription.

## Subscription List Endpoint

Endpoint: `GET /subscription/list` (`listActiveSubscriptions`).

- [ ] Implement route through endpoint constructor with method `GET`.
- [ ] Attach OpenAPI operation id `listActiveSubscriptions`.
- [ ] Use session middleware and reference middleware.
- [ ] Query validates optional `referenceId`.
- [ ] Query validates optional `customerType = user | organization`.
- [ ] Load subscriptions by reference id.
- [ ] Return empty list when no subscriptions exist.
- [ ] Resolve configured plans.
- [ ] Attach plan `limits` to response.
- [ ] Attach monthly `priceId` for non-year intervals.
- [ ] Attach annual discount price id when `billingInterval = year`, falling back to monthly price id.
- [ ] Return only active/trialing subscriptions.

## Subscription Success Endpoint

Endpoint: `GET /subscription/success` (`subscriptionSuccess`).

- [ ] Implement route through endpoint constructor with method `GET`.
- [ ] Attach OpenAPI operation id `handleSubscriptionSuccess`.
- [ ] Use origin check middleware for `callbackURL`.
- [ ] Query accepts flexible callback fields.
- [ ] Redirect to callback URL when no authenticated session exists.
- [ ] Redirect to callback URL when no `checkoutSessionId` exists.
- [ ] Replace `{CHECKOUT_SESSION_ID}` in callback URL with actual checkout session id.
- [ ] Retrieve checkout session from Stripe.
- [ ] Redirect without update when checkout session retrieval fails.
- [ ] Extract internal `subscriptionId` from checkout session metadata.
- [ ] Redirect without update when metadata lacks subscription id.
- [ ] Load local subscription by id.
- [ ] Redirect without update when local subscription is missing.
- [ ] Redirect without update when subscription is already active/trialing.
- [ ] Resolve Stripe customer id from subscription or session user.
- [ ] Fetch active Stripe subscription for customer.
- [ ] Resolve matching plan item.
- [ ] Update local subscription status, plan, seats, billing interval, periods, Stripe subscription id, trial dates, cancellation fields.
- [ ] Redirect to callback URL after update.

## Billing Portal Endpoint

Endpoint: `POST /subscription/billing-portal` (`createBillingPortal`).

- [ ] Implement route through endpoint constructor with method `POST`.
- [ ] Attach OpenAPI operation id `createBillingPortal`.
- [ ] Use session middleware, reference middleware, and origin check middleware.
- [ ] Request body validates optional `locale`.
- [ ] Request body validates optional `referenceId`.
- [ ] Request body validates optional `customerType = user | organization`.
- [ ] Request body defaults `returnUrl` to `/`.
- [ ] Request body defaults `disableRedirect` to false.
- [ ] For organization, resolve customer id from organization record.
- [ ] For organization, fall back to active subscription customer id.
- [ ] For user, resolve customer id from session user.
- [ ] For user, fall back to active subscription customer id.
- [ ] Reject when no Stripe customer id exists.
- [ ] Create Stripe Billing Portal session with locale, customer, and return URL.
- [ ] Return portal URL and `redirect`.
- [ ] Map Stripe portal creation errors to `UNABLE_TO_CREATE_BILLING_PORTAL`.

## Stripe Webhook Endpoint

Endpoint: `POST /stripe/webhook` (`stripeWebhook`).

- [ ] Implement route through endpoint constructor with method `POST`.
- [ ] Attach OpenAPI operation id `handleStripeWebhook`.
- [ ] Apply hidden endpoint metadata equivalent to upstream `HIDE_METADATA`.
- [ ] Disable body parsing and read raw request body.
- [ ] Clone request as needed for raw body access.
- [ ] Reject missing body.
- [ ] Reject missing `stripe-signature` header.
- [ ] Reject missing webhook secret.
- [ ] Verify webhook using async `constructEventAsync` when available.
- [ ] Verify webhook using sync `constructEvent` fallback.
- [ ] Reject invalid signature or failed event construction.
- [ ] Reject null/undefined constructed event.
- [ ] Dispatch `checkout.session.completed`.
- [ ] Dispatch `customer.subscription.created`.
- [ ] Dispatch `customer.subscription.updated`.
- [ ] Dispatch `customer.subscription.deleted`.
- [ ] Call `onEvent` after handled supported events.
- [ ] Call `onEvent` for unsupported events.
- [ ] Convert processing failures to `STRIPE_WEBHOOK_ERROR`.
- [ ] Return `{ success: true }`.

## Webhook Handler: Checkout Session Completed

- [ ] Ignore setup-mode checkout sessions.
- [ ] Ignore when subscriptions are disabled.
- [ ] Retrieve Stripe subscription from checkout session.
- [ ] Resolve matching plan item.
- [ ] Ignore when no plan item matches.
- [ ] Extract `referenceId` from `client_reference_id` or subscription metadata.
- [ ] Extract `subscriptionId` from checkout session metadata.
- [ ] Resolve seats from seat item or base item.
- [ ] Update local subscription by id.
- [ ] Store plan, status, period start/end, Stripe subscription id, cancellation fields, ended date, seats, billing interval.
- [ ] Store trial start/end when Stripe event includes trial data.
- [ ] Call free trial `onTrialStart`.
- [ ] Load updated subscription if adapter update returns nothing.
- [ ] Call `onSubscriptionComplete`.
- [ ] Log errors without throwing out of handler.

## Webhook Handler: Customer Subscription Created

- [ ] Ignore when subscriptions are disabled.
- [ ] Require Stripe customer id.
- [ ] Check existing local subscription by metadata `subscriptionId`.
- [ ] Check existing local subscription by Stripe subscription id when metadata is absent.
- [ ] Skip duplicate creation when local subscription already exists.
- [ ] Find reference by Stripe customer id, organization first when organization integration is enabled.
- [ ] Skip when no user or organization references the customer.
- [ ] Resolve matching plan item.
- [ ] Skip when no item matches configured plans.
- [ ] Skip when no plan matches item.
- [ ] Resolve seats.
- [ ] Store period start/end from subscription item.
- [ ] Store trial start/end when present.
- [ ] Create local subscription for dashboard-created Stripe subscription.
- [ ] Store reference id, Stripe customer id, Stripe subscription id, status, plan, periods, seats, billing interval, and limits.
- [ ] Call `onSubscriptionCreated`.
- [ ] Log errors without throwing out of handler.

## Webhook Handler: Customer Subscription Updated

- [ ] Ignore when subscriptions are disabled.
- [ ] Resolve matching plan item.
- [ ] Ignore when no subscription item exists.
- [ ] Find local subscription by metadata `subscriptionId`.
- [ ] Find local subscription by Stripe subscription id when metadata is absent.
- [ ] Fall back to subscriptions by Stripe customer id.
- [ ] If multiple subscriptions exist for customer, choose active/trialing one.
- [ ] Log and skip when multiple subscriptions exist and none are active/trialing.
- [ ] Resolve seats from configured plan or item quantity.
- [ ] Store trial start/end when present.
- [ ] Update plan, limits, status, periods, cancellation fields, ended date, seats, Stripe subscription id, billing interval, and `stripeScheduleId`.
- [ ] Detect new cancellation when Stripe is active and pending cancel while local subscription was not pending.
- [ ] Call `onSubscriptionCancel` for newly pending cancellation.
- [ ] Call `onSubscriptionUpdate`.
- [ ] Call free trial `onTrialEnd` when Stripe changes trialing subscription to active.
- [ ] Call free trial `onTrialExpired` when Stripe changes trialing subscription to incomplete_expired.
- [ ] Log errors without throwing out of handler.

## Webhook Handler: Customer Subscription Deleted

- [ ] Ignore when subscriptions are disabled.
- [ ] Find local subscription by Stripe subscription id.
- [ ] Mark local subscription as canceled.
- [ ] Store cancellation fields, ended date, trial dates, and clear `stripeScheduleId`.
- [ ] Call `onSubscriptionDeleted`.
- [ ] Log warning when local subscription is missing.
- [ ] Log errors without throwing out of handler.

## Subscription Scheduling

- [ ] `scheduleAtPeriodEnd` schedules plan change instead of immediate update.
- [ ] Create schedule from active subscription.
- [ ] Preserve current phase items and dates.
- [ ] Add next phase with desired prices, quantities, and `proration_behavior = none`.
- [ ] Set schedule `end_behavior = release`.
- [ ] Mark plugin-created schedule with metadata `source = @better-auth/stripe`.
- [ ] Store created schedule id locally.
- [ ] Release existing plugin-created schedule before creating a new one.
- [ ] Release existing plugin-created schedule before immediate upgrade.
- [ ] Do not release non-plugin schedules.
- [ ] Webhook update syncs attached schedule id.
- [ ] Webhook update clears schedule id when Stripe schedule is removed.
- [ ] Webhook delete clears schedule id.
- [ ] Restore endpoint releases active pending schedule and clears local schedule id.

## Free Trials

- [ ] Add trial period days during checkout when plan has free trial.
- [ ] Prevent multiple free trials for the same reference id across all plans.
- [ ] Treat previous `trialStart`, `trialEnd`, or `trialing` status as trial history.
- [ ] Call `onTrialStart` after checkout completion update.
- [ ] Call `onTrialEnd` on active update after trialing state.
- [ ] Call `onTrialExpired` on incomplete_expired update after trialing state.
- [ ] Preserve trial dates from `subscription.updated`.
- [ ] Preserve trial dates from `subscription.deleted`.
- [ ] Prevent trial abuse after subscription canceled during trial.

## Annual Billing And Billing Interval

- [ ] Use `annualDiscountPriceId` when request has `annual = true`.
- [ ] Use `annualDiscountLookupKey` when request has `annual = true` and no price id.
- [ ] Use monthly `priceId` when request has `annual = false` or absent.
- [ ] Use monthly `lookupKey` when no monthly price id exists.
- [ ] Persist billing interval from Stripe subscription item recurring interval.
- [ ] Return annual discount price id from list response when stored interval is `year`.
- [ ] Fallback to monthly price id when annual discount price id is absent.

## Customer Collision And Duplicate Prevention

- [ ] Do not create duplicate customer on signup if Stripe customer already exists by email.
- [ ] Do not create duplicate customer when signup and upgrade happen for same user.
- [ ] User lookup excludes organization customers by metadata.
- [ ] Organization lookup requires organization metadata.
- [ ] Fallback customer list filtering preserves user/organization separation.
- [ ] Existing incomplete subscription is reused instead of creating duplicate local subscription.
- [ ] Existing active subscription is upgraded instead of creating new one.
- [ ] Duplicate subscription is rejected when same plan, same seats, same price, and valid active period.
- [ ] Same plan monthly to annual change is allowed.
- [ ] Same plan seat quantity upgrade is allowed when seats differ or auto-managed seats apply.
- [ ] Active subscription is preferred when canceled subscription also exists for the same reference id.

## Callback Surface

- [ ] User `onCustomerCreate`.
- [ ] Organization `onCustomerCreate`.
- [ ] `getCustomerCreateParams` for users.
- [ ] `organization.getCustomerCreateParams`.
- [ ] `getCheckoutSessionParams`.
- [ ] `authorizeReference`.
- [ ] `onEvent`.
- [ ] `onSubscriptionComplete`.
- [ ] `onSubscriptionCreated`.
- [ ] `onSubscriptionUpdate`.
- [ ] `onSubscriptionCancel`.
- [ ] `onSubscriptionDeleted`.
- [ ] `freeTrial.onTrialStart`.
- [ ] `freeTrial.onTrialEnd`.
- [ ] `freeTrial.onTrialExpired`.

## API Surface Names

- [ ] `auth.api.upgradeSubscription`.
- [ ] `auth.api.cancelSubscription`.
- [ ] `auth.api.restoreSubscription`.
- [ ] `auth.api.listActiveSubscriptions`.
- [ ] `auth.api.subscriptionSuccess` or Rust equivalent for `/subscription/success`.
- [ ] `auth.api.createBillingPortal`.
- [ ] `auth.api.stripeWebhook`.
- [ ] Client-visible POST `/subscription/billing-portal`.
- [ ] Client-visible POST `/subscription/restore`.
- [ ] Client helper/plugin id `stripe-client` is not server logic, but its exposed methods must match server route methods.
- [ ] Client helper exposes Stripe error codes for client-side matching.
- [ ] Client helper infers server plugin shape when subscription support is enabled.

## Test Coverage Checklist

General plugin and schema:

- [ ] Endpoint registration includes webhook.
- [ ] Subscription endpoint registration is gated by `subscription.enabled`.
- [ ] User schema includes `stripeCustomerId`.
- [ ] Additional user schema fields merge with Stripe schema.
- [ ] Flexible `limits` types are accepted.

Metadata and utilities:

- [ ] Customer metadata internal fields are protected.
- [ ] Subscription metadata internal fields are protected.
- [ ] Metadata getters extract typed internal fields.
- [ ] Prototype pollution keys are dropped for customer metadata.
- [ ] Prototype pollution keys are dropped for subscription metadata.
- [ ] Internal metadata fields always override user metadata.
- [ ] Stripe search values escape double quotes.
- [ ] `resolvePlanItem` handles empty items.
- [ ] `resolvePlanItem` handles unmatched single item.
- [ ] `resolvePlanItem` handles unmatched multi-item.
- [ ] `resolvePlanItem` matches price id.
- [ ] `resolvePlanItem` matches lookup key.

User subscriptions:

- [ ] Create Stripe customer on signup.
- [ ] Create checkout subscription.
- [ ] Cross-user subscription id operations are rejected for upgrade, cancel, and restore.
- [ ] Upgrade passes metadata to Stripe subscription and checkout session.
- [ ] List active subscriptions.
- [ ] Annual billing returns annual discount price id.
- [ ] Webhook creates, updates, completes, and deletes subscriptions.
- [ ] Webhook handles trials.
- [ ] Duplicate subscription creation is skipped.
- [ ] Subscription creation is skipped when user/reference is missing.
- [ ] Subscription creation is skipped when plan is missing.
- [ ] Metadata subscription id prevents duplicate webhook creation.
- [ ] Subscription event callbacks execute.
- [ ] Update callback receives updated subscription.
- [ ] Schedule id is synced, cleared on removal, and cleared on deletion.
- [ ] Billing portal session is created.
- [ ] Billing portal works for existing custom reference id.
- [ ] Custom reference upgrade does not update personal subscription.
- [ ] Customer email syncs to Stripe on user email change.
- [ ] Customer create params merge with defaults.
- [ ] Custom customer address params are accepted.
- [ ] Nested customer create params merge deterministically.
- [ ] Signup works without customer create params.

Webhook error handling:

- [ ] Invalid webhook signature is rejected.
- [ ] Missing Stripe signature header is rejected.
- [ ] Missing request body is rejected.
- [ ] Missing webhook secret is rejected.
- [ ] Null/undefined constructed event is rejected.
- [ ] Async processing errors return webhook error.
- [ ] Valid async signature verification succeeds.
- [ ] `constructEventAsync` is called with exactly payload, signature, secret.
- [ ] Stripe v18 sync `constructEvent` is supported.

Duplicate customer prevention:

- [ ] Existing Stripe customer by email is linked on signup.
- [ ] New Stripe customer is created only when no local id and no Stripe customer exists.
- [ ] Organization customer with same email is not used for user customer lookup.
- [ ] Existing user customer is found even when an organization customer shares email.
- [ ] Organization customer is created with `customerType` metadata.
- [ ] Customer search fallback to `customers.list` works for signup.
- [ ] Customer search fallback to `customers.list` works for upgrade.

Cancellation and restore:

- [ ] Billing Portal cancel_at_period_end webhook syncs cancel fields.
- [ ] Scheduled cancel_at date webhook syncs cancel fields.
- [ ] Immediate deletion marks status canceled and ended date.
- [ ] Period-end deletion marks ended date.
- [ ] Cancel fallback syncs state when webhook was missed.
- [ ] Restore clears `cancelAtPeriodEnd`.
- [ ] Restore clears specific `cancelAt`.
- [ ] Restore releases pending schedule and clears local schedule id.
- [ ] Restore rejects when no pending cancel or scheduled change exists.

Reference authorization:

- [ ] User reference passes with no explicit reference id.
- [ ] User reference passes when reference id is current user id.
- [ ] User reference rejects custom reference without `authorizeReference`.
- [ ] User reference rejects when `authorizeReference` returns false.
- [ ] User reference allows when `authorizeReference` returns true.
- [ ] Organization reference rejects without `authorizeReference`.
- [ ] Organization reference rejects without reference id or active organization id.
- [ ] Organization reference rejects when `authorizeReference` returns false.
- [ ] Organization reference allows when `authorizeReference` returns true.

Scheduling and line items:

- [ ] Existing active subscription upgrades even when canceled subscription exists for same reference.
- [ ] Plan change can be scheduled at period end.
- [ ] Existing plugin schedule is released before new schedule.
- [ ] Existing plugin schedule is released before immediate upgrade.
- [ ] External schedules are not released.
- [ ] Immediate upgrade swaps line item prices.
- [ ] Scheduled upgrade swaps line item prices in next phase.
- [ ] Upgrade adds new line items when new plan has more items.
- [ ] Downgrade removes line items when new plan has fewer items.
- [ ] Immediate upgrade does not duplicate existing line items.
- [ ] Scheduled upgrade does not duplicate existing line items.
- [ ] `subscriptionSuccess` updates subscription via checkout session id and redirects.
- [ ] `subscriptionSuccess` redirects without update when checkout session id is missing.
- [ ] `subscriptionSuccess` replaces checkout session placeholder in callback URL.
- [ ] `subscriptionSuccess` redirects when checkout session retrieval fails.

Metered pricing:

- [ ] Metered base price omits quantity in checkout session.
- [ ] Licensed base price includes quantity in checkout session.
- [ ] Metered price omits quantity in Billing Portal upgrade.
- [ ] Metered price omits quantity in direct subscription upgrade.
- [ ] Metered price omits quantity in scheduled upgrade.

Organization subscriptions:

- [ ] Organization upgrade creates Stripe customer.
- [ ] Organization upgrade uses existing organization Stripe customer id.
- [ ] Organization customer creation calls custom params callback.
- [ ] Organization customer create params can supply billing/email/address data that defaults do not provide.
- [ ] Organization billing portal works.
- [ ] Organization cancel works.
- [ ] Organization restore works.
- [ ] Organization list works.
- [ ] Dashboard-created organization subscription webhook creates local subscription.
- [ ] Cross-organization operations are rejected.
- [ ] Organization subscription rejects when `authorizeReference` is not configured.
- [ ] User and organization subscriptions stay separate.
- [ ] Organization subscription update webhook updates local record.
- [ ] Organization subscription cancellation update webhook syncs cancellation.
- [ ] Organization subscription delete webhook marks canceled.
- [ ] Non-existent organization upgrade returns organization not found.
- [ ] Organization customer creation failure maps to customer creation error.
- [ ] Organization customer create params callback failure maps to customer creation error.
- [ ] Organization dashboard-created subscription calls `onSubscriptionCreated`.
- [ ] Organization lookup does not match user customer with organization metadata collision.
- [ ] Organization hook integration preserves existing hooks.
- [ ] Organization name syncs to Stripe on update.
- [ ] Organization deletion is blocked with active subscription.
- [ ] Organization deletion is allowed with no active subscription.

Seat-based billing:

- [ ] Checkout creates base and seat line items.
- [ ] Checkout uses actual member count as seat quantity.
- [ ] Seat pricing configuration logs an error when organization integration is disabled.
- [ ] Checkout includes additional line items.
- [ ] Checkout omits extra line items when plan has none.
- [ ] Checkout avoids duplicate base price when `priceId == seatPriceId`.
- [ ] Portal upgrade swaps seat item for different seat pricing.
- [ ] Portal upgrade uses custom `prorationBehavior`.
- [ ] Portal upgrade skips seat item swap when unchanged.
- [ ] Seat-only plan upgrades do not duplicate subscription item.
- [ ] Invitation acceptance syncs seat quantity.
- [ ] Member removal syncs seat quantity.
- [ ] Member removal uses custom `prorationBehavior`.
- [ ] Webhook creation persists seat count.
- [ ] Webhook update persists seat count.
