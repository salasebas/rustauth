# Stripe — test parity

Upstream reference: `packages/stripe/test/*.ts` (Vitest).  
OpenAuth: `crates/openauth-stripe/tests/**/*.rs` (integration with `CaptureTransport`).

---

## 1. Counts

| Metric | Better Auth 1.6.9 | OpenAuth |
| --- | ---: | ---: |
| Test files | 5 | 36 modules under `tests/` (incl. `common/`) |
| `it()` / `#[test]` runtime cases | **150** | **174** |
| Type-only cases (`expectTypeOf`) | **12** | 0 |
| Tests in crate `src/` | 0 | 0 |
| Smoke example tests | 0 | 5 (`examples/stripe-smoke-server`, CLI/redaction) |
| Other workspace crates | — | 0 Stripe references outside `openauth-stripe` |

Upstream breakdown by file:

| File | `it()` |
| --- | ---: |
| `stripe.test.ts` | 101 |
| `stripe-organization.test.ts` | 22 |
| `seat-based-billing.test.ts` | 14 |
| `utils.test.ts` | 9 |
| `metadata.test.ts` | 4 |

OpenAuth groups by domain in subfolders (`routes/`, `webhooks/`, `stripe_api/`, …) instead of two large files.

---

## 2. What does not count as a “gap”

| Upstream | Reason |
| --- | --- |
| `describe("stripe type")` + `expectTypeOf` (4 tests, ~8 type assertions) | TypeScript inference of `auth.api.*`; in Rust the API is the crate + HTTP routes |
| Tests that only validate schema types on `auth.$Infer` | Replaced by `plugin_surface.rs` (schema/endpoint registration) |

---

## 3. Domain matrix

| Domain | Upstream (describe / file) | OpenAuth (main modules) | Coverage |
| --- | --- | --- | --- |
| Plugin registration / schema | `stripe` intro, types | `plugin_surface.rs` | **Covered** |
| Metadata helpers | `stripe - metadata helpers`, `metadata.test.ts` | `metadata.rs` | **Covered** |
| Utils (`escapeStripeSearchValue`, `resolvePlanItem`) | `utils.test.ts` | `utils.rs` | **Covered** |
| Upgrade / checkout | `stripe` user subs | `routes/upgrade.rs`, `routes.rs` | **Covered** |
| List + limits + annual price | list tests in `stripe.test.ts` | `routes/list_limits.rs`, `routes.rs` | **Covered** |
| Active upgrade / portal / schedule | line items, scheduling, metered | `routes/active_upgrade.rs` | **Covered** |
| Cancel / restore / portal errors | cancel/restore describes | `routes/manage.rs`, `cancel_already_canceled.rs` | **Covered** |
| `subscriptionSuccess` | dedicated describe | `routes.rs` (success tests) | **Covered** |
| Webhook lifecycle | webhooks in `stripe.test.ts` | `webhook_lifecycle.rs`, `webhook_hooks.rs` | **Covered** |
| Webhook signature/body errors | `Webhook Error Handling` | `routes.rs`, `stripe_api/webhook_signature.rs` | **Covered** |
| Webhook skip paths (created) | implicit upstream | `webhooks/skip_paths.rs` | **Covered** |
| Webhook idempotency | **Not in upstream** | `webhooks/idempotency.rs` | **Extension** |
| Checkout reference fallback | upstream | `webhooks/checkout_reference.rs` | **Covered** |
| Handler resilience (200) | partial | `webhooks/resilience.rs` | **Covered** |
| Duplicate / link customer signup | `Duplicate customer prevention` | `customers.rs` | **Covered** |
| User/org collision | `User/Organization customer collision` | `customers.rs` | **Covered** |
| Search → list fallback | `Search API fallback` | `customers.rs` (warn/log) | **Covered** |
| `getCustomerCreateParams` merge | dedicated describe | `customers.rs`, `routes/customer_metadata.rs` | **Covered** |
| Trial abuse | `trial abuse prevention` | `routes/trial_abuse.rs` | **Covered** |
| Reference middleware user/org | `referenceMiddleware` | `routes/reference.rs`, `upgrade.rs` | **Covered** |
| Cross-user subscription id | implicit | `routes/cross_user.rs` | **Covered** |
| Metered quantity | `metered usage pricing` | `routes/upgrade.rs`, `active_upgrade.rs` | **Covered** |
| Line items add/remove/dedup | 3 describes | `active_upgrade.rs` | **Covered** |
| Organization customer + subs | `stripe-organization.test.ts` | `organization.rs`, `customers.rs`, `manage.rs` | **Covered** |
| Organization hooks chain | `organizationHooks integration` | `organization.rs` | **Covered** |
| Seat billing checkout/portal | `seat-based-billing.test.ts` | `upgrade.rs`, `active_upgrade.rs`, `organization.rs` | **Covered** |
| Seat webhook + member sync | seat describes | `organization.rs`, `webhook_lifecycle.rs` | **Covered** |
| Reuse incomplete subscription | upstream | `routes/reuse_incomplete.rs` | **Covered** |
| Upgrade errors (plan, body) | scattered | `routes/upgrade_errors.rs`, `upgrade_lookup.rs` | **Covered** |
| Stripe API client / form | N/A (mocked in BA) | `stripe_api/client.rs`, `form_encoding.rs` | **Rust-specific** |
| Error mapping Stripe→plugin | partial in BA | `errors/stripe_api_mapping.rs` | **Covered** |
| Zero-day trial config | not explicit | `routes/upgrade_trial_validation.rs` | **Extension** |

---

## 4. OpenAuth tests without a direct upstream equivalent

| Test / area | Reason |
| --- | --- |
| `webhooks/idempotency.rs` | **Extension** (`stripeWebhookEvent`) |
| `stripe_api/form_encoding.rs` | Rust client Stripe form encoding |
| `stripe_api/client.rs` | `StripeTransport` / reqwest contract |
| `plugin_surface.rs` | Static endpoint/schema registration (replaces TS type tests) |
| `routes/upgrade_trial_validation.rs` | Trial configuration validation |
| `examples/stripe-smoke-server` (5 tests) | CLI / smoke secret redaction |

---

## 5. How to run

```bash
# Stripe crate (recommended local loop in AGENTS.md)
cargo nextest run -p openauth-stripe

# Format + clippy for the crate
cargo fmt --all --check
cargo clippy -p openauth-stripe --all-targets -- -D warnings
```

Manual smoke against Stripe test mode: `scripts/stripe-smoke.sh` and `crates/openauth-stripe/SMOKE.md`.

---

## 6. Gap status (deep review 2026-06-01, closed 2026-06-01)

### Tests

| ID | Status |
| --- | --- |
| T1 | **Closed** — `customers::signup_and_upgrade_call_customers_create_only_once` |
| T2 | 7 upstream N/A tests (TS types + Stripe SDK v18/v19) — no equivalent (correct) |
| T3 | ~24 **Extension** Rust tests (idempotency, form encoding, limits webhook, G6/G7, …) |

**Coverage:** all 150 upstream tests have **Covered**, intentional **N/A**, or documented **Extension**. Detail: [upstream-test-catalog.md](./upstream-test-catalog.md).

### Runtime

| ID | Status |
| --- | --- |
| G1–G2, G4, G6–G7, G11, T1 | **Closed** in crate + tests |
| G3 | **Extension** (`FAILED_TO_FETCH_PLANS`) |
| G5 | **Design** (DB hooks vs `organizationHooks`) |
| G8–G10, G12 | **Parity or OpenAuth improvement** documented |

**Second pass (2026-06-02):** G1–G12 inventory. **Closure (2026-06-01):** no known open runtime gaps for 1.6.9.

Per `ROADMAP.md`, planned **P0–P3** items are closed. **Product** remaining: example UI, exit beta.

---

## 7. Convention for future iterations

When Better Auth adds an upstream test:

1. Locate the `describe` in `packages/stripe/test/`.
2. Add or extend the Rust module in the matching row of the §3 matrix.
3. Update counts in §1 of this file.

Row template:

```markdown
| <behavior> | `<upstream describe>` | `tests/<module>.rs` | Covered / Gap / Extension |
```
