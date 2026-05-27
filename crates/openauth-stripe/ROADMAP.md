# openauth-stripe — roadmap y gaps

Referencia: Better Auth Stripe **1.6.9**. Ver también [UPSTREAM.md](./UPSTREAM.md).

Este archivo guarda el análisis de paridad, tests pendientes y producción. Actualizar al cerrar ítems.

---

## Sobre `groupId` e idempotencia (FAQ)

| Tema | ¿En upstream 1.6.9? | Por qué aparece en análisis |
|------|---------------------|-----------------------------|
| **`groupId`** | Solo en **tipos TS** (`types.ts`); **no** en schema, rutas ni tests | Documentación/API futura o extensión de tipos; **no** hay implementación ni promesa de versión en el código |
| **`group` en plan** | Solo tipo; list no lo expone | Nosotros lo exponemos en GET list (extensión documentada) |
| **Idempotencia `event.id`** | **No implementada** | Riesgo general de webhooks Stripe (reintentos); no es deuda de paridad con BA 1.6.9 |

**No implementar** `groupId` ni idempotencia salvo requisito propio explícito.

---

## Leyenda

- `[x]` hecho
- `[~]` en progreso / parcial
- `[ ]` pendiente
- `[-]` no hacer (upstream tampoco / deprecado / fuera de alcance)

---

## A. Lógica — prioridad

### A1. Crítico

| Estado | ID | Item |
|--------|-----|------|
| [x] | A1.1 | Reconciliar Stripe ↔ DB antes de `active_upgrade` (list subs, link `stripe_subscription_id`) |
| [x] | A1.2 | Reutilizar fila `incomplete` en upgrade (no crear duplicados) |
| [x] | A1.3 | Duplicate same plan+seats rejection (upstream `isAlreadySubscribed` con price id Stripe) |

### A2. Medio

| Estado | ID | Item |
|--------|-----|------|
| [x] | A2.1 | `/subscription/success`: incluir `trialing` al listar Stripe |
| [x] | A2.2 | `/subscription/success`: periodos desde `resolve_plan_item`, no `items[0]` |
| [x] | A2.3 | `/subscription/success`: verificar metadata `referenceId` vs fila local (metadata server-side) |
| [x] | A2.4 | Org delete: bloquear subs no terminales (`past_due`, `unpaid`, …) en DB |
| [x] | A2.5 | Seat sync: skip si sub Stripe no active/trialing |
| [x] | A2.6 | Validación init: `seat_price_id` sin org enabled → warn |
| [x] | A2.7 | Customer search fallback → log warn |
| [x] | A2.8 | Metadata en lazy customer create (upgrade) |
| [x] | A2.9 | Portal upgrade quantity org seats (omitir quantity si `seat_price_id`) |
| [x] | A2.10 | Errores HTTP: rutas cliente devuelven `error_response` en fallos de parseo Stripe |
| [x] | A2.11 | `originalMessage` en JSON de error Stripe |
| [x] | A2.12 | Timeouts reqwest en `StripeClient` (30s default) |
| [x] | A2.13 | Warn en build si `stripe_webhook_secret` vacío |

### A3. Hecho / no hacer

| Estado | ID | Item |
|--------|-----|------|
| [x] | — | `whsec_`, errores HTTP rutas principales, cancel already-canceled, checkout reference |
| [x] | — | Logging hooks/webhooks, `UPSTREAM.md`, tests modulares (159) |
| [-] | — | `groupId`, idempotencia webhook, alias deprecado `SUBSCRIPTION_NOT_SCHEDULED_FOR_CANCELLATION` |

---

## B. Tests pendientes

### B1. P0 — seguridad

| Estado | Test |
|--------|------|
| [x] | `webhook_rejects_missing_stripe_signature_header` |
| [x] | `reference_user_*` (5 casos) — ver `tests/routes/reference.rs` + `upgrade.rs` |
| [x] | `reference_org_*` (2 casos) — ver `tests/routes/reference.rs` + `upgrade.rs` |
| [x] | `cross_user_cancel/restore_*` — ver `tests/routes/cross_user.rs` |

### B2. P1 — webhooks

| Estado | Test |
|--------|------|
| [x] | checkout retrieve fail → 200 |
| [x] | subscription.created skip paths (3) |
| [x] | cancellation sync (`cancel_at`, `ended_at`) — cubierto en `webhook_lifecycle.rs` |
| [x] | seats on webhook create/update — cubierto en `webhook_lifecycle.rs` / org created |

### B3. P2 — billing

| Estado | Test |
|--------|------|
| [x] | trial abuse (2) — `tests/routes/trial_abuse.rs` |
| [x] | duplicate same plan+seats — `subscription_upgrade_rejects_same_active_plan_and_interval` |
| [x] | restore clears `cancel_at` — `restore_subscription_clears_cancel_at_timestamp` |
| [x] | active upgrade schedule release — `subscription_upgrade_releases_existing_plugin_schedule_before_immediate_change` |

---

## C. Producción / docs

| Estado | Item |
|--------|------|
| [x] | README: eventos webhook, `authorizeReference`, runbook hooks |
| [x] | Hook logger → app logger (`PluginDatabaseHookContext::logger`) |
| [x] | Smoke test-mode servidor: [SMOKE.md](./SMOKE.md), [.env.smoke.example](./.env.smoke.example), [scripts/stripe-smoke.sh](../../scripts/stripe-smoke.sh) |
| [ ] | Example app con Stripe UI (fuera del smoke actual) |
| [ ] | Quitar beta / 1.0 cuando A1 + P0 tests verdes |

---

## D. Orden de sprints

1. **Sprint cerrado:** A1 + A2 + B1–B3 tests, 159 tests verdes
2. **Pendiente release:** quitar beta / criterios 1.0
