#![allow(clippy::unwrap_used)]

#[path = "common/mod.rs"]
mod common;

#[path = "webhooks/checkout_reference.rs"]
mod checkout_reference;
#[path = "webhooks/idempotency.rs"]
mod idempotency;
#[path = "webhooks/resilience.rs"]
mod resilience;
#[path = "webhooks/skip_paths.rs"]
mod skip_paths;
