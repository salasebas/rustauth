#![allow(clippy::unwrap_used)]

#[path = "stripe_api/client.rs"]
mod client;
#[path = "stripe_api/form_encoding.rs"]
mod form_encoding;
#[path = "stripe_api/webhook_signature.rs"]
mod webhook_signature;
