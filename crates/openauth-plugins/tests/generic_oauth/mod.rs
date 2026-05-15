#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "plugin tests intentionally fail fast with contextual setup errors"
)]

mod common;
mod helpers;
mod plugin;
mod provider;
mod routes;
