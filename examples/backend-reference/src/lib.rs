//! Backend-only reference application for RustAuth-RS.
//!
//! # Layout
//!
//! - [`config`] — environment-driven runtime settings
//! - [`auth`] — RustAuth options, plugins, schema, and [`AuthStack`] factory
//! - [`database`] — Deadpool Postgres adapter
//! - [`server`] — Axum router (auth API + introspection)
//! - [`catalog`] — endpoint grouping for navigation
//! - [`client`] — request builders and example flows
//!
//! # Quick start
//!
//! ```no_run
//! use rustauth_example_backend_reference::auth::AuthStack;
//! use rustauth_example_backend_reference::config::AppConfig;
//! use rustauth_example_backend_reference::server::build_router;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let stack = AuthStack::from_config(AppConfig::from_env()?).await?;
//!     let app = build_router(stack)?;
//!     // axum::serve(...)
//!     Ok(())
//! }
//! ```

pub mod auth;
pub mod catalog;
pub mod client;
pub mod config;
pub mod database;
pub mod error;
pub mod server;

pub use auth::AuthStack;
pub use config::AppConfig;
pub use error::{AppError, AppResult};
pub use server::build_router;
