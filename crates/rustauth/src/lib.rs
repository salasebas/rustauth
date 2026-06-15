//! RustAuth authentication toolkit.

pub mod auth;
pub mod prelude;

pub use auth::{RustAuth, RustAuthBuilder};
#[cfg(feature = "oauth")]
pub use rustauth_core::oauth;
#[cfg(feature = "social-providers")]
pub use rustauth_core::social_providers;
pub use rustauth_core::{
    api, context, cookies, crypto, db, env, error, error_codes, options, plugin, rate_limit,
    session, user, utils, verification, RustAuthError, RustAuthOptions,
};

#[cfg(feature = "deadpool-postgres")]
pub use rustauth_deadpool_postgres as deadpool_postgres;
#[cfg(feature = "diesel")]
pub use rustauth_diesel as diesel;
#[cfg(feature = "fred")]
pub use rustauth_fred as fred;
#[cfg(feature = "i18n")]
pub use rustauth_i18n as i18n;
#[cfg(feature = "oauth-provider")]
pub use rustauth_oauth_provider as oauth_provider;
#[cfg(feature = "passkey")]
pub use rustauth_passkey as passkey;
#[cfg(feature = "plugins")]
pub use rustauth_plugins as plugins;
#[cfg(feature = "redis")]
pub use rustauth_redis as redis;
#[cfg(feature = "scim")]
pub use rustauth_scim as scim;
#[cfg(feature = "sqlx")]
pub use rustauth_sqlx as sqlx;
#[cfg(feature = "sso")]
pub use rustauth_sso as sso;
#[cfg(feature = "stripe")]
pub use rustauth_stripe as stripe;
#[cfg(feature = "telemetry")]
pub mod telemetry {
    pub use rustauth_telemetry::{
        create_telemetry, CustomTrackFn, TelemetryContext, TelemetryEvent, TelemetryHttpError,
        TelemetryHttpTransport, TelemetryPublisher,
    };
}
#[cfg(feature = "tokio-postgres")]
pub use rustauth_tokio_postgres as tokio_postgres;

/// Current crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
