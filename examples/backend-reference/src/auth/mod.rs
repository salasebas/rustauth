//! Authentication domain: options, plugins, schema, and [`AuthStack`] factory.

pub mod access;
pub mod factory;
pub mod options;
pub mod plugins;
pub mod schema;
pub mod social_providers;

pub use factory::AuthStack;
pub use options::{build_rustauth_options, enabled_plugin_ids};
pub use social_providers::SOCIAL_SETUP_PATTERNS;
