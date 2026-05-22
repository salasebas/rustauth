//! SCIM support for OpenAuth.

mod options;
mod routes;
mod schema;

pub mod errors;
pub mod filters;
pub mod mappings;
pub mod metadata;
pub mod patch;
pub mod resources;
pub mod store;
pub mod token;

pub use options::{
    AfterScimTokenGeneratedHook, AfterScimTokenGeneratedInput, BeforeScimTokenGeneratedHook,
    BeforeScimTokenGeneratedInput, DefaultScimProvider, ProviderOwnershipOptions, ScimHookError,
    ScimHookFuture, ScimOptions, ScimOrganizationMember, ScimTokenStorage, ScimTokenStorageFuture,
    ScimTokenTransform,
};

use openauth_core::plugin::AuthPlugin;

/// Better Auth upstream plugin identifier used for endpoint and schema parity.
pub const UPSTREAM_PLUGIN_ID: &str = "scim";

/// Current crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Build the server-side SCIM plugin.
pub fn scim(options: ScimOptions) -> AuthPlugin {
    let mut plugin = AuthPlugin::new(UPSTREAM_PLUGIN_ID).with_version(VERSION);

    for contribution in schema::contributions() {
        plugin = plugin.with_schema(contribution);
    }
    for endpoint in routes::endpoints(options) {
        plugin = plugin.with_endpoint(endpoint);
    }

    plugin
}
