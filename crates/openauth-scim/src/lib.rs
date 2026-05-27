//! Server-side SCIM 2.0 provisioning for OpenAuth.
//!
//! # Provider connections
//!
//! Each row in `scim_providers` is keyed by a globally unique `provider_id`
//! (Better Auth uses the same model). That id names one SCIM integration — for
//! example a single Okta enterprise app — not a tenant or organization by itself.
//! Optional `organization_id` on the row and in the bearer token limits which users
//! may be provisioned.
//!
//! If you need two independent tokens for the same vendor, use two provider ids
//! (`okta-workforce`, `okta-partners`). Regenerating a token updates the existing
//! row via upsert instead of deleting it first.
//!
//! # List filters
//!
//! - Database pushdown: `userName eq "user@example.com"` ([`filters::list_user_filter_uses_database_pushdown`]).
//! - In-memory evaluation: any other expression accepted by [`filters::parse_filter`],
//!   including extension attributes stored in SCIM user profiles.
//!
//! See the crate README for route coverage and parity notes versus Better Auth.

mod audit;
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
pub mod validation;

pub use audit::ScimAuditEventResolver;
pub use options::{
    AfterScimTokenGeneratedHook, AfterScimTokenGeneratedInput, BeforeScimTokenGeneratedHook,
    BeforeScimTokenGeneratedInput, DefaultScimProvider, ProviderOwnershipOptions, ScimAuditEvent,
    ScimAuditEventKind, ScimAuditSeverity, ScimBulkMode, ScimDeprovisionMode, ScimHookError,
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
