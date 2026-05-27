#![allow(clippy::expect_used, clippy::unwrap_used)]

use openauth_scim::{ScimOptions, ScimTokenStorage};

/// Route and adapter tests that seed `scim_token` as a raw base token use plain storage.
pub(crate) fn scim_options_for_manual_provider_tokens() -> ScimOptions {
    ScimOptions {
        token_storage: ScimTokenStorage::Plain,
        ..ScimOptions::default()
    }
}

#[path = "scim/db_adapters.rs"]
mod db_adapters;
#[path = "scim/errors.rs"]
mod errors;
#[path = "scim/filters.rs"]
mod filters;
#[path = "scim/mappings.rs"]
mod mappings;
#[path = "scim/metadata.rs"]
mod metadata;
#[path = "scim/metadata_snapshot.rs"]
mod metadata_snapshot;
#[path = "scim/patch.rs"]
mod patch;
#[path = "scim/resources.rs"]
mod resources;
#[path = "scim/routes/mod.rs"]
mod routes;
#[path = "scim/schema.rs"]
mod schema;
#[path = "scim/store.rs"]
mod store;
#[path = "scim/token.rs"]
mod token;
#[path = "scim/validation.rs"]
mod validation;
