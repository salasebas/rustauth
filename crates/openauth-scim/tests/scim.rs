#![allow(clippy::expect_used, clippy::unwrap_used)]

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
#[path = "scim/patch.rs"]
mod patch;
#[path = "scim/resources.rs"]
mod resources;
#[path = "scim/routes.rs"]
mod routes;
#[path = "scim/schema.rs"]
mod schema;
#[path = "scim/store.rs"]
mod store;
#[path = "scim/token.rs"]
mod token;
