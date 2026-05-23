#![cfg(any(feature = "oidc", feature = "saml"))]

#[path = "sso/docs.rs"]
mod docs;
#[path = "sso/endpoints.rs"]
mod endpoints;
#[path = "sso/errors.rs"]
mod errors;
#[path = "sso/linking.rs"]
mod linking;
#[cfg(feature = "oidc")]
#[path = "sso/oidc.rs"]
mod oidc;
#[path = "sso/openapi.rs"]
mod openapi;
#[path = "sso/schema.rs"]
mod schema;
#[cfg(feature = "saml")]
#[path = "sso/security.rs"]
mod security;
#[path = "sso/store.rs"]
mod store;
#[path = "sso/support.rs"]
mod support;
