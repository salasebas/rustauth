use super::*;

#[path = "registration/basics.rs"]
mod basics;
#[cfg(feature = "oidc")]
#[path = "registration/discovery.rs"]
mod discovery;
#[path = "registration/limits.rs"]
mod limits;
#[path = "registration/persistence.rs"]
mod persistence;
#[cfg(feature = "saml")]
#[path = "registration/saml_metadata.rs"]
mod saml_metadata;
#[path = "registration/validation.rs"]
mod validation;
