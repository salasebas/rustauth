use super::*;

#[cfg(feature = "oidc")]
#[path = "sign_in/defaults_discovery.rs"]
mod defaults_discovery;
#[cfg(all(feature = "oidc", feature = "saml"))]
#[path = "sign_in/dual_signed.rs"]
mod dual_signed;
#[cfg(feature = "oidc")]
#[path = "sign_in/oidc_basic.rs"]
mod oidc_basic;
#[cfg(feature = "oidc")]
#[path = "sign_in/redirect_validation.rs"]
mod redirect_validation;
#[cfg(feature = "saml")]
#[path = "sign_in/saml.rs"]
mod saml;
