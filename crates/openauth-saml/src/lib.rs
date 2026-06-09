//! SAML 2.0 service-provider support for OpenAuth enterprise SSO.
//!
//! Signed and encrypted SAML paths use [`opensaml`] when the `saml-signed`
//! feature is enabled; otherwise they fail closed with stable error codes.

pub mod options;

mod bridge;

#[path = "saml/mod.rs"]
mod saml_impl;

pub mod metadata {
    pub use crate::saml_impl::metadata::*;
}

#[cfg(any(feature = "sso-internal", feature = "test-util"))]
pub mod assertions {
    pub use crate::saml_impl::assertions::*;
}

#[cfg(any(feature = "sso-internal", feature = "test-util"))]
pub mod authn_request {
    pub use crate::saml_impl::authn_request::*;
}

#[cfg(feature = "test-util")]
pub mod encryption {
    pub use crate::saml_impl::encryption::*;
}

#[cfg(any(feature = "sso-internal", feature = "test-util"))]
pub mod logout {
    pub use crate::saml_impl::logout::*;
}

#[cfg(any(feature = "sso-internal", feature = "test-util"))]
pub mod security {
    pub use crate::saml_impl::security::*;
}

#[cfg(any(feature = "sso-internal", feature = "test-util"))]
pub mod signature {
    pub use crate::saml_impl::signature::*;
}

#[cfg(any(feature = "sso-internal", feature = "test-util"))]
pub mod state {
    pub use crate::saml_impl::state::*;
}

#[cfg(feature = "test-util")]
pub mod xml {
    pub use crate::saml_impl::xml::*;
}

pub use crate::bridge::SpBuildOptions;
pub use options::{
    SamlConfig, SamlIdpMetadata, SamlMapping, SamlProviderConfig, SamlService, SamlSpMetadata,
};
pub use saml_impl::{
    collect_saml_runtime_algorithms, validate_saml_config_algorithms,
    validate_saml_config_algorithms_with_policy, validate_saml_runtime_algorithms,
    validate_saml_timestamp, validate_saml_timestamp_at, DataEncryptionAlgorithm,
    DeprecatedAlgorithmBehavior, DigestAlgorithm, KeyEncryptionAlgorithm, SamlConditions,
    SamlRuntimeAlgorithmPolicy, SamlRuntimeAlgorithms, SamlSecurityError, SignatureAlgorithm,
    TimestampValidationOptions,
};

/// Public signature policy placeholder for future backend selection.
pub type SamlSignaturePolicy<'a> = SamlRuntimeAlgorithmPolicy<'a>;
/// Public parsed assertion type.
pub type SamlAssertion = saml_impl::assertions::ParsedSamlAssertion;
/// Public logout state identifier type.
pub type SamlLogoutState = String;
/// Public SAML error type for security validation failures.
pub type SamlError = SamlSecurityError;

/// Current crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
