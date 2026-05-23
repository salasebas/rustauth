//! SAML 2.0 service-provider support for OpenAuth enterprise SSO.
//!
//! Signed and encrypted SAML paths fail closed until a dedicated verification
//! backend is enabled behind an explicit feature.

pub mod options;

#[path = "saml/mod.rs"]
mod saml_impl;

pub mod assertions {
    pub use crate::saml_impl::assertions::*;
}

pub mod authn_request {
    pub use crate::saml_impl::authn_request::*;
}

pub mod encryption {
    pub use crate::saml_impl::encryption::*;
}

pub mod logout {
    pub use crate::saml_impl::logout::*;
}

pub mod metadata {
    pub use crate::saml_impl::metadata::*;
}

pub mod security {
    pub use crate::saml_impl::security::*;
}

pub mod signature {
    pub use crate::saml_impl::signature::*;
}

pub mod state {
    pub use crate::saml_impl::state::*;
}

pub mod xml {
    pub use crate::saml_impl::xml::*;
}

pub use options::{
    SamlConfig, SamlIdpMetadata, SamlMapping, SamlProviderConfig, SamlService, SamlSpMetadata,
};
pub use saml_impl::{
    collect_saml_runtime_algorithms, validate_saml_config_algorithms,
    validate_saml_config_algorithms_with_policy, validate_saml_runtime_algorithms,
    validate_saml_timestamp, DataEncryptionAlgorithm, DeprecatedAlgorithmBehavior, DigestAlgorithm,
    KeyEncryptionAlgorithm, SamlConditions, SamlRuntimeAlgorithmPolicy, SamlRuntimeAlgorithms,
    SamlSecurityError, SignatureAlgorithm, TimestampValidationOptions,
};

/// Public signature policy placeholder for future backend selection.
pub type SamlSignaturePolicy<'a> = SamlRuntimeAlgorithmPolicy<'a>;
/// Public parsed assertion type.
pub type SamlAssertion = assertions::ParsedSamlAssertion;
/// Public logout state identifier type.
pub type SamlLogoutState = String;
/// Public SAML error type for security validation failures.
pub type SamlError = SamlSecurityError;

/// Current crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
