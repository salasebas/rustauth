use openauth_core::plugin::PluginErrorCode;

/// Provider lookup failed.
pub const PROVIDER_NOT_FOUND: &str = "PROVIDER_NOT_FOUND";
/// Provider registration conflicts with an existing provider id.
pub const PROVIDER_EXISTS: &str = "PROVIDER_EXISTS";
/// Domain verification was requested for an already verified provider.
pub const DOMAIN_VERIFIED: &str = "DOMAIN_VERIFIED";
/// Domain verification was attempted without a pending token.
pub const NO_PENDING_VERIFICATION: &str = "NO_PENDING_VERIFICATION";
/// SAML response parsing or validation failed.
pub const SAML_INVALID_RESPONSE: &str = "SAML_INVALID_RESPONSE";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// High-level category for stable public SSO error codes.
pub enum SsoErrorCategory {
    /// Invalid server or provider configuration.
    Configuration,
    /// Invalid user-controlled input.
    UserInput,
    /// Authenticated user is not authorized for the requested action.
    Authorization,
    /// Requested resource does not exist.
    NotFound,
    /// Identity provider runtime failure.
    IdentityProviderRuntime,
    /// Rejected input that may indicate an attack.
    SuspectedAttack,
    /// Feature or protocol behavior is intentionally unsupported.
    Unsupported,
    /// Unexpected internal failure.
    Unexpected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Descriptor for a stable SSO error code registered by the plugin.
pub struct SsoErrorDescriptor {
    /// Stable public error code.
    pub code: &'static str,
    /// Human-readable default message.
    pub message: &'static str,
    /// Error category for logging and metrics.
    pub category: SsoErrorCategory,
}

const ERROR_DESCRIPTORS: &[SsoErrorDescriptor] = &[
    descriptor(
        PROVIDER_NOT_FOUND,
        "SSO provider not found",
        SsoErrorCategory::NotFound,
    ),
    descriptor(
        "SAML_PROVIDER_NOT_FOUND",
        "SAML provider not found",
        SsoErrorCategory::NotFound,
    ),
    descriptor(
        PROVIDER_EXISTS,
        "SSO provider already exists",
        SsoErrorCategory::UserInput,
    ),
    descriptor(
        DOMAIN_VERIFIED,
        "Domain has already been verified",
        SsoErrorCategory::UserInput,
    ),
    descriptor(
        NO_PENDING_VERIFICATION,
        "No pending domain verification exists",
        SsoErrorCategory::UserInput,
    ),
    descriptor(
        "INVALID_ISSUER",
        "Invalid issuer",
        SsoErrorCategory::UserInput,
    ),
    descriptor(
        "INVALID_DOMAIN",
        "Invalid domain",
        SsoErrorCategory::UserInput,
    ),
    descriptor(
        "INVALID_CALLBACK_URL",
        "Invalid callback URL",
        SsoErrorCategory::UserInput,
    ),
    descriptor(
        "INVALID_ERROR_CALLBACK_URL",
        "Invalid error callback URL",
        SsoErrorCategory::UserInput,
    ),
    descriptor(
        "INVALID_NEW_USER_CALLBACK_URL",
        "Invalid new-user callback URL",
        SsoErrorCategory::UserInput,
    ),
    descriptor(
        "DOMAIN_NOT_VERIFIED",
        "Provider domain has not been verified",
        SsoErrorCategory::Authorization,
    ),
    descriptor(
        "INVALID_ORIGIN",
        "Invalid request origin",
        SsoErrorCategory::Authorization,
    ),
    descriptor(
        "OIDC_PROVIDER_NOT_CONFIGURED",
        "OIDC provider is not configured",
        SsoErrorCategory::Configuration,
    ),
    descriptor(
        "OIDC_CONFIG_NOT_CONFIGURED",
        "OIDC config is not configured",
        SsoErrorCategory::Configuration,
    ),
    descriptor(
        "INVALID_OIDC_CONFIG",
        "Invalid OIDC configuration",
        SsoErrorCategory::Configuration,
    ),
    descriptor(
        "SAML_PROVIDER_NOT_CONFIGURED",
        "SAML provider is not configured",
        SsoErrorCategory::Configuration,
    ),
    descriptor(
        "SAML_CONFIG_NOT_CONFIGURED",
        "SAML config is not configured",
        SsoErrorCategory::Configuration,
    ),
    descriptor(
        "INVALID_SAML_CONFIG",
        "Invalid SAML configuration",
        SsoErrorCategory::Configuration,
    ),
    descriptor(
        "SAML_METADATA_TOO_LARGE",
        "SAML metadata is too large",
        SsoErrorCategory::Configuration,
    ),
    descriptor(
        "SAML_UNKNOWN_ALGORITHM",
        "Unknown SAML algorithm",
        SsoErrorCategory::Configuration,
    ),
    descriptor(
        "SAML_DEPRECATED_CONFIG_ALGORITHM",
        "Deprecated SAML configuration algorithm",
        SsoErrorCategory::Configuration,
    ),
    descriptor(
        "SAML_ALGORITHM_NOT_ALLOWED",
        "SAML algorithm is not allowed",
        SsoErrorCategory::Configuration,
    ),
    descriptor(
        "SAML_AUTHN_REQUEST_PRIVATE_KEY_REQUIRED",
        "SAML AuthnRequest signing private key is required",
        SsoErrorCategory::Configuration,
    ),
    descriptor(
        "MISSING_SAML_RESPONSE",
        "Missing SAML response",
        SsoErrorCategory::IdentityProviderRuntime,
    ),
    descriptor(
        "SAML_RESPONSE_TOO_LARGE",
        "SAML response is too large",
        SsoErrorCategory::IdentityProviderRuntime,
    ),
    descriptor(
        "SAML_RESPONSE_NOT_SUCCESS",
        "SAML response was not successful",
        SsoErrorCategory::IdentityProviderRuntime,
    ),
    descriptor(
        "SAML_SIGN_IN_FAILED",
        "SAML sign-in failed",
        SsoErrorCategory::IdentityProviderRuntime,
    ),
    descriptor(
        "UNABLE_TO_EXTRACT_SAML_USER",
        "Unable to extract SAML user",
        SsoErrorCategory::IdentityProviderRuntime,
    ),
    descriptor(
        "SAML_SESSION_NOT_FOUND",
        "SAML session was not found",
        SsoErrorCategory::IdentityProviderRuntime,
    ),
    descriptor(
        SAML_INVALID_RESPONSE,
        "Invalid SAML response",
        SsoErrorCategory::SuspectedAttack,
    ),
    descriptor(
        "INVALID_SAML_RESPONSE",
        "Invalid SAML response",
        SsoErrorCategory::SuspectedAttack,
    ),
    descriptor(
        "REPLAYED_SAML_ASSERTION",
        "Replayed SAML assertion",
        SsoErrorCategory::SuspectedAttack,
    ),
    descriptor(
        "SAML_SIGNATURE_INVALID",
        "Invalid SAML signature",
        SsoErrorCategory::SuspectedAttack,
    ),
    descriptor(
        "SAML_ASSERTION_SIGNATURE_REQUIRED",
        "SAML assertion signature is required",
        SsoErrorCategory::SuspectedAttack,
    ),
    descriptor(
        "SAML_LOGOUT_REQUEST_SIGNATURE_REQUIRED",
        "SAML LogoutRequest signature is required",
        SsoErrorCategory::SuspectedAttack,
    ),
    descriptor(
        "SAML_LOGOUT_RESPONSE_SIGNATURE_REQUIRED",
        "SAML LogoutResponse signature is required",
        SsoErrorCategory::SuspectedAttack,
    ),
    descriptor(
        "SAML_DEPRECATED_RUNTIME_ALGORITHM",
        "Deprecated SAML runtime algorithm",
        SsoErrorCategory::SuspectedAttack,
    ),
    descriptor(
        "SAML_DESTINATION_MISMATCH",
        "SAML destination mismatch",
        SsoErrorCategory::SuspectedAttack,
    ),
    descriptor(
        "SAML_ISSUER_MISMATCH",
        "SAML issuer mismatch",
        SsoErrorCategory::SuspectedAttack,
    ),
    descriptor(
        "SAML_IN_RESPONSE_TO_MISMATCH",
        "SAML InResponseTo mismatch",
        SsoErrorCategory::SuspectedAttack,
    ),
    descriptor(
        "SAML_TIMESTAMP_INVALID",
        "SAML timestamp is invalid",
        SsoErrorCategory::SuspectedAttack,
    ),
    descriptor(
        "SAML_RECIPIENT_MISMATCH",
        "SAML recipient mismatch",
        SsoErrorCategory::SuspectedAttack,
    ),
    descriptor(
        "INVALID_EMAIL_DOMAIN",
        "Invalid SSO email domain",
        SsoErrorCategory::SuspectedAttack,
    ),
    descriptor(
        "SAML_SIGNATURE_VALIDATION_NOT_IMPLEMENTED",
        "SAML signature validation is not enabled",
        SsoErrorCategory::Unsupported,
    ),
    descriptor(
        "ENCRYPTED_SAML_ASSERTION_UNSUPPORTED",
        "Encrypted SAML assertion is not supported",
        SsoErrorCategory::Unsupported,
    ),
    descriptor(
        "SAML_AUTHN_REQUEST_SIGNING_NOT_SUPPORTED",
        "SAML AuthnRequest signing is not enabled",
        SsoErrorCategory::Unsupported,
    ),
    descriptor(
        "SAML_AUTHN_REQUEST_SIGNING_FAILED",
        "SAML AuthnRequest signing failed",
        SsoErrorCategory::Unexpected,
    ),
];

const fn descriptor(
    code: &'static str,
    message: &'static str,
    category: SsoErrorCategory,
) -> SsoErrorDescriptor {
    SsoErrorDescriptor {
        code,
        message,
        category,
    }
}

pub fn plugin_error_codes() -> Vec<PluginErrorCode> {
    sso_error_descriptors()
        .iter()
        .map(|descriptor| PluginErrorCode::new(descriptor.code, descriptor.message))
        .collect()
}

/// Return all SSO error descriptors known by the plugin.
pub fn sso_error_descriptors() -> &'static [SsoErrorDescriptor] {
    ERROR_DESCRIPTORS
}

/// Look up the high-level category for a stable SSO error code.
pub fn sso_error_category(code: &str) -> SsoErrorCategory {
    sso_error_descriptors()
        .iter()
        .find(|descriptor| descriptor.code == code)
        .map(|descriptor| descriptor.category)
        .unwrap_or(SsoErrorCategory::Unexpected)
}
