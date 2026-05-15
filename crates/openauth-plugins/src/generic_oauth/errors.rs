use openauth_core::plugin::PluginErrorCode;

pub const INVALID_OAUTH_CONFIGURATION: &str = "INVALID_OAUTH_CONFIGURATION";
pub const TOKEN_URL_NOT_FOUND: &str = "TOKEN_URL_NOT_FOUND";
pub const PROVIDER_CONFIG_NOT_FOUND: &str = "PROVIDER_CONFIG_NOT_FOUND";
pub const PROVIDER_ID_REQUIRED: &str = "PROVIDER_ID_REQUIRED";
pub const INVALID_OAUTH_CONFIG: &str = "INVALID_OAUTH_CONFIG";
pub const SESSION_REQUIRED: &str = "SESSION_REQUIRED";
pub const ISSUER_MISMATCH: &str = "ISSUER_MISMATCH";
pub const ISSUER_MISSING: &str = "ISSUER_MISSING";

pub(crate) fn error_code(code: &str, message: &str) -> PluginErrorCode {
    PluginErrorCode::new(code, message)
}
