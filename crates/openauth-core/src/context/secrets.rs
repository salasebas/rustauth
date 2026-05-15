use std::fmt;

use crate::crypto::{JweSecretSource, SecretConfig, SecretSource};
use crate::error::OpenAuthError;
use crate::options::OpenAuthOptions;

use super::AuthEnvironment;

pub(super) const DEFAULT_SECRET: &str = "better-auth-secret-12345678901234567890";

#[derive(Clone, PartialEq, Eq)]
pub enum SecretMaterial {
    Single(String),
    Rotating(SecretConfig),
}

impl fmt::Debug for SecretMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Single(_) => formatter
                .debug_tuple("Single")
                .field(&"<redacted>")
                .finish(),
            Self::Rotating(config) => formatter.debug_tuple("Rotating").field(config).finish(),
        }
    }
}

impl JweSecretSource for SecretMaterial {
    fn current_jwe_secret(&self) -> Result<String, OpenAuthError> {
        match self {
            Self::Single(secret) => secret.current_jwe_secret(),
            Self::Rotating(config) => config.current_jwe_secret(),
        }
    }

    fn all_jwe_secrets(&self) -> Result<Vec<crate::crypto::jwe::JweSecret>, OpenAuthError> {
        match self {
            Self::Single(secret) => secret.all_jwe_secrets(),
            Self::Rotating(config) => config.all_jwe_secrets(),
        }
    }
}

impl SecretSource for &SecretMaterial {
    fn encrypt_current(&self, data: &str) -> Result<String, OpenAuthError> {
        match self {
            SecretMaterial::Single(secret) => secret.encrypt_current(data),
            SecretMaterial::Rotating(config) => config.encrypt_current(data),
        }
    }

    fn decrypt_payload(&self, data: &str) -> Result<String, OpenAuthError> {
        match self {
            SecretMaterial::Single(secret) => secret.decrypt_payload(data),
            SecretMaterial::Rotating(config) => config.decrypt_payload(data),
        }
    }
}

pub(super) fn resolve_legacy_secret(
    options: &OpenAuthOptions,
    environment: &AuthEnvironment,
) -> Option<String> {
    options
        .secret
        .clone()
        .or_else(|| environment.better_auth_secret.clone())
        .or_else(|| environment.auth_secret.clone())
}

pub(super) fn validate_secret(secret: &str, production: bool) -> Result<(), OpenAuthError> {
    if secret.is_empty() {
        return Err(OpenAuthError::InvalidConfig(
            "OpenAuth secret is missing".to_owned(),
        ));
    }
    if production && secret == DEFAULT_SECRET {
        return Err(OpenAuthError::InvalidConfig(
            "default secret cannot be used in production".to_owned(),
        ));
    }
    Ok(())
}
