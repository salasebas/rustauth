use rustauth_core::context::{AuthContext, SecretMaterial};
use rustauth_core::crypto::{symmetric_decrypt, symmetric_encrypt};
use rustauth_core::error::RustAuthError;

use super::Jwk;

pub(crate) fn encrypt_private_key(
    context: &AuthContext,
    mut key: Jwk,
    disabled: bool,
) -> Result<Jwk, RustAuthError> {
    if !disabled {
        key.private_key = encrypt_with_context(context, &key.private_key)?;
    }
    Ok(key)
}

pub(crate) fn decrypt_private_key(
    context: &AuthContext,
    private_key: &str,
    disabled: bool,
) -> Result<String, RustAuthError> {
    if disabled {
        return Ok(private_key.to_owned());
    }
    decrypt_with_context(context, private_key)
}

fn encrypt_with_context(context: &AuthContext, data: &str) -> Result<String, RustAuthError> {
    match &context.secret_config {
        SecretMaterial::Single(secret) => symmetric_encrypt(secret.as_str(), data),
        SecretMaterial::Rotating(config) => symmetric_encrypt(config, data),
    }
}

fn decrypt_with_context(context: &AuthContext, data: &str) -> Result<String, RustAuthError> {
    match &context.secret_config {
        SecretMaterial::Single(secret) => symmetric_decrypt(secret.as_str(), data),
        SecretMaterial::Rotating(config) => symmetric_decrypt(config, data),
    }
}
