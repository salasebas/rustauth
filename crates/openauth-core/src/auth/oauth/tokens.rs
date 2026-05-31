use crate::context::{AuthContext, SecretMaterial};
use crate::crypto::{parse_envelope, symmetric_decrypt, symmetric_encrypt};
use crate::error::OpenAuthError;

/// OAuth provider tokens persisted in the account table. Grouping the fields
/// keeps create/update/refresh paths from drifting on which tokens are
/// encrypted at rest.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StoredOAuthTokens {
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
}

pub fn set_token_util(
    token: Option<&str>,
    context: &AuthContext,
) -> Result<Option<String>, OpenAuthError> {
    let Some(token) = token else {
        return Ok(None);
    };
    if context.options.account.encrypt_oauth_tokens {
        encrypt_with_context(token, context).map(Some)
    } else {
        Ok(Some(token.to_owned()))
    }
}

/// Encrypt every OAuth token field exactly once at the storage boundary so no
/// single token class (including `id_token`) is left in plaintext at rest.
pub fn encrypt_oauth_tokens_for_storage(
    access_token: Option<&str>,
    refresh_token: Option<&str>,
    id_token: Option<&str>,
    context: &AuthContext,
) -> Result<StoredOAuthTokens, OpenAuthError> {
    Ok(StoredOAuthTokens {
        access_token: set_token_util(access_token, context)?,
        refresh_token: set_token_util(refresh_token, context)?,
        id_token: set_token_util(id_token, context)?,
    })
}

pub fn decrypt_oauth_token(token: &str, context: &AuthContext) -> Result<String, OpenAuthError> {
    if token.is_empty() || !context.options.account.encrypt_oauth_tokens {
        return Ok(token.to_owned());
    }
    if !is_likely_encrypted(token) {
        return Ok(token.to_owned());
    }
    decrypt_with_context(token, context)
}

/// Decrypt a stored optional OAuth token for use or inclusion in a response.
pub fn decrypt_optional_oauth_token(
    token: Option<&str>,
    context: &AuthContext,
) -> Result<Option<String>, OpenAuthError> {
    token
        .map(|token| decrypt_oauth_token(token, context))
        .transpose()
}

pub(crate) fn encrypt_with_context(
    data: &str,
    context: &AuthContext,
) -> Result<String, OpenAuthError> {
    match &context.secret_config {
        SecretMaterial::Single(secret) => symmetric_encrypt(secret.as_str(), data),
        SecretMaterial::Rotating(config) => symmetric_encrypt(config, data),
    }
}

pub(crate) fn decrypt_with_context(
    data: &str,
    context: &AuthContext,
) -> Result<String, OpenAuthError> {
    match &context.secret_config {
        SecretMaterial::Single(secret) => symmetric_decrypt(secret.as_str(), data),
        SecretMaterial::Rotating(config) => symmetric_decrypt(config, data),
    }
}

fn is_likely_encrypted(token: &str) -> bool {
    // Rotating secrets wrap the ciphertext in the `$oa$<version>$<hex>`
    // envelope; single secrets emit the raw hex payload. Anything else (for
    // example a legacy plaintext JWT id_token) is treated as not encrypted so
    // backwards-compatible reads pass it through untouched.
    parse_envelope(token).is_some()
        || (!token.is_empty()
            && token.len() % 2 == 0
            && token.chars().all(|character| character.is_ascii_hexdigit()))
}
