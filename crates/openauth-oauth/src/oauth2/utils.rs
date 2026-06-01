use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};

use super::error::OAuthError;

pub use super::tokens::{get_oauth2_tokens, get_primary_client_id};

/// Inclusive RFC 7636 §4.1 bounds for a PKCE `code_verifier`.
const CODE_VERIFIER_MIN_LEN: usize = 43;
const CODE_VERIFIER_MAX_LEN: usize = 128;

/// Validates a PKCE `code_verifier` against RFC 7636 §4.1 syntax: 43–128
/// characters drawn only from the unreserved set `A-Z`, `a-z`, `0-9`, `-`,
/// `.`, `_`, `~`. Empty, too-short, too-long, whitespace, non-ASCII, and
/// reserved-character values are rejected so OpenAuth never advertises `S256`
/// for a verifier a provider would reject.
pub fn validate_code_verifier(code_verifier: &str) -> Result<(), OAuthError> {
    let len = code_verifier.len();
    if !(CODE_VERIFIER_MIN_LEN..=CODE_VERIFIER_MAX_LEN).contains(&len) {
        return Err(OAuthError::InvalidCodeVerifier(format!(
            "length {len} is outside the RFC 7636 range of \
             {CODE_VERIFIER_MIN_LEN}-{CODE_VERIFIER_MAX_LEN} characters"
        )));
    }
    if !code_verifier
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
    {
        return Err(OAuthError::InvalidCodeVerifier(
            "only RFC 7636 unreserved characters (A-Z, a-z, 0-9, -, ., _, ~) are allowed"
                .to_owned(),
        ));
    }
    Ok(())
}

pub fn generate_code_challenge(code_verifier: &str) -> Result<String, OAuthError> {
    validate_code_verifier(code_verifier)?;
    let hash = Sha256::digest(code_verifier.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(hash))
}
