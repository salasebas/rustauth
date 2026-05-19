use thiserror::Error;

#[cfg(feature = "saml-signed")]
use samael::traits::ToXml;

#[derive(Debug, Error)]
pub enum SamlAssertionDecryptionError {
    #[error("encrypted SAML assertions are not supported without the `saml-signed` feature")]
    Unsupported,
    #[error("SAML encrypted assertion missing private key")]
    MissingPrivateKey,
    #[error("invalid SAML assertion decryption key")]
    InvalidPrivateKey,
    #[error("failed to parse encrypted SAML response")]
    InvalidResponse,
    #[error("SAML response does not contain an encrypted assertion")]
    MissingEncryptedAssertion,
    #[error("failed to decrypt SAML assertion")]
    DecryptionFailed,
    #[error("failed to serialize decrypted SAML response")]
    SerializationFailed,
}

impl SamlAssertionDecryptionError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unsupported => "ENCRYPTED_SAML_ASSERTION_UNSUPPORTED",
            Self::MissingPrivateKey => "SAML_DECRYPTION_KEY_REQUIRED",
            Self::InvalidPrivateKey => "SAML_DECRYPTION_KEY_INVALID",
            Self::InvalidResponse
            | Self::MissingEncryptedAssertion
            | Self::DecryptionFailed
            | Self::SerializationFailed => "SAML_ASSERTION_DECRYPTION_FAILED",
        }
    }
}

#[cfg(feature = "saml-signed")]
pub fn decrypt_encrypted_assertion_response(
    xml: &str,
    private_key_pem: &str,
) -> Result<String, SamlAssertionDecryptionError> {
    let key = openssl::pkey::PKey::private_key_from_pem(private_key_pem.as_bytes())
        .map_err(|_| SamlAssertionDecryptionError::InvalidPrivateKey)?;
    let mut response = xml
        .parse::<samael::schema::Response>()
        .map_err(|_| SamlAssertionDecryptionError::InvalidResponse)?;
    let encrypted = response
        .encrypted_assertion
        .take()
        .ok_or(SamlAssertionDecryptionError::MissingEncryptedAssertion)?;
    let assertion = encrypted
        .decrypt(&key)
        .map_err(|_| SamlAssertionDecryptionError::DecryptionFailed)?;
    response.assertion = Some(assertion);
    response.encrypted_assertion = None;
    response
        .to_string()
        .map_err(|_| SamlAssertionDecryptionError::SerializationFailed)
}

#[cfg(not(feature = "saml-signed"))]
pub fn decrypt_encrypted_assertion_response(
    _xml: &str,
    _private_key_pem: &str,
) -> Result<String, SamlAssertionDecryptionError> {
    Err(SamlAssertionDecryptionError::Unsupported)
}
