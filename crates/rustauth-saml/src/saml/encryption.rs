use thiserror::Error;

#[derive(Debug, Error)]
pub enum SamlAssertionDecryptionError {
    #[error("encrypted SAML assertions are not supported")]
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

pub fn decrypt_encrypted_assertion_response(
    xml: &str,
    private_key_pem: &str,
) -> Result<String, SamlAssertionDecryptionError> {
    #[cfg(feature = "saml-signed")]
    {
        if private_key_pem.trim().is_empty() {
            return Err(SamlAssertionDecryptionError::MissingPrivateKey);
        }
        let key = opensaml::crypto::keys::load_private_key(private_key_pem, None)
            .map_err(|_| SamlAssertionDecryptionError::InvalidPrivateKey)?;
        let (response, _) =
            opensaml::crypto::decrypt_assertion(xml, &key).map_err(map_decryption_error)?;
        Ok(response)
    }
    #[cfg(not(feature = "saml-signed"))]
    {
        let _ = (xml, private_key_pem);
        Err(SamlAssertionDecryptionError::Unsupported)
    }
}

#[cfg(feature = "saml-signed")]
fn map_decryption_error(error: opensaml::error::OpenSamlError) -> SamlAssertionDecryptionError {
    match error {
        opensaml::error::OpenSamlError::Crypto(message)
            if message.contains("ERR_UNDEFINED_ENCRYPTED_ASSERTION") =>
        {
            SamlAssertionDecryptionError::MissingEncryptedAssertion
        }
        opensaml::error::OpenSamlError::Xml(_)
        | opensaml::error::OpenSamlError::Base64(_)
        | opensaml::error::OpenSamlError::Invalid(_) => {
            SamlAssertionDecryptionError::InvalidResponse
        }
        _ => SamlAssertionDecryptionError::DecryptionFailed,
    }
}
