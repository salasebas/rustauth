#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SamlSignatureInfo {
    pub count: usize,
    pub response: bool,
    pub assertion: bool,
    pub logout_request: bool,
    pub logout_response: bool,
}

impl SamlSignatureInfo {
    pub fn is_signed(self) -> bool {
        self.count > 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SamlSignedElement {
    Response,
    Assertion,
    LogoutRequest,
    LogoutResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedSamlSignature {
    pub element: SamlSignedElement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SamlSignatureValidationError {
    NotImplemented,
    MissingCertificate,
    AmbiguousSignature,
    Invalid,
}

impl SamlSignatureValidationError {
    pub fn code(self) -> &'static str {
        match self {
            Self::NotImplemented => "SAML_SIGNATURE_VALIDATION_NOT_IMPLEMENTED",
            Self::MissingCertificate => "SAML_CERTIFICATE_REQUIRED",
            Self::AmbiguousSignature => "SAML_SIGNATURE_AMBIGUOUS",
            Self::Invalid => "SAML_SIGNATURE_INVALID",
        }
    }
}

pub async fn verify_signed_saml_response(
    _encoded_response: &str,
    _signature: SamlSignatureInfo,
    _cert: &str,
) -> Result<VerifiedSamlSignature, SamlSignatureValidationError> {
    Err(SamlSignatureValidationError::NotImplemented)
}

pub async fn verify_signed_logout_request(
    _encoded_request: &str,
    _signature: SamlSignatureInfo,
    _cert: &str,
) -> Result<VerifiedSamlSignature, SamlSignatureValidationError> {
    Err(SamlSignatureValidationError::NotImplemented)
}

pub async fn verify_signed_logout_response(
    _encoded_response: &str,
    _signature: SamlSignatureInfo,
    _cert: &str,
) -> Result<VerifiedSamlSignature, SamlSignatureValidationError> {
    Err(SamlSignatureValidationError::NotImplemented)
}

pub fn verify_redirect_logout_request(
    _path_and_query: &str,
    _cert: &str,
) -> Result<(), SamlSignatureValidationError> {
    Err(SamlSignatureValidationError::NotImplemented)
}

pub fn verify_redirect_logout_response(
    _path_and_query: &str,
    _cert: &str,
) -> Result<(), SamlSignatureValidationError> {
    Err(SamlSignatureValidationError::NotImplemented)
}
