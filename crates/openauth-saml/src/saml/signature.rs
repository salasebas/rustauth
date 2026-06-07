#[cfg(feature = "saml-signed")]
use opensaml::constants::Binding;
use opensaml::constants::ParserType;
#[cfg(feature = "saml-signed")]
use opensaml::flow::{flow, FlowOptions, HttpRequest};

#[cfg(feature = "saml-signed")]
use crate::bridge::opensaml_error_code;
#[cfg(feature = "saml-signed")]
use crate::options::SamlConfig;

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
    encoded_response: &str,
    signature: SamlSignatureInfo,
    cert: &str,
) -> Result<VerifiedSamlSignature, SamlSignatureValidationError> {
    if !signature.is_signed() {
        return Err(SamlSignatureValidationError::Invalid);
    }
    verify_post_message(encoded_response, cert, ParserType::SamlResponse, signature)
}

pub async fn verify_signed_logout_request(
    encoded_request: &str,
    signature: SamlSignatureInfo,
    cert: &str,
) -> Result<VerifiedSamlSignature, SamlSignatureValidationError> {
    if !signature.is_signed() {
        return Err(SamlSignatureValidationError::Invalid);
    }
    verify_post_message(encoded_request, cert, ParserType::LogoutRequest, signature).map(|_| {
        VerifiedSamlSignature {
            element: SamlSignedElement::LogoutRequest,
        }
    })
}

pub async fn verify_signed_logout_response(
    encoded_response: &str,
    signature: SamlSignatureInfo,
    cert: &str,
) -> Result<VerifiedSamlSignature, SamlSignatureValidationError> {
    if !signature.is_signed() {
        return Err(SamlSignatureValidationError::Invalid);
    }
    verify_post_message(
        encoded_response,
        cert,
        ParserType::LogoutResponse,
        signature,
    )
    .map(|_| VerifiedSamlSignature {
        element: SamlSignedElement::LogoutResponse,
    })
}

pub fn verify_redirect_logout_request(
    path_and_query: &str,
    cert: &str,
) -> Result<(), SamlSignatureValidationError> {
    verify_redirect_signature(path_and_query, cert, ParserType::LogoutRequest)
}

pub fn verify_redirect_logout_response(
    path_and_query: &str,
    cert: &str,
) -> Result<(), SamlSignatureValidationError> {
    verify_redirect_signature(path_and_query, cert, ParserType::LogoutResponse)
}

fn verify_post_message(
    encoded: &str,
    cert: &str,
    parser_type: ParserType,
    signature: SamlSignatureInfo,
) -> Result<VerifiedSamlSignature, SamlSignatureValidationError> {
    #[cfg(feature = "saml-signed")]
    {
        let compact = encoded.split_whitespace().collect::<String>();
        let param = parser_type.query_param();
        let request = HttpRequest::post(vec![(param.to_owned(), compact)]);
        let certs = [cert.to_owned()];
        flow(
            &FlowOptions {
                binding: Some(Binding::Post),
                parser_type: Some(parser_type),
                check_signature: true,
                from_issuer: None,
                signing_certs: &certs,
                decrypt_key: None,
                decrypt_key_pass: None,
                clock_drifts: (0, 0),
                expected_audience: None,
                expected_in_response_to: None,
            },
            &request,
        )
        .map_err(map_verify_error)?;
        let element = if signature.assertion {
            SamlSignedElement::Assertion
        } else {
            SamlSignedElement::Response
        };
        Ok(VerifiedSamlSignature { element })
    }
    #[cfg(not(feature = "saml-signed"))]
    {
        let _ = (encoded, cert, parser_type, signature);
        Err(SamlSignatureValidationError::NotImplemented)
    }
}

fn verify_redirect_signature(
    path_and_query: &str,
    cert: &str,
    parser_type: ParserType,
) -> Result<(), SamlSignatureValidationError> {
    #[cfg(feature = "saml-signed")]
    {
        use opensaml::binding::{base64_decode, deflate_raw_decode};

        let url = url::Url::parse(&format!("https://example.test{path_and_query}"))
            .map_err(|_| SamlSignatureValidationError::Invalid)?;
        let query: Vec<(String, String)> = url
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();
        let param = parser_type.query_param();
        let message = query
            .iter()
            .find(|(key, _)| key == param)
            .map(|(_, value)| value.clone())
            .ok_or(SamlSignatureValidationError::Invalid)?;
        let relay_state = query
            .iter()
            .find(|(key, _)| key == "RelayState")
            .map(|(_, value)| value.as_str());
        let sig_alg = query
            .iter()
            .find(|(key, _)| key == "SigAlg")
            .map(|(_, value)| value.as_str())
            .ok_or(SamlSignatureValidationError::Invalid)?;
        let xml = String::from_utf8(
            deflate_raw_decode(
                &base64_decode(&message).map_err(|_| SamlSignatureValidationError::Invalid)?,
            )
            .map_err(|_| SamlSignatureValidationError::Invalid)?,
        )
        .map_err(|_| SamlSignatureValidationError::Invalid)?;
        let octet =
            opensaml::binding::build_redirect_octet(parser_type, &xml, relay_state, sig_alg)
                .map_err(|_| SamlSignatureValidationError::Invalid)?;
        let mut request = HttpRequest::redirect(query);
        request.octet_string = Some(octet);
        let certs = [cert.to_owned()];
        flow(
            &FlowOptions {
                binding: Some(Binding::Redirect),
                parser_type: Some(parser_type),
                check_signature: true,
                from_issuer: None,
                signing_certs: &certs,
                decrypt_key: None,
                decrypt_key_pass: None,
                clock_drifts: (0, 0),
                expected_audience: None,
                expected_in_response_to: None,
            },
            &request,
        )
        .map_err(map_verify_error)?;
        Ok(())
    }
    #[cfg(not(feature = "saml-signed"))]
    {
        let _ = (path_and_query, cert, parser_type);
        Err(SamlSignatureValidationError::NotImplemented)
    }
}

#[cfg(feature = "saml-signed")]
fn map_verify_error(error: opensaml::error::OpenSamlError) -> SamlSignatureValidationError {
    match opensaml_error_code(&error) {
        "SAML_SIGNATURE_VALIDATION_NOT_IMPLEMENTED" => SamlSignatureValidationError::NotImplemented,
        "SAML_CERTIFICATE_REQUIRED" => SamlSignatureValidationError::MissingCertificate,
        _ => SamlSignatureValidationError::Invalid,
    }
}

#[cfg(feature = "saml-signed")]
pub fn verify_saml_response_with_config(
    encoded_response: &str,
    config: &SamlConfig,
    base_url: &str,
    provider_id: &str,
    build_options: &crate::bridge::SpBuildOptions,
    in_response_to: Option<&str>,
) -> Result<VerifiedSamlSignature, SamlSignatureValidationError> {
    let sp = crate::bridge::create_service_provider(config, base_url, provider_id, build_options)
        .map_err(|_| SamlSignatureValidationError::Invalid)?;
    let idp = crate::bridge::create_identity_provider(config)
        .map_err(|_| SamlSignatureValidationError::Invalid)?;
    crate::bridge::parse_login_response(&sp, &idp, encoded_response, in_response_to, true)
        .map_err(map_verify_error)?;
    Ok(VerifiedSamlSignature {
        element: SamlSignedElement::Assertion,
    })
}
