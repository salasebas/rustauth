#[cfg(feature = "saml-signed")]
use crate::saml::xml::{local_name, validate_saml_xml};
#[cfg(feature = "saml-signed")]
use base64::Engine;
#[cfg(feature = "saml-signed")]
use openauth_core::error::OpenAuthError;
#[cfg(feature = "saml-signed")]
use quick_xml::events::Event;
#[cfg(feature = "saml-signed")]
use quick_xml::Reader;
#[cfg(feature = "saml-signed")]
use std::path::PathBuf;
#[cfg(feature = "saml-signed")]
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(feature = "saml-signed")]
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

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
    verify_signed_post_xml(
        encoded_response,
        signature,
        cert,
        &[SamlSignedElement::Response, SamlSignedElement::Assertion],
    )
    .await
}

pub async fn verify_signed_logout_request(
    encoded_request: &str,
    signature: SamlSignatureInfo,
    cert: &str,
) -> Result<VerifiedSamlSignature, SamlSignatureValidationError> {
    verify_signed_post_xml(
        encoded_request,
        signature,
        cert,
        &[SamlSignedElement::LogoutRequest],
    )
    .await
}

pub async fn verify_signed_logout_response(
    encoded_response: &str,
    signature: SamlSignatureInfo,
    cert: &str,
) -> Result<VerifiedSamlSignature, SamlSignatureValidationError> {
    verify_signed_post_xml(
        encoded_response,
        signature,
        cert,
        &[SamlSignedElement::LogoutResponse],
    )
    .await
}

#[cfg(not(feature = "saml-signed"))]
async fn verify_signed_post_xml(
    _encoded: &str,
    _signature: SamlSignatureInfo,
    _cert: &str,
    _allowed: &[SamlSignedElement],
) -> Result<VerifiedSamlSignature, SamlSignatureValidationError> {
    Err(SamlSignatureValidationError::NotImplemented)
}

#[cfg(feature = "saml-signed")]
async fn verify_signed_post_xml(
    encoded: &str,
    signature: SamlSignatureInfo,
    cert: &str,
    allowed: &[SamlSignedElement],
) -> Result<VerifiedSamlSignature, SamlSignatureValidationError> {
    if signature.count != 1 {
        return Err(SamlSignatureValidationError::AmbiguousSignature);
    }
    let xml = decode_base64_xml(encoded).map_err(|_| SamlSignatureValidationError::Invalid)?;
    ensure_unique_xml_ids(&xml)?;
    let cert = certificate_pem(cert)?;
    let element = signed_element(signature).ok_or(SamlSignatureValidationError::Invalid)?;
    if !allowed.contains(&element) {
        return Err(SamlSignatureValidationError::Invalid);
    }
    let element_name = element.xmlsec_id_attr_element();
    tokio::task::spawn_blocking(move || verify_xmlsec1(&xml, &cert, element_name))
        .await
        .map_err(|_| SamlSignatureValidationError::Invalid)??;
    Ok(VerifiedSamlSignature { element })
}

pub fn verify_redirect_logout_request(
    path_and_query: &str,
    cert: &str,
) -> Result<(), SamlSignatureValidationError> {
    verify_redirect_binding(path_and_query, cert, RedirectBindingMessage::Request)
}

pub fn verify_redirect_logout_response(
    path_and_query: &str,
    cert: &str,
) -> Result<(), SamlSignatureValidationError> {
    verify_redirect_binding(path_and_query, cert, RedirectBindingMessage::Response)
}

#[derive(Debug, Clone, Copy)]
enum RedirectBindingMessage {
    Request,
    Response,
}

#[cfg(not(feature = "saml-signed"))]
fn verify_redirect_binding(
    _path_and_query: &str,
    _cert: &str,
    _message: RedirectBindingMessage,
) -> Result<(), SamlSignatureValidationError> {
    Err(SamlSignatureValidationError::NotImplemented)
}

#[cfg(feature = "saml-signed")]
fn verify_redirect_binding(
    path_and_query: &str,
    cert: &str,
    message: RedirectBindingMessage,
) -> Result<(), SamlSignatureValidationError> {
    let cert = certificate_der(cert)?;
    let verifier = samael::crypto::UrlVerifier::from_x509(&cert)
        .map_err(|_| SamlSignatureValidationError::Invalid)?;
    let path_and_query = path_and_query.to_owned();
    let valid = match message {
        RedirectBindingMessage::Request => verifier
            .verify_percent_encoded_request_uri_string(&path_and_query)
            .map_err(|_| SamlSignatureValidationError::Invalid)?,
        RedirectBindingMessage::Response => verifier
            .verify_percent_encoded_response_uri_string(&path_and_query)
            .map_err(|_| SamlSignatureValidationError::Invalid)?,
    };
    valid
        .then_some(())
        .ok_or(SamlSignatureValidationError::Invalid)
}

#[cfg(feature = "saml-signed")]
fn decode_base64_xml(encoded: &str) -> Result<String, OpenAuthError> {
    let compact = encoded.split_whitespace().collect::<String>();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(compact)
        .map_err(|_| OpenAuthError::Api("Invalid base64-encoded SAML message".to_owned()))?;
    String::from_utf8(bytes)
        .map_err(|_| OpenAuthError::Api("Invalid base64-encoded SAML message".to_owned()))
}

#[cfg(feature = "saml-signed")]
fn ensure_unique_xml_ids(xml: &str) -> Result<(), SamlSignatureValidationError> {
    validate_saml_xml(xml).map_err(|_| SamlSignatureValidationError::Invalid)?;

    let mut reader = Reader::from_str(xml);
    let mut ids = std::collections::BTreeSet::new();
    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) | Ok(Event::Empty(element)) => {
                for attr in element.attributes() {
                    let attr = attr.map_err(|_| SamlSignatureValidationError::Invalid)?;
                    if local_name(attr.key.as_ref())
                        .map_err(|_| SamlSignatureValidationError::Invalid)?
                        == "ID"
                    {
                        let value = attr
                            .decode_and_unescape_value(reader.decoder())
                            .map_err(|_| SamlSignatureValidationError::Invalid)?
                            .into_owned();
                        if !ids.insert(value) {
                            return Err(SamlSignatureValidationError::AmbiguousSignature);
                        }
                    }
                }
            }
            Ok(Event::Eof) => return Ok(()),
            Err(_) => return Err(SamlSignatureValidationError::Invalid),
            Ok(_) => {}
        }
    }
}

#[cfg(feature = "saml-signed")]
fn signed_element(signature: SamlSignatureInfo) -> Option<SamlSignedElement> {
    if signature.assertion {
        Some(SamlSignedElement::Assertion)
    } else if signature.response {
        Some(SamlSignedElement::Response)
    } else if signature.logout_request {
        Some(SamlSignedElement::LogoutRequest)
    } else if signature.logout_response {
        Some(SamlSignedElement::LogoutResponse)
    } else {
        None
    }
}

impl SamlSignedElement {
    #[cfg(feature = "saml-signed")]
    fn xmlsec_id_attr_element(self) -> &'static str {
        match self {
            Self::Response => "Response",
            Self::Assertion => "Assertion",
            Self::LogoutRequest => "LogoutRequest",
            Self::LogoutResponse => "LogoutResponse",
        }
    }
}

#[cfg(feature = "saml-signed")]
fn verify_xmlsec1(
    xml: &str,
    cert_pem: &str,
    id_attr_element: &'static str,
) -> Result<(), SamlSignatureValidationError> {
    let directory = temp_directory()?;
    let xml_path = directory.join("message.xml");
    let cert_path = directory.join("idp-cert.pem");
    let result = (|| {
        std::fs::create_dir_all(&directory).map_err(|_| SamlSignatureValidationError::Invalid)?;
        std::fs::write(&xml_path, xml).map_err(|_| SamlSignatureValidationError::Invalid)?;
        std::fs::write(&cert_path, cert_pem).map_err(|_| SamlSignatureValidationError::Invalid)?;
        let status = std::process::Command::new("xmlsec1")
            .arg("--verify")
            .arg("--lax-key-search")
            .arg("--enabled-reference-uris")
            .arg("same-doc")
            .arg("--id-attr:ID")
            .arg(id_attr_element)
            .arg("--pubkey-cert-pem")
            .arg(&cert_path)
            .arg(&xml_path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|_| SamlSignatureValidationError::Invalid)?;
        status
            .success()
            .then_some(())
            .ok_or(SamlSignatureValidationError::Invalid)
    })();
    let _ = std::fs::remove_dir_all(&directory);
    result
}

#[cfg(feature = "saml-signed")]
fn temp_directory() -> Result<PathBuf, SamlSignatureValidationError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| SamlSignatureValidationError::Invalid)?;
    Ok(std::env::temp_dir().join(format!(
        "openauth-sso-saml-{}-{}-{}",
        std::process::id(),
        now.as_nanos(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    )))
}

#[cfg(feature = "saml-signed")]
fn certificate_der(
    cert: &str,
) -> Result<samael::crypto::CertificateDer, SamlSignatureValidationError> {
    let normalized = normalize_certificate(cert);
    if normalized.is_empty() {
        return Err(SamlSignatureValidationError::MissingCertificate);
    }
    samael::crypto::decode_x509_cert(&normalized).map_err(|_| SamlSignatureValidationError::Invalid)
}

#[cfg(feature = "saml-signed")]
fn certificate_pem(cert: &str) -> Result<String, SamlSignatureValidationError> {
    let normalized = normalize_certificate(cert);
    if normalized.is_empty() {
        return Err(SamlSignatureValidationError::MissingCertificate);
    }
    Ok(format!(
        "-----BEGIN CERTIFICATE-----\n{normalized}\n-----END CERTIFICATE-----\n"
    ))
}

#[cfg(feature = "saml-signed")]
fn normalize_certificate(cert: &str) -> String {
    cert.lines()
        .filter(|line| !line.starts_with("-----BEGIN ") && !line.starts_with("-----END "))
        .flat_map(|line| line.chars())
        .filter(|character| !character.is_whitespace())
        .collect()
}
