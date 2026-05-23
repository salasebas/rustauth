use base64::Engine;
use openauth_core::error::OpenAuthError;
use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use std::collections::BTreeMap;

use super::encryption::{decrypt_encrypted_assertion_response, SamlAssertionDecryptionError};
use super::security::{collect_saml_runtime_algorithms, SamlConditions, SamlRuntimeAlgorithms};
use super::signature::SamlSignatureInfo;
use super::xml::{local_name, validate_saml_xml};

pub const ENCRYPTED_ASSERTION_UNSUPPORTED: &str = "Encrypted SAML assertions are not supported";

#[derive(Debug, thiserror::Error)]
pub enum SamlResponseParseError {
    #[error("Invalid base64-encoded SAML response")]
    InvalidEncoding,
    #[error("Invalid SAML XML: {0}")]
    InvalidXml(String),
    #[error("SAML response contains no assertions")]
    MissingAssertion,
    #[error("SAML response contains {count} assertions, expected exactly 1")]
    UnexpectedAssertionCount { count: usize },
    #[error("{0}")]
    EncryptedAssertionUnsupported(&'static str),
    #[error("SAML assertion missing ID")]
    MissingAssertionId,
    #[error("{0}")]
    Decryption(#[from] SamlAssertionDecryptionError),
}

impl SamlResponseParseError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::EncryptedAssertionUnsupported(_) => "ENCRYPTED_SAML_ASSERTION_UNSUPPORTED",
            Self::Decryption(error) => error.code(),
            Self::MissingAssertionId => "INVALID_SAML_RESPONSE",
            Self::MissingAssertion
            | Self::UnexpectedAssertionCount { .. }
            | Self::InvalidEncoding
            | Self::InvalidXml(_) => "INVALID_SAML_RESPONSE",
        }
    }

    pub fn status(&self) -> http::StatusCode {
        http::StatusCode::BAD_REQUEST
    }
}

impl From<SamlResponseParseError> for OpenAuthError {
    fn from(error: SamlResponseParseError) -> Self {
        match error {
            SamlResponseParseError::Decryption(error) => {
                OpenAuthError::Api(error.code().to_owned())
            }
            error => OpenAuthError::Api(error.to_string()),
        }
    }
}

impl From<OpenAuthError> for SamlResponseParseError {
    fn from(error: OpenAuthError) -> Self {
        SamlResponseParseError::InvalidXml(error.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssertionCounts {
    pub assertions: usize,
    pub encrypted_assertions: usize,
    pub total: usize,
}

pub fn count_assertions(xml: &str) -> Result<AssertionCounts, OpenAuthError> {
    validate_saml_xml(xml)?;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut assertions = 0;
    let mut encrypted_assertions = 0;

    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) => {
                let name = local_name(element.name().as_ref())?;
                increment_assertion_count(&name, &mut assertions, &mut encrypted_assertions);
            }
            Ok(Event::Empty(element)) => {
                let name = local_name(element.name().as_ref())?;
                increment_assertion_count(&name, &mut assertions, &mut encrypted_assertions);
            }
            Ok(Event::Eof) => break,
            Err(error) => return Err(OpenAuthError::Api(format!("Invalid SAML XML: {error}"))),
            _ => {}
        }
    }

    Ok(AssertionCounts {
        assertions,
        encrypted_assertions,
        total: assertions + encrypted_assertions,
    })
}

pub fn validate_single_assertion(encoded_response: &str) -> Result<(), OpenAuthError> {
    let compact = encoded_response.split_whitespace().collect::<String>();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(compact)
        .map_err(|_| OpenAuthError::Api("Invalid base64-encoded SAML response".to_owned()))?;
    let xml = String::from_utf8(bytes)
        .map_err(|_| OpenAuthError::Api("Invalid base64-encoded SAML response".to_owned()))?;
    if !xml.contains('<') {
        return Err(OpenAuthError::Api(
            "Invalid base64-encoded SAML response".to_owned(),
        ));
    }
    let counts = count_assertions(&xml)?;
    if counts.total == 0 {
        return Err(OpenAuthError::Api(
            "SAML response contains no assertions".to_owned(),
        ));
    }
    if counts.assertions == 0 && counts.encrypted_assertions == 1 {
        return Err(OpenAuthError::Api(
            ENCRYPTED_ASSERTION_UNSUPPORTED.to_owned(),
        ));
    }
    if counts.total > 1 {
        return Err(OpenAuthError::Api(format!(
            "SAML response contains {} assertions, expected exactly 1",
            counts.total
        )));
    }
    validate_assertion_locations(&xml)?;
    Ok(())
}

fn increment_assertion_count(name: &str, assertions: &mut usize, encrypted_assertions: &mut usize) {
    if name == "Assertion" {
        *assertions += 1;
    } else if name == "EncryptedAssertion" {
        *encrypted_assertions += 1;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSamlResponse {
    pub response_destination: Option<String>,
    pub response_in_response_to: Option<String>,
    pub response_issuer: Option<String>,
    pub status_code: Option<String>,
    pub has_signature: bool,
    pub signature: SamlSignatureInfo,
    pub algorithms: SamlRuntimeAlgorithms,
    pub assertion: ParsedSamlAssertion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSamlAssertion {
    pub id: String,
    pub issuer: Option<String>,
    pub name_id: Option<String>,
    pub conditions: Option<SamlConditions>,
    pub subject_confirmation: Option<ParsedSubjectConfirmation>,
    pub attributes: BTreeMap<String, String>,
    pub session_index: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSubjectConfirmation {
    pub recipient: Option<String>,
    pub in_response_to: Option<String>,
    pub conditions: Option<SamlConditions>,
}

pub fn parse_saml_response(encoded_response: &str) -> Result<ParsedSamlResponse, OpenAuthError> {
    let xml = decode_saml_response_xml(encoded_response)?;
    parse_saml_response_xml(&xml)
}

pub fn parse_saml_response_with_decryption(
    encoded_response: &str,
    decryption_private_key: Option<&str>,
) -> Result<ParsedSamlResponse, OpenAuthError> {
    parse_saml_response_with_decryption_detailed(encoded_response, decryption_private_key)
        .map_err(Into::into)
}

pub fn parse_saml_response_with_decryption_detailed(
    encoded_response: &str,
    decryption_private_key: Option<&str>,
) -> Result<ParsedSamlResponse, SamlResponseParseError> {
    let xml = decode_saml_response_xml_detailed(encoded_response)?;
    validate_assertion_locations_detailed(&xml)?;
    let counts = count_assertions_detailed(&xml)?;
    if counts.assertions == 0 && counts.encrypted_assertions == 1 {
        let Some(private_key) = decryption_private_key else {
            return Err(SamlResponseParseError::EncryptedAssertionUnsupported(
                ENCRYPTED_ASSERTION_UNSUPPORTED,
            ));
        };
        let decrypted = decrypt_encrypted_assertion_response(&xml, private_key)?;
        return parse_saml_response_xml_detailed(&decrypted);
    }
    parse_saml_response_xml_detailed(&xml)
}

fn parse_saml_response_xml(xml: &str) -> Result<ParsedSamlResponse, OpenAuthError> {
    parse_saml_response_xml_detailed(xml).map_err(Into::into)
}

fn parse_saml_response_xml_detailed(
    xml: &str,
) -> Result<ParsedSamlResponse, SamlResponseParseError> {
    validate_saml_xml(xml)?;
    validate_assertion_locations_detailed(xml)?;
    let algorithms = collect_saml_runtime_algorithms(xml)?;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut state = SamlResponseParseState::default();

    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) => {
                let name = local_name(element.name().as_ref())?;
                state.start(&reader, &element, name)?;
            }
            Ok(Event::Empty(element)) => {
                let name = local_name(element.name().as_ref())?;
                state.empty(&reader, &element, &name)?;
            }
            Ok(Event::Text(text)) => {
                state.current_text.push_str(
                    &text
                        .unescape()
                        .map_err(|error| SamlResponseParseError::InvalidXml(error.to_string()))?,
                );
            }
            Ok(Event::End(element)) => {
                let name = local_name(element.name().as_ref())?;
                state.end(&name);
            }
            Ok(Event::Eof) => break,
            Err(error) => return Err(SamlResponseParseError::InvalidXml(error.to_string())),
            _ => {}
        }
    }

    state.finish(algorithms)
}

fn decode_saml_response_xml(encoded_response: &str) -> Result<String, OpenAuthError> {
    decode_saml_response_xml_detailed(encoded_response).map_err(Into::into)
}

fn decode_saml_response_xml_detailed(
    encoded_response: &str,
) -> Result<String, SamlResponseParseError> {
    let compact = encoded_response.split_whitespace().collect::<String>();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(compact)
        .map_err(|_| SamlResponseParseError::InvalidEncoding)?;
    String::from_utf8(bytes).map_err(|_| SamlResponseParseError::InvalidEncoding)
}

fn count_assertions_detailed(xml: &str) -> Result<AssertionCounts, SamlResponseParseError> {
    count_assertions(xml).map_err(SamlResponseParseError::from)
}

fn validate_assertion_locations(xml: &str) -> Result<(), OpenAuthError> {
    validate_saml_xml(xml)?;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut stack = Vec::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) => {
                let name = local_name(element.name().as_ref())?;
                validate_assertion_parent(&stack, &name)?;
                stack.push(name);
            }
            Ok(Event::Empty(element)) => {
                let name = local_name(element.name().as_ref())?;
                validate_assertion_parent(&stack, &name)?;
            }
            Ok(Event::End(_)) => {
                stack.pop();
            }
            Ok(Event::Eof) => break,
            Err(error) => return Err(OpenAuthError::Api(format!("Invalid SAML XML: {error}"))),
            _ => {}
        }
    }

    Ok(())
}

fn validate_assertion_parent(stack: &[String], name: &str) -> Result<(), OpenAuthError> {
    if matches!(name, "Assertion" | "EncryptedAssertion")
        && !stack.last().is_some_and(|parent| parent == "Response")
    {
        return Err(OpenAuthError::Api(
            "SAML assertion must be a direct Response child".to_owned(),
        ));
    }
    Ok(())
}

fn validate_assertion_locations_detailed(xml: &str) -> Result<(), SamlResponseParseError> {
    validate_assertion_locations(xml).map_err(SamlResponseParseError::from)
}

#[derive(Default)]
struct SamlResponseParseState {
    response_destination: Option<String>,
    response_in_response_to: Option<String>,
    response_issuer: Option<String>,
    assertion_issuer: Option<String>,
    status_code: Option<String>,
    assertion_id: Option<String>,
    name_id: Option<String>,
    conditions: Option<SamlConditions>,
    subject_confirmation: Option<ParsedSubjectConfirmation>,
    attributes: BTreeMap<String, String>,
    session_index: Option<String>,
    has_signature: bool,
    signature: SamlSignatureInfo,
    assertion_count: usize,
    encrypted_assertion_count: usize,
    stack: Vec<String>,
    current_text: String,
    current_attribute: Option<(String, String)>,
}

impl SamlResponseParseState {
    fn start(
        &mut self,
        reader: &Reader<&[u8]>,
        element: &BytesStart<'_>,
        name: String,
    ) -> Result<(), SamlResponseParseError> {
        self.apply_start(reader, element, &name)?;
        self.count_element(&name);
        self.current_text.clear();
        self.stack.push(name);
        Ok(())
    }

    fn empty(
        &mut self,
        reader: &Reader<&[u8]>,
        element: &BytesStart<'_>,
        name: &str,
    ) -> Result<(), SamlResponseParseError> {
        self.apply_start(reader, element, name)?;
        self.count_element(name);
        Ok(())
    }

    fn end(&mut self, name: &str) {
        match name {
            "Issuer" if self.stack_contains("Assertion") && !self.current_text.is_empty() => {
                self.assertion_issuer = Some(self.current_text.clone());
            }
            "Issuer" if !self.current_text.is_empty() => {
                self.response_issuer = Some(self.current_text.clone());
            }
            "NameID" if self.name_id.is_none() && !self.current_text.is_empty() => {
                self.name_id = Some(self.current_text.clone());
            }
            "AttributeValue" => {
                if let Some((_, value)) = &mut self.current_attribute {
                    if value.is_empty() {
                        *value = self.current_text.clone();
                    }
                }
            }
            "Attribute" => {
                if let Some((key, value)) = self.current_attribute.take() {
                    self.attributes.insert(key, value);
                }
            }
            _ => {}
        }
        self.current_text.clear();
        self.stack.pop();
    }

    fn finish(
        self,
        algorithms: SamlRuntimeAlgorithms,
    ) -> Result<ParsedSamlResponse, SamlResponseParseError> {
        let total_assertions = self.assertion_count + self.encrypted_assertion_count;
        if total_assertions != 1 {
            return Err(SamlResponseParseError::UnexpectedAssertionCount {
                count: total_assertions,
            });
        }
        if self.assertion_count == 0 && self.encrypted_assertion_count == 1 {
            return Err(SamlResponseParseError::EncryptedAssertionUnsupported(
                ENCRYPTED_ASSERTION_UNSUPPORTED,
            ));
        }
        let assertion_id = self
            .assertion_id
            .ok_or(SamlResponseParseError::MissingAssertionId)?;
        Ok(ParsedSamlResponse {
            response_destination: self.response_destination,
            response_in_response_to: self.response_in_response_to,
            response_issuer: self.response_issuer,
            status_code: self.status_code,
            has_signature: self.has_signature,
            signature: self.signature,
            algorithms,
            assertion: ParsedSamlAssertion {
                id: assertion_id,
                issuer: self.assertion_issuer,
                name_id: self.name_id,
                conditions: self.conditions,
                subject_confirmation: self.subject_confirmation,
                attributes: self.attributes,
                session_index: self.session_index,
            },
        })
    }

    fn apply_start(
        &mut self,
        reader: &Reader<&[u8]>,
        element: &BytesStart<'_>,
        name: &str,
    ) -> Result<(), SamlResponseParseError> {
        match name {
            "Response" => {
                self.response_destination = attr(reader, element, "Destination")?;
                self.response_in_response_to = attr(reader, element, "InResponseTo")?;
            }
            "StatusCode" => {
                self.status_code = attr(reader, element, "Value")?;
            }
            "Assertion" => {
                self.assertion_id = attr(reader, element, "ID")?;
            }
            "Conditions" if self.stack_contains("Assertion") => {
                self.conditions = Some(SamlConditions {
                    not_before: attr(reader, element, "NotBefore")?,
                    not_on_or_after: attr(reader, element, "NotOnOrAfter")?,
                });
            }
            "SubjectConfirmationData" => {
                self.subject_confirmation = Some(ParsedSubjectConfirmation {
                    recipient: attr(reader, element, "Recipient")?,
                    in_response_to: attr(reader, element, "InResponseTo")?,
                    conditions: Some(SamlConditions {
                        not_before: attr(reader, element, "NotBefore")?,
                        not_on_or_after: attr(reader, element, "NotOnOrAfter")?,
                    }),
                });
            }
            "AuthnStatement" => {
                self.session_index = attr(reader, element, "SessionIndex")?;
            }
            "Attribute" => {
                let key = attr(reader, element, "Name")?
                    .or_else(|| attr(reader, element, "FriendlyName").ok().flatten());
                if let Some(key) = key {
                    self.current_attribute = Some((key, String::new()));
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn count_element(&mut self, name: &str) {
        if name == "Assertion" {
            self.assertion_count += 1;
        } else if name == "EncryptedAssertion" {
            self.encrypted_assertion_count += 1;
        } else if name == "Signature" {
            self.has_signature = true;
            self.signature.count += 1;
            if self.stack_contains("Assertion") {
                self.signature.assertion = true;
            } else if self.stack_contains("Response") {
                self.signature.response = true;
            }
        }
    }

    fn stack_contains(&self, name: &str) -> bool {
        self.stack.iter().any(|item| item == name)
    }
}

fn attr(
    reader: &Reader<&[u8]>,
    element: &BytesStart<'_>,
    name: &str,
) -> Result<Option<String>, OpenAuthError> {
    for attribute in element.attributes() {
        let attribute = attribute.map_err(|error| OpenAuthError::Api(error.to_string()))?;
        if local_name(attribute.key.as_ref())? == name {
            return attribute
                .decode_and_unescape_value(reader.decoder())
                .map(|value| Some(value.into_owned()))
                .map_err(|error| OpenAuthError::Api(error.to_string()));
        }
    }
    Ok(None)
}
