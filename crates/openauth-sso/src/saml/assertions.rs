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
    let xml = decode_saml_response_xml(encoded_response)?;
    let counts = count_assertions(&xml)?;
    if counts.assertions == 0 && counts.encrypted_assertions == 1 {
        let Some(private_key) = decryption_private_key else {
            return Err(OpenAuthError::Api(
                ENCRYPTED_ASSERTION_UNSUPPORTED.to_owned(),
            ));
        };
        let decrypted = decrypt_encrypted_assertion_response(&xml, private_key)
            .map_err(encrypted_assertion_error)?;
        return parse_saml_response_xml(&decrypted);
    }
    parse_saml_response_xml(&xml)
}

fn parse_saml_response_xml(xml: &str) -> Result<ParsedSamlResponse, OpenAuthError> {
    validate_saml_xml(xml)?;
    let algorithms = collect_saml_runtime_algorithms(xml)?;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut response_destination = None;
    let mut response_in_response_to = None;
    let mut response_issuer = None;
    let mut assertion_issuer = None;
    let mut status_code = None;
    let mut assertion_id = None;
    let mut name_id = None;
    let mut conditions = None;
    let mut subject_confirmation = None;
    let mut attributes = BTreeMap::new();
    let mut session_index = None;
    let mut has_signature = false;
    let mut signature = SamlSignatureInfo::default();
    let mut assertion_count = 0;
    let mut encrypted_assertion_count = 0;
    let mut stack = Vec::new();
    let mut current_text = String::new();
    let mut current_attribute: Option<(String, String)> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) => {
                let name = local_name(element.name().as_ref())?;
                apply_start(
                    &reader,
                    &element,
                    &name,
                    &stack,
                    &mut response_destination,
                    &mut response_in_response_to,
                    &mut status_code,
                    &mut assertion_id,
                    &mut conditions,
                    &mut subject_confirmation,
                    &mut session_index,
                    &mut current_attribute,
                )?;
                if name == "Assertion" {
                    assertion_count += 1;
                } else if name == "EncryptedAssertion" {
                    encrypted_assertion_count += 1;
                } else if name == "Signature" {
                    has_signature = true;
                    signature.count += 1;
                    if stack.iter().any(|item| item == "Assertion") {
                        signature.assertion = true;
                    } else if stack.iter().any(|item| item == "Response") {
                        signature.response = true;
                    }
                }
                current_text.clear();
                stack.push(name);
            }
            Ok(Event::Empty(element)) => {
                let name = local_name(element.name().as_ref())?;
                apply_start(
                    &reader,
                    &element,
                    &name,
                    &stack,
                    &mut response_destination,
                    &mut response_in_response_to,
                    &mut status_code,
                    &mut assertion_id,
                    &mut conditions,
                    &mut subject_confirmation,
                    &mut session_index,
                    &mut current_attribute,
                )?;
                if name == "Assertion" {
                    assertion_count += 1;
                } else if name == "EncryptedAssertion" {
                    encrypted_assertion_count += 1;
                } else if name == "Signature" {
                    has_signature = true;
                    signature.count += 1;
                    if stack.iter().any(|item| item == "Assertion") {
                        signature.assertion = true;
                    } else if stack.iter().any(|item| item == "Response") {
                        signature.response = true;
                    }
                }
            }
            Ok(Event::Text(text)) => {
                current_text.push_str(
                    &text
                        .unescape()
                        .map_err(|error| OpenAuthError::Api(error.to_string()))?,
                );
            }
            Ok(Event::End(element)) => {
                let name = local_name(element.name().as_ref())?;
                match name.as_str() {
                    "Issuer" if stack.iter().any(|item| item == "Assertion") => {
                        if !current_text.is_empty() {
                            assertion_issuer = Some(current_text.clone());
                        }
                    }
                    "Issuer" => {
                        if !current_text.is_empty() {
                            response_issuer = Some(current_text.clone());
                        }
                    }
                    "NameID" => {
                        if name_id.is_none() && !current_text.is_empty() {
                            name_id = Some(current_text.clone());
                        }
                    }
                    "AttributeValue" => {
                        if let Some((_, value)) = &mut current_attribute {
                            if value.is_empty() {
                                *value = current_text.clone();
                            }
                        }
                    }
                    "Attribute" => {
                        if let Some((key, value)) = current_attribute.take() {
                            attributes.insert(key, value);
                        }
                    }
                    _ => {}
                }
                current_text.clear();
                stack.pop();
            }
            Ok(Event::Eof) => break,
            Err(error) => return Err(OpenAuthError::Api(format!("Invalid SAML XML: {error}"))),
            _ => {}
        }
    }

    if assertion_count + encrypted_assertion_count != 1 {
        return Err(OpenAuthError::Api(format!(
            "SAML response contains {} assertions, expected exactly 1",
            assertion_count + encrypted_assertion_count
        )));
    }
    if assertion_count == 0 && encrypted_assertion_count == 1 {
        return Err(OpenAuthError::Api(
            ENCRYPTED_ASSERTION_UNSUPPORTED.to_owned(),
        ));
    }
    let assertion_id =
        assertion_id.ok_or_else(|| OpenAuthError::Api("SAML assertion missing ID".to_owned()))?;
    Ok(ParsedSamlResponse {
        response_destination,
        response_in_response_to,
        response_issuer,
        status_code,
        has_signature,
        signature,
        algorithms,
        assertion: ParsedSamlAssertion {
            id: assertion_id,
            issuer: assertion_issuer,
            name_id,
            conditions,
            subject_confirmation,
            attributes,
            session_index,
        },
    })
}

fn decode_saml_response_xml(encoded_response: &str) -> Result<String, OpenAuthError> {
    let compact = encoded_response.split_whitespace().collect::<String>();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(compact)
        .map_err(|_| OpenAuthError::Api("Invalid base64-encoded SAML response".to_owned()))?;
    String::from_utf8(bytes)
        .map_err(|_| OpenAuthError::Api("Invalid base64-encoded SAML response".to_owned()))
}

fn encrypted_assertion_error(error: SamlAssertionDecryptionError) -> OpenAuthError {
    match error {
        SamlAssertionDecryptionError::Unsupported => {
            OpenAuthError::Api(ENCRYPTED_ASSERTION_UNSUPPORTED.to_owned())
        }
        other => OpenAuthError::Api(other.code().to_owned()),
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_start(
    reader: &Reader<&[u8]>,
    element: &BytesStart<'_>,
    name: &str,
    stack: &[String],
    response_destination: &mut Option<String>,
    response_in_response_to: &mut Option<String>,
    status_code: &mut Option<String>,
    assertion_id: &mut Option<String>,
    conditions: &mut Option<SamlConditions>,
    subject_confirmation: &mut Option<ParsedSubjectConfirmation>,
    session_index: &mut Option<String>,
    current_attribute: &mut Option<(String, String)>,
) -> Result<(), OpenAuthError> {
    match name {
        "Response" => {
            *response_destination = attr(reader, element, "Destination")?;
            *response_in_response_to = attr(reader, element, "InResponseTo")?;
        }
        "StatusCode" => {
            *status_code = attr(reader, element, "Value")?;
        }
        "Assertion" => {
            *assertion_id = attr(reader, element, "ID")?;
        }
        "Conditions" if stack.iter().any(|item| item == "Assertion") => {
            *conditions = Some(SamlConditions {
                not_before: attr(reader, element, "NotBefore")?,
                not_on_or_after: attr(reader, element, "NotOnOrAfter")?,
            });
        }
        "SubjectConfirmationData" => {
            *subject_confirmation = Some(ParsedSubjectConfirmation {
                recipient: attr(reader, element, "Recipient")?,
                in_response_to: attr(reader, element, "InResponseTo")?,
                conditions: Some(SamlConditions {
                    not_before: attr(reader, element, "NotBefore")?,
                    not_on_or_after: attr(reader, element, "NotOnOrAfter")?,
                }),
            });
        }
        "AuthnStatement" => {
            *session_index = attr(reader, element, "SessionIndex")?;
        }
        "Attribute" => {
            let key = attr(reader, element, "Name")?
                .or_else(|| attr(reader, element, "FriendlyName").ok().flatten());
            if let Some(key) = key {
                *current_attribute = Some((key, String::new()));
            }
        }
        _ => {}
    }
    Ok(())
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
