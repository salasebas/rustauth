use std::io::{Read, Write};

use base64::Engine;
use flate2::{read::DeflateDecoder, write::DeflateEncoder, Compression};
use openauth_core::error::OpenAuthError;
use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use url::Url;

use crate::options::SamlConfig;
use crate::saml_impl::metadata::first_single_logout_service_location;
use crate::saml_impl::signature::SamlSignatureInfo;
use crate::saml_impl::xml::{local_name, validate_saml_xml};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlLogoutRequest {
    pub id: String,
    pub redirect_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlLogoutBindingResponse {
    pub id: String,
    pub binding: SamlLogoutBinding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SamlLogoutBinding {
    Redirect { url: String },
    Post { html: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlLogoutRequestInput {
    pub request_id: String,
    pub relay_state: String,
    pub name_id: String,
    pub session_index: Option<String>,
}

pub fn build_logout_request_redirect(
    config: &SamlConfig,
    input: SamlLogoutRequestInput,
) -> Result<SamlLogoutRequest, SamlLogoutRequestError> {
    let xml = logout_request_xml(config, &input)?;
    let encoded = deflate_and_encode(&xml)?;
    let logout_service_url = idp_logout_service_url(config);
    let mut url = Url::parse(&logout_service_url)
        .map_err(|source| SamlLogoutRequestError::InvalidEntryPoint(source.to_string()))?;
    url.query_pairs_mut()
        .append_pair("SAMLRequest", &encoded)
        .append_pair("RelayState", &input.relay_state);
    Ok(SamlLogoutRequest {
        id: input.request_id,
        redirect_url: url.to_string(),
    })
}

pub fn build_logout_request_binding(
    config: &SamlConfig,
    input: SamlLogoutRequestInput,
) -> Result<SamlLogoutBindingResponse, SamlLogoutRequestError> {
    let destination = idp_logout_service(config);
    let xml = logout_request_xml_for_destination(config, &input, &destination.location)?;
    let binding = if destination.binding == SamlLogoutServiceBinding::Post {
        SamlLogoutBinding::Post {
            html: post_binding_form(
                &destination.location,
                "SAMLRequest",
                &base64_xml(&xml),
                Some(&input.relay_state),
            ),
        }
    } else {
        SamlLogoutBinding::Redirect {
            url: redirect_binding_url(
                &destination.location,
                "SAMLRequest",
                &deflate_and_encode(&xml)?,
                Some(&input.relay_state),
            )?,
        }
    };
    Ok(SamlLogoutBindingResponse {
        id: input.request_id,
        binding,
    })
}

pub fn build_logout_response_redirect(
    config: &SamlConfig,
    response_id: String,
    in_response_to: &str,
    relay_state: Option<&str>,
) -> Result<SamlLogoutRequest, SamlLogoutRequestError> {
    let xml = logout_response_xml(config, &response_id, in_response_to)?;
    let encoded = deflate_and_encode(&xml)?;
    let logout_service_url = idp_logout_service_url(config);
    let mut url = Url::parse(&logout_service_url)
        .map_err(|source| SamlLogoutRequestError::InvalidEntryPoint(source.to_string()))?;
    url.query_pairs_mut().append_pair("SAMLResponse", &encoded);
    if let Some(relay_state) = relay_state.filter(|value| !value.is_empty()) {
        url.query_pairs_mut().append_pair("RelayState", relay_state);
    }
    Ok(SamlLogoutRequest {
        id: response_id,
        redirect_url: url.to_string(),
    })
}

pub fn build_logout_response_binding(
    config: &SamlConfig,
    response_id: String,
    in_response_to: &str,
    relay_state: Option<&str>,
) -> Result<SamlLogoutBindingResponse, SamlLogoutRequestError> {
    let destination = idp_logout_service(config);
    let xml = logout_response_xml_for_destination(
        config,
        &response_id,
        in_response_to,
        &destination.location,
    )?;
    let binding = if destination.binding == SamlLogoutServiceBinding::Post {
        SamlLogoutBinding::Post {
            html: post_binding_form(
                &destination.location,
                "SAMLResponse",
                &base64_xml(&xml),
                relay_state,
            ),
        }
    } else {
        SamlLogoutBinding::Redirect {
            url: redirect_binding_url(
                &destination.location,
                "SAMLResponse",
                &deflate_and_encode(&xml)?,
                relay_state,
            )?,
        }
    };
    Ok(SamlLogoutBindingResponse {
        id: response_id,
        binding,
    })
}

pub fn logout_request_xml(
    config: &SamlConfig,
    input: &SamlLogoutRequestInput,
) -> Result<String, SamlLogoutRequestError> {
    logout_request_xml_for_destination(config, input, &idp_logout_service_url(config))
}

fn logout_request_xml_for_destination(
    config: &SamlConfig,
    input: &SamlLogoutRequestInput,
    destination: &str,
) -> Result<String, SamlLogoutRequestError> {
    let issue_instant = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|source| SamlLogoutRequestError::Encode(source.to_string()))?;
    let issuer = config
        .sp_metadata
        .entity_id
        .as_deref()
        .unwrap_or(config.issuer.as_str());
    let session_index = input.session_index.as_deref().map(|value| {
        format!(
            "<samlp:SessionIndex>{}</samlp:SessionIndex>",
            escape_xml(value)
        )
    });

    Ok(format!(
        r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{}" Version="2.0" IssueInstant="{}" Destination="{}"><saml:Issuer>{}</saml:Issuer><saml:NameID>{}</saml:NameID>{}</samlp:LogoutRequest>"#,
        escape_xml(&input.request_id),
        escape_xml(&issue_instant),
        escape_xml(destination),
        escape_xml(issuer),
        escape_xml(&input.name_id),
        session_index.unwrap_or_default()
    ))
}

pub fn logout_response_xml(
    config: &SamlConfig,
    response_id: &str,
    in_response_to: &str,
) -> Result<String, SamlLogoutRequestError> {
    logout_response_xml_for_destination(
        config,
        response_id,
        in_response_to,
        &idp_logout_service_url(config),
    )
}

fn logout_response_xml_for_destination(
    config: &SamlConfig,
    response_id: &str,
    in_response_to: &str,
    destination: &str,
) -> Result<String, SamlLogoutRequestError> {
    let issue_instant = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|source| SamlLogoutRequestError::Encode(source.to_string()))?;
    let issuer = config
        .sp_metadata
        .entity_id
        .as_deref()
        .unwrap_or(config.issuer.as_str());

    Ok(format!(
        r#"<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{}" Version="2.0" IssueInstant="{}" Destination="{}" InResponseTo="{}"><saml:Issuer>{}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:LogoutResponse>"#,
        escape_xml(response_id),
        escape_xml(&issue_instant),
        escape_xml(destination),
        escape_xml(in_response_to),
        escape_xml(issuer),
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SamlLogoutServiceBinding {
    Redirect,
    Post,
}

struct SamlLogoutServiceDestination {
    binding: SamlLogoutServiceBinding,
    location: String,
}

fn idp_logout_service(config: &SamlConfig) -> SamlLogoutServiceDestination {
    config
        .idp_metadata
        .as_ref()
        .and_then(|metadata| {
            metadata
                .single_logout_service
                .as_ref()
                .and_then(|services| configured_service_destination(services))
                .or_else(|| {
                    metadata
                        .metadata
                        .as_deref()
                        .and_then(|xml| first_single_logout_service_location(xml).ok().flatten())
                        .filter(|location| is_http_url(location))
                        .map(|location| SamlLogoutServiceDestination {
                            binding: SamlLogoutServiceBinding::Redirect,
                            location,
                        })
                })
        })
        .unwrap_or_else(|| SamlLogoutServiceDestination {
            binding: SamlLogoutServiceBinding::Redirect,
            location: config.entry_point.clone(),
        })
}

fn idp_logout_service_url(config: &SamlConfig) -> String {
    idp_logout_service(config).location
}

fn configured_service_destination(
    services: &[crate::options::SamlService],
) -> Option<SamlLogoutServiceDestination> {
    let mut first = None;
    for service in services {
        if !is_http_url(&service.location) {
            continue;
        }
        if service.binding.ends_with("HTTP-Redirect") {
            return Some(SamlLogoutServiceDestination {
                binding: SamlLogoutServiceBinding::Redirect,
                location: service.location.clone(),
            });
        }
        if first.is_none() && service.binding.ends_with("HTTP-POST") {
            first = Some(SamlLogoutServiceDestination {
                binding: SamlLogoutServiceBinding::Post,
                location: service.location.clone(),
            });
        }
    }
    first
}

fn redirect_binding_url(
    destination: &str,
    message_name: &str,
    encoded_message: &str,
    relay_state: Option<&str>,
) -> Result<String, SamlLogoutRequestError> {
    let mut url = Url::parse(destination)
        .map_err(|source| SamlLogoutRequestError::InvalidEntryPoint(source.to_string()))?;
    url.query_pairs_mut()
        .append_pair(message_name, encoded_message);
    if let Some(relay_state) = relay_state.filter(|value| !value.is_empty()) {
        url.query_pairs_mut().append_pair("RelayState", relay_state);
    }
    Ok(url.to_string())
}

fn post_binding_form(
    action: &str,
    message_name: &str,
    encoded_message: &str,
    relay_state: Option<&str>,
) -> String {
    let relay_state = relay_state
        .filter(|value| !value.is_empty())
        .map(|value| {
            format!(
                r#"<input type="hidden" name="RelayState" value="{}"/>"#,
                escape_xml(value)
            )
        })
        .unwrap_or_default();
    format!(
        r#"<!doctype html><html><body onload="document.forms[0].submit()"><form method="post" action="{}"><input type="hidden" name="{}" value="{}"/>{}<noscript><button type="submit">Continue</button></noscript></form></body></html>"#,
        escape_xml(action),
        escape_xml(message_name),
        escape_xml(encoded_message),
        relay_state
    )
}

fn base64_xml(xml: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(xml.as_bytes())
}

fn is_http_url(value: &str) -> bool {
    Url::parse(value)
        .map(|url| matches!(url.scheme(), "http" | "https"))
        .unwrap_or(false)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSamlLogoutRequest {
    pub id: String,
    pub name_id: Option<String>,
    pub session_index: Option<String>,
    pub has_signature: bool,
    pub signature: SamlSignatureInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSamlLogoutResponse {
    pub in_response_to: Option<String>,
    pub status_code: Option<String>,
    pub has_signature: bool,
    pub signature: SamlSignatureInfo,
}

pub fn parse_post_logout_request(encoded: &str) -> Result<ParsedSamlLogoutRequest, OpenAuthError> {
    parse_logout_request_xml(&decode_base64_xml(encoded)?)
}

pub fn parse_post_logout_response(
    encoded: &str,
) -> Result<ParsedSamlLogoutResponse, OpenAuthError> {
    parse_logout_response_xml(&decode_base64_xml(encoded)?)
}

pub fn parse_redirect_logout_request(
    encoded: &str,
) -> Result<ParsedSamlLogoutRequest, OpenAuthError> {
    parse_logout_request_xml(&decode_redirect_xml(encoded)?)
}

pub fn parse_redirect_logout_response(
    encoded: &str,
) -> Result<ParsedSamlLogoutResponse, OpenAuthError> {
    parse_logout_response_xml(&decode_redirect_xml(encoded)?)
}

fn parse_logout_request_xml(xml: &str) -> Result<ParsedSamlLogoutRequest, OpenAuthError> {
    validate_saml_xml(xml)?;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut id = None;
    let mut name_id = None;
    let mut session_index = None;
    let mut has_signature = false;
    let mut signature = SamlSignatureInfo::default();
    let mut current_text = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) => {
                let name = local_name(element.name().as_ref())?;
                if name == "LogoutRequest" {
                    id = attribute_value(&reader, &element, "ID")?;
                } else if name == "Signature" {
                    has_signature = true;
                    signature.count += 1;
                    signature.logout_request = true;
                }
                current_text.clear();
            }
            Ok(Event::Empty(element)) => {
                let name = local_name(element.name().as_ref())?;
                if name == "LogoutRequest" {
                    id = attribute_value(&reader, &element, "ID")?;
                } else if name == "Signature" {
                    has_signature = true;
                    signature.count += 1;
                    signature.logout_request = true;
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
                match local_name(element.name().as_ref())?.as_str() {
                    "NameID" if !current_text.is_empty() => name_id = Some(current_text.clone()),
                    "SessionIndex" if !current_text.is_empty() => {
                        session_index = Some(current_text.clone());
                    }
                    _ => {}
                }
                current_text.clear();
            }
            Ok(Event::Eof) => break,
            Err(error) => return Err(OpenAuthError::Api(format!("Invalid SAML XML: {error}"))),
            _ => {}
        }
    }

    let id = id.ok_or_else(|| OpenAuthError::Api("SAML LogoutRequest missing ID".to_owned()))?;
    Ok(ParsedSamlLogoutRequest {
        id,
        name_id,
        session_index,
        has_signature,
        signature,
    })
}

fn parse_logout_response_xml(xml: &str) -> Result<ParsedSamlLogoutResponse, OpenAuthError> {
    validate_saml_xml(xml)?;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut in_response_to = None;
    let mut status_code = None;
    let mut has_signature = false;
    let mut signature = SamlSignatureInfo::default();

    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) | Ok(Event::Empty(element)) => {
                let name = local_name(element.name().as_ref())?;
                if name == "LogoutResponse" {
                    in_response_to = attribute_value(&reader, &element, "InResponseTo")?;
                } else if name == "StatusCode" {
                    status_code = attribute_value(&reader, &element, "Value")?;
                } else if name == "Signature" {
                    has_signature = true;
                    signature.count += 1;
                    signature.logout_response = true;
                }
            }
            Ok(Event::Eof) => break,
            Err(error) => return Err(OpenAuthError::Api(format!("Invalid SAML XML: {error}"))),
            _ => {}
        }
    }

    Ok(ParsedSamlLogoutResponse {
        in_response_to,
        status_code,
        has_signature,
        signature,
    })
}

fn decode_base64_xml(encoded: &str) -> Result<String, OpenAuthError> {
    let compact = encoded.split_whitespace().collect::<String>();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(compact)
        .map_err(|_| OpenAuthError::Api("Invalid base64-encoded SAML message".to_owned()))?;
    String::from_utf8(bytes)
        .map_err(|_| OpenAuthError::Api("Invalid base64-encoded SAML message".to_owned()))
}

fn decode_redirect_xml(encoded: &str) -> Result<String, OpenAuthError> {
    let compact = encoded.split_whitespace().collect::<String>();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(compact)
        .map_err(|_| OpenAuthError::Api("Invalid base64-encoded SAML message".to_owned()))?;
    let mut decoder = DeflateDecoder::new(bytes.as_slice());
    let mut xml = String::new();
    decoder
        .read_to_string(&mut xml)
        .map_err(|error| OpenAuthError::Api(format!("Invalid SAML redirect binding: {error}")))?;
    Ok(xml)
}

fn deflate_and_encode(xml: &str) -> Result<String, SamlLogoutRequestError> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(xml.as_bytes())
        .map_err(|source| SamlLogoutRequestError::Encode(source.to_string()))?;
    let compressed = encoder
        .finish()
        .map_err(|source| SamlLogoutRequestError::Encode(source.to_string()))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(compressed))
}

fn attribute_value(
    reader: &Reader<&[u8]>,
    element: &BytesStart<'_>,
    name: &str,
) -> Result<Option<String>, OpenAuthError> {
    for attr in element.attributes() {
        let attr = attr.map_err(|error| OpenAuthError::Api(error.to_string()))?;
        if local_name(attr.key.as_ref())? == name {
            return attr
                .decode_and_unescape_value(reader.decoder())
                .map(|value| Some(value.into_owned()))
                .map_err(|error| OpenAuthError::Api(error.to_string()));
        }
    }
    Ok(None)
}

fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[derive(Debug, thiserror::Error)]
pub enum SamlLogoutRequestError {
    #[error("invalid SAML logout entry point: {0}")]
    InvalidEntryPoint(String),
    #[error("failed to encode SAML LogoutRequest: {0}")]
    Encode(String),
}
