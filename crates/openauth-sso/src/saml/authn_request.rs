use std::io::Write;

use base64::Engine;
use flate2::{write::DeflateEncoder, Compression};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use url::Url;

use crate::options::SamlConfig;

const POST_BINDING: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlAuthnRequest {
    pub id: String,
    pub redirect_url: String,
}

pub fn build_authn_request_redirect(
    provider_id: &str,
    base_url: &str,
    config: &SamlConfig,
    request_id: String,
    relay_state: String,
) -> Result<SamlAuthnRequest, SamlAuthnRequestError> {
    let xml = authn_request_xml(provider_id, base_url, config, &request_id)?;
    let encoded = deflate_and_encode(&xml)?;
    let mut url = Url::parse(&config.entry_point)
        .map_err(|source| SamlAuthnRequestError::InvalidEntryPoint(source.to_string()))?;
    url.query_pairs_mut()
        .append_pair("SAMLRequest", &encoded)
        .append_pair("RelayState", &relay_state);
    if config.authn_requests_signed {
        url = sign_authn_request_redirect(url, config)?;
    }
    Ok(SamlAuthnRequest {
        id: request_id,
        redirect_url: url.to_string(),
    })
}

pub fn authn_request_xml(
    provider_id: &str,
    base_url: &str,
    config: &SamlConfig,
    request_id: &str,
) -> Result<String, SamlAuthnRequestError> {
    let issue_instant = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|source| SamlAuthnRequestError::Encode(source.to_string()))?;
    let acs = assertion_consumer_service_url(provider_id, base_url, config);
    let issuer = config
        .sp_metadata
        .entity_id
        .as_deref()
        .unwrap_or(config.issuer.as_str());
    let name_id_policy = config.identifier_format.as_deref().map(|format| {
        format!(
            r#"<samlp:NameIDPolicy Format="{}" AllowCreate="true"/>"#,
            escape_xml(format)
        )
    });

    Ok(format!(
        r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{}" Version="2.0" IssueInstant="{}" Destination="{}" ProtocolBinding="{}" AssertionConsumerServiceURL="{}"><saml:Issuer>{}</saml:Issuer>{}</samlp:AuthnRequest>"#,
        escape_xml(request_id),
        escape_xml(&issue_instant),
        escape_xml(&config.entry_point),
        POST_BINDING,
        escape_xml(&acs),
        escape_xml(issuer),
        name_id_policy.unwrap_or_default()
    ))
}

pub(crate) fn assertion_consumer_service_url(
    provider_id: &str,
    base_url: &str,
    config: &SamlConfig,
) -> String {
    if let Some(acs_url) = config
        .acs_url
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        acs_url.to_owned()
    } else if config.callback_url.is_empty() {
        format!(
            "{}/sso/saml2/sp/acs/{}",
            base_url.trim_end_matches('/'),
            provider_id
        )
    } else {
        config.callback_url.clone()
    }
}

fn deflate_and_encode(xml: &str) -> Result<String, SamlAuthnRequestError> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(xml.as_bytes())
        .map_err(|source| SamlAuthnRequestError::Encode(source.to_string()))?;
    let compressed = encoder
        .finish()
        .map_err(|source| SamlAuthnRequestError::Encode(source.to_string()))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(compressed))
}

#[cfg(not(feature = "saml-signed"))]
fn sign_authn_request_redirect(
    _url: Url,
    _config: &SamlConfig,
) -> Result<Url, SamlAuthnRequestError> {
    Err(SamlAuthnRequestError::SigningNotSupported)
}

#[cfg(feature = "saml-signed")]
fn sign_authn_request_redirect(
    url: Url,
    config: &SamlConfig,
) -> Result<Url, SamlAuthnRequestError> {
    let private_key = config
        .private_key
        .as_ref()
        .map(|secret| secret.expose_secret())
        .or(config
            .sp_metadata
            .private_key
            .as_ref()
            .map(|secret| secret.expose_secret()))
        .filter(|value| !value.trim().is_empty())
        .ok_or(SamlAuthnRequestError::PrivateKeyRequired)?;
    let private_key = private_key_from_pem(
        private_key,
        config
            .sp_metadata
            .private_key_pass
            .as_ref()
            .map(|secret| secret.expose_secret()),
    )?;
    samael::crypto::sign_url(url, &private_key).map_err(|error| {
        SamlAuthnRequestError::Sign(format!("failed to sign SAML AuthnRequest: {error}"))
    })
}

#[cfg(feature = "saml-signed")]
fn private_key_from_pem(
    private_key: &str,
    passphrase: Option<&str>,
) -> Result<openssl::pkey::PKey<openssl::pkey::Private>, SamlAuthnRequestError> {
    if let Some(passphrase) = passphrase.filter(|value| !value.is_empty()) {
        return openssl::pkey::PKey::private_key_from_pem_passphrase(
            private_key.as_bytes(),
            passphrase.as_bytes(),
        )
        .map_err(|error| SamlAuthnRequestError::InvalidPrivateKey(error.to_string()));
    }

    openssl::pkey::PKey::private_key_from_pem(private_key.as_bytes())
        .or_else(|_| {
            base64::engine::general_purpose::STANDARD
                .decode(private_key.split_whitespace().collect::<String>())
                .map_err(|_| openssl::error::ErrorStack::get())
                .and_then(|bytes| openssl::pkey::PKey::private_key_from_der(&bytes))
        })
        .map_err(|error| SamlAuthnRequestError::InvalidPrivateKey(error.to_string()))
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
pub enum SamlAuthnRequestError {
    #[error("invalid SAML entry point: {0}")]
    InvalidEntryPoint(String),
    #[error("failed to encode SAML AuthnRequest: {0}")]
    Encode(String),
    #[error("signed SAML AuthnRequests require SP private key support")]
    SigningNotSupported,
    #[error("signed SAML AuthnRequests require SP private key material")]
    PrivateKeyRequired,
    #[error("invalid SAML AuthnRequest private key: {0}")]
    InvalidPrivateKey(String),
    #[error("{0}")]
    Sign(String),
}
