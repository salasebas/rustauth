use opensaml::constants::Binding;
use opensaml::entity::{now_iso8601, CustomTagReplacement};
use opensaml::template::replace_tags_by_value;
use url::Url;

use crate::bridge::{
    create_identity_provider, create_service_provider, opensaml_error_code, SpBuildOptions,
};
use crate::options::SamlConfig;

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
    if config.authn_requests_signed
        && config.private_key.is_none()
        && config.sp_metadata.private_key.is_none()
    {
        return Err(SamlAuthnRequestError::PrivateKeyRequired);
    }

    let sp = create_service_provider(
        config,
        base_url,
        provider_id,
        &SpBuildOptions {
            relay_state: Some(relay_state),
            ..Default::default()
        },
    )
    .map_err(map_authn_request_error)?;
    let idp = create_identity_provider(config).map_err(map_authn_request_error)?;
    let destination = idp
        .metadata
        .get_single_sign_on_service(Binding::Redirect)
        .unwrap_or_else(|| config.entry_point.clone());

    let provider_id = provider_id.to_owned();
    let base_url = base_url.to_owned();
    let config = config.clone();
    let request_id_for_custom = request_id.clone();
    let custom: CustomTagReplacement = &|template| {
        let acs = assertion_consumer_service_url(&provider_id, &base_url, &config);
        let issuer = config
            .sp_metadata
            .entity_id
            .as_deref()
            .unwrap_or(config.issuer.as_str())
            .to_owned();
        let name_id_format = config
            .identifier_format
            .clone()
            .unwrap_or_else(|| "urn:oasis:names:tc:SAML:2.0:nameid-format:transient".to_owned());
        let xml = replace_tags_by_value(
            template,
            &[
                ("ID", request_id_for_custom.clone()),
                ("IssueInstant", now_iso8601()),
                ("Destination", destination.clone()),
                ("AssertionConsumerServiceURL", acs),
                ("Issuer", issuer),
                ("NameIDFormat", name_id_format),
                ("AllowCreate", "true".to_string()),
            ],
        );
        (request_id_for_custom.clone(), xml)
    };

    let context = sp
        .create_login_request(&idp, Binding::Redirect, Some(custom))
        .map_err(map_authn_request_error)?;

    Ok(SamlAuthnRequest {
        id: request_id,
        redirect_url: context.context,
    })
}

pub fn authn_request_xml(
    provider_id: &str,
    base_url: &str,
    config: &SamlConfig,
    request_id: &str,
) -> Result<String, SamlAuthnRequestError> {
    let redirect = build_authn_request_redirect(
        provider_id,
        base_url,
        config,
        request_id.to_owned(),
        String::new(),
    )?;
    let url = Url::parse(&redirect.redirect_url)
        .map_err(|source| SamlAuthnRequestError::InvalidEntryPoint(source.to_string()))?;
    let encoded = url
        .query_pairs()
        .find(|(key, _)| key == "SAMLRequest")
        .map(|(_, value)| value.into_owned())
        .ok_or_else(|| SamlAuthnRequestError::Encode("missing SAMLRequest".to_owned()))?;
    decode_redirect_authn_request(&encoded)
}

pub fn assertion_consumer_service_url(
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

fn decode_redirect_authn_request(encoded: &str) -> Result<String, SamlAuthnRequestError> {
    let bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        encoded.as_bytes(),
    )
    .map_err(|source| SamlAuthnRequestError::Encode(source.to_string()))?;
    let mut decoder = flate2::read::DeflateDecoder::new(bytes.as_slice());
    let mut xml = String::new();
    std::io::Read::read_to_string(&mut decoder, &mut xml)
        .map_err(|source| SamlAuthnRequestError::Encode(source.to_string()))?;
    Ok(xml)
}

fn map_authn_request_error(error: opensaml::error::OpenSamlError) -> SamlAuthnRequestError {
    match &error {
        opensaml::error::OpenSamlError::MissingKey(_) => SamlAuthnRequestError::PrivateKeyRequired,
        opensaml::error::OpenSamlError::Unsupported(_) => {
            SamlAuthnRequestError::SigningNotSupported
        }
        opensaml::error::OpenSamlError::Invalid(message) if message.contains("ENTRY_POINT") => {
            SamlAuthnRequestError::InvalidEntryPoint(message.clone())
        }
        other => SamlAuthnRequestError::Sign(format!("{other} ({})", opensaml_error_code(other))),
    }
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
