use opensaml::constants::Binding;
use opensaml::metadata::{generate_sp_metadata, Endpoint, IdpMetadata, SpMetadataConfig};

use crate::options::SamlConfig;
use crate::saml_impl::authn_request::assertion_consumer_service_url;
use crate::saml_impl::xml::validate_saml_xml;
use rustauth_core::error::RustAuthError;

pub fn service_provider_metadata(
    provider_id: &str,
    base_url: &str,
    config: &SamlConfig,
    single_logout_enabled: bool,
) -> String {
    if let Some(metadata) = config
        .sp_metadata
        .metadata
        .as_deref()
        .filter(|metadata| !metadata.trim().is_empty())
    {
        return metadata.to_owned();
    }

    let entity_id = config
        .sp_metadata
        .entity_id
        .as_deref()
        .unwrap_or(config.issuer.as_str())
        .to_owned();
    let acs = assertion_consumer_service_url(provider_id, base_url, config);
    let mut name_id_format = Vec::new();
    if let Some(format) = &config.identifier_format {
        name_id_format.push(format.clone());
    }
    let mut single_logout_service = Vec::new();
    if single_logout_enabled {
        let slo_url = format!(
            "{}/sso/saml2/sp/slo/{}",
            base_url.trim_end_matches('/'),
            provider_id
        );
        single_logout_service.push(Endpoint::new(Binding::Post, slo_url.clone()));
        single_logout_service.push(Endpoint::new(Binding::Redirect, slo_url));
    }

    generate_sp_metadata(&SpMetadataConfig {
        entity_id,
        signing_certs: if config.cert.is_empty() {
            Vec::new()
        } else {
            vec![config.cert.clone()]
        },
        encrypt_certs: Vec::new(),
        authn_requests_signed: config.authn_requests_signed,
        want_assertions_signed: config.want_assertions_signed,
        name_id_format,
        single_logout_service,
        assertion_consumer_service: vec![Endpoint::new(Binding::Post, acs)],
        elements_order: None,
    })
}

pub fn first_single_sign_on_service_location(xml: &str) -> Result<Option<String>, RustAuthError> {
    validate_saml_xml(xml)?;
    Ok(IdpMetadata::from_xml(xml)
        .ok()
        .and_then(|metadata| metadata.get_single_sign_on_service(Binding::Redirect))
        .or_else(|| {
            IdpMetadata::from_xml(xml)
                .ok()
                .and_then(|metadata| metadata.get_single_sign_on_service(Binding::Post))
        }))
}

pub fn first_single_logout_service_location(xml: &str) -> Result<Option<String>, RustAuthError> {
    validate_saml_xml(xml)?;
    Ok(IdpMetadata::from_xml(xml)
        .ok()
        .and_then(|metadata| metadata.get_single_logout_service(Binding::Redirect))
        .or_else(|| {
            IdpMetadata::from_xml(xml)
                .ok()
                .and_then(|metadata| metadata.get_single_logout_service(Binding::Post))
        }))
}
