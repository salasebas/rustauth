use crate::options::{SamlConfig, SsoOptions};
use crate::utils;
use serde_json::json;

#[derive(Debug)]
pub(super) enum SamlConfigValidationError {
    MetadataTooLarge { max_size: usize },
    MissingEntryPoint,
    InvalidEntryPoint,
}

pub(super) fn normalize_saml_config(
    mut config: SamlConfig,
    options: &SsoOptions,
) -> Result<SamlConfig, SamlConfigValidationError> {
    validate_metadata_size(&config, options)?;
    if super::is_valid_http_url(&config.entry_point) {
        return Ok(config);
    }
    if let Some(entry_point) = configured_idp_entry_point(&config) {
        config.entry_point = entry_point;
        return Ok(config);
    }
    if config.entry_point.trim().is_empty() {
        Err(SamlConfigValidationError::MissingEntryPoint)
    } else {
        Err(SamlConfigValidationError::InvalidEntryPoint)
    }
}

fn validate_metadata_size(
    config: &SamlConfig,
    options: &SsoOptions,
) -> Result<(), SamlConfigValidationError> {
    let Some(metadata) = config
        .idp_metadata
        .as_ref()
        .and_then(|metadata| metadata.metadata.as_ref())
    else {
        return Ok(());
    };
    if metadata.len() > options.saml.max_metadata_size {
        return Err(SamlConfigValidationError::MetadataTooLarge {
            max_size: options.saml.max_metadata_size,
        });
    }
    Ok(())
}

fn configured_idp_entry_point(config: &SamlConfig) -> Option<String> {
    let metadata = config.idp_metadata.as_ref()?;
    if let Some(location) = metadata
        .single_sign_on_service
        .as_ref()
        .and_then(|services| configured_single_sign_on_service_location(services))
    {
        return Some(location);
    }
    metadata
        .metadata
        .as_deref()
        .and_then(|xml| crate::saml_impl::metadata::first_single_sign_on_service_location(xml).ok())
        .flatten()
        .and_then(|location| valid_location(&location))
}

fn configured_single_sign_on_service_location(
    services: &[crate::options::SamlService],
) -> Option<String> {
    services
        .iter()
        .find(|service| service.binding.ends_with("HTTP-Redirect"))
        .and_then(|service| valid_location(&service.location))
        .or_else(|| {
            services
                .iter()
                .find_map(|service| valid_location(&service.location))
        })
}

fn valid_location(location: &str) -> Option<String> {
    super::is_valid_http_url(location).then(|| location.to_owned())
}

pub(super) fn error_response(
    error: SamlConfigValidationError,
) -> Result<openauth_core::api::ApiResponse, openauth_core::error::OpenAuthError> {
    match error {
        SamlConfigValidationError::MetadataTooLarge { max_size } => utils::json(
            http::StatusCode::BAD_REQUEST,
            &json!({
                "code": "SAML_METADATA_TOO_LARGE",
                "message": format!("IdP metadata exceeds maximum allowed size ({max_size} bytes)")
            }),
        ),
        SamlConfigValidationError::MissingEntryPoint => utils::json(
            http::StatusCode::BAD_REQUEST,
            &json!({
                "code": "INVALID_SAML_CONFIG",
                "message": "SAML configuration requires either idpMetadata.metadata, idpMetadata.singleSignOnService, or a valid entryPoint URL"
            }),
        ),
        SamlConfigValidationError::InvalidEntryPoint => utils::json(
            http::StatusCode::BAD_REQUEST,
            &json!({
                "code": "INVALID_SAML_CONFIG",
                "message": "SAML configuration requires a valid entryPoint URL"
            }),
        ),
    }
}
