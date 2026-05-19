use std::sync::Arc;

mod domain_verification;
mod oidc;
mod provider_update;
mod providers;
mod registration;
mod saml_acs;
mod saml_config;
mod saml_metadata;
mod sign_in;
mod slo;
mod support;

use http::Method;
use openauth_core::api::AsyncAuthEndpoint;
use serde_json::json;

use crate::options::{SamlConfig, SsoOptions};
use crate::saml::security::{validate_saml_config_algorithms_with_policy, SamlSecurityError};
use crate::saml::signature::SamlSignatureValidationError;
use crate::utils;

pub fn endpoints(options: Arc<SsoOptions>) -> Vec<AsyncAuthEndpoint> {
    let mut endpoints = vec![
        saml_metadata::endpoint(Arc::clone(&options)),
        registration::endpoint(Arc::clone(&options)),
        sign_in::endpoint(Arc::clone(&options)),
        oidc::callback_endpoint(Arc::clone(&options), "/sso/callback/:providerId"),
        oidc::callback_endpoint(Arc::clone(&options), "/sso/callback"),
        saml_acs::get_callback_endpoint(),
        saml_acs::endpoint(
            Arc::clone(&options),
            "/sso/saml2/callback/:providerId",
            "handleSAMLCallback",
        ),
        saml_acs::endpoint(
            Arc::clone(&options),
            "/sso/saml2/sp/acs/:providerId",
            "handleSAMLAssertionConsumerService",
        ),
        slo::endpoint(Arc::clone(&options), Method::GET),
        slo::endpoint(Arc::clone(&options), Method::POST),
        slo::logout_endpoint(Arc::clone(&options)),
        providers::list_endpoint(Arc::clone(&options)),
        providers::get_endpoint(Arc::clone(&options)),
        provider_update::endpoint(Arc::clone(&options)),
        providers::delete_endpoint(Arc::clone(&options)),
    ];
    if options.domain_verification.enabled {
        endpoints.push(domain_verification::request_endpoint(Arc::clone(&options)));
        endpoints.push(domain_verification::verify_endpoint(Arc::clone(&options)));
    }
    endpoints
}
pub(super) fn saml_signature_error_response(
    error: SamlSignatureValidationError,
) -> Result<openauth_core::api::ApiResponse, openauth_core::error::OpenAuthError> {
    utils::json(
        http::StatusCode::BAD_REQUEST,
        &json!({"code": error.code()}),
    )
}
fn optional_http_url(value: Option<&str>) -> bool {
    value.map(is_valid_http_url).unwrap_or(true)
}

fn is_valid_http_url(value: &str) -> bool {
    url::Url::parse(value)
        .map(|url| matches!(url.scheme(), "http" | "https"))
        .unwrap_or(false)
}

fn validate_configured_saml_algorithms(
    config: &SamlConfig,
    options: &SsoOptions,
) -> Result<(), SamlSecurityError> {
    validate_saml_config_algorithms_with_policy(
        config.signature_algorithm.as_deref(),
        config.digest_algorithm.as_deref(),
        options.saml.algorithms.on_deprecated,
        options
            .saml
            .algorithms
            .allowed_signature_algorithms
            .as_deref(),
        options.saml.algorithms.allowed_digest_algorithms.as_deref(),
    )
}

fn saml_algorithm_error_response(
    error: SamlSecurityError,
) -> Result<openauth_core::api::ApiResponse, openauth_core::error::OpenAuthError> {
    match error {
        SamlSecurityError::UnknownSignatureAlgorithm(algorithm)
        | SamlSecurityError::UnknownDigestAlgorithm(algorithm) => utils::json(
            http::StatusCode::BAD_REQUEST,
            &json!({
                "code": "SAML_UNKNOWN_ALGORITHM",
                "message": format!("SAML algorithm not recognized: {algorithm}")
            }),
        ),
        SamlSecurityError::DeprecatedSignatureAlgorithm(algorithm)
        | SamlSecurityError::DeprecatedDigestAlgorithm(algorithm) => utils::json(
            http::StatusCode::BAD_REQUEST,
            &json!({
                "code": "SAML_DEPRECATED_CONFIG_ALGORITHM",
                "message": format!("SAML config uses deprecated algorithm: {algorithm}")
            }),
        ),
        SamlSecurityError::SignatureAlgorithmNotAllowed(algorithm)
        | SamlSecurityError::DigestAlgorithmNotAllowed(algorithm) => utils::json(
            http::StatusCode::BAD_REQUEST,
            &json!({
                "code": "SAML_ALGORITHM_NOT_ALLOWED",
                "message": format!("SAML algorithm not in allow-list: {algorithm}")
            }),
        ),
        other => utils::json(
            http::StatusCode::BAD_REQUEST,
            &json!({
                "code": "INVALID_SAML_CONFIG",
                "message": other.to_string()
            }),
        ),
    }
}

fn saml_runtime_algorithm_error_code(error: &SamlSecurityError) -> &'static str {
    match error {
        SamlSecurityError::UnknownSignatureAlgorithm(_)
        | SamlSecurityError::UnknownDigestAlgorithm(_)
        | SamlSecurityError::UnknownKeyEncryptionAlgorithm(_)
        | SamlSecurityError::UnknownDataEncryptionAlgorithm(_) => "SAML_UNKNOWN_ALGORITHM",
        SamlSecurityError::DeprecatedSignatureAlgorithm(_)
        | SamlSecurityError::DeprecatedDigestAlgorithm(_)
        | SamlSecurityError::DeprecatedKeyEncryptionAlgorithm(_)
        | SamlSecurityError::DeprecatedDataEncryptionAlgorithm(_) => {
            "SAML_DEPRECATED_RUNTIME_ALGORITHM"
        }
        SamlSecurityError::SignatureAlgorithmNotAllowed(_)
        | SamlSecurityError::DigestAlgorithmNotAllowed(_)
        | SamlSecurityError::KeyEncryptionAlgorithmNotAllowed(_)
        | SamlSecurityError::DataEncryptionAlgorithmNotAllowed(_) => "SAML_ALGORITHM_NOT_ALLOWED",
        _ => "INVALID_SAML_RESPONSE",
    }
}
