//! Maps OpenAuth [`SamlConfig`] to [`opensaml`] entities (upstream `helpers.ts` parity).

use std::time::Duration;

use opensaml::constants::signature_algorithm;
use opensaml::constants::Binding;
use opensaml::entity::EntitySetting;
#[cfg(feature = "saml-signed")]
use opensaml::entity::{BindingContext, User};
use opensaml::error::OpenSamlError;
#[cfg(feature = "saml-signed")]
use opensaml::flow::{flow, FlowOptions, FlowResult, HttpRequest};
use opensaml::idp::IdentityProvider;
#[cfg(feature = "saml-signed")]
use opensaml::logout::{
    create_logout_request_with_id, create_logout_response_with_id, parse_logout_request,
    parse_logout_response,
};
use opensaml::metadata::{Endpoint, IdpMetadataConfig, SpMetadataConfig};
use opensaml::sp::ServiceProvider;
#[cfg(feature = "saml-signed")]
use opensaml::util::Value;

use crate::options::SamlConfig;
use crate::saml_impl::authn_request::assertion_consumer_service_url;
#[cfg(feature = "saml-signed")]
use crate::saml_impl::security::SamlConditions;

/// Runtime inputs when building a service provider entity.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpBuildOptions {
    pub relay_state: Option<String>,
    pub clock_skew: Duration,
    pub single_logout_enabled: bool,
    pub want_logout_request_signed: bool,
    pub want_logout_response_signed: bool,
}

/// Stable OpenAuth error code for an [`OpenSamlError`].
pub fn opensaml_error_code(error: &OpenSamlError) -> &'static str {
    match error {
        OpenSamlError::FailedToVerifySignature
        | OpenSamlError::FailedMessageSignatureVerification
        | OpenSamlError::PotentialWrappingAttack
        | OpenSamlError::UnmatchCertificate => "SAML_SIGNATURE_INVALID",
        OpenSamlError::MissingKey(_) | OpenSamlError::MissingMetadata(_) => {
            "SAML_CERTIFICATE_REQUIRED"
        }
        OpenSamlError::Unsupported(_) => "SAML_SIGNATURE_VALIDATION_NOT_IMPLEMENTED",
        OpenSamlError::InvalidInResponseTo => "INVALID_SAML_STATE",
        OpenSamlError::UnmatchIssuer | OpenSamlError::UnmatchAudience => "INVALID_SAML_RESPONSE",
        OpenSamlError::ExpiredSession | OpenSamlError::SubjectUnconfirmed => {
            "INVALID_SAML_RESPONSE"
        }
        OpenSamlError::Crypto(_) => "SAML_ASSERTION_DECRYPTION_FAILED",
        OpenSamlError::UndefinedStatus
        | OpenSamlError::FailedStatus { .. }
        | OpenSamlError::Invalid(_)
        | OpenSamlError::Xml(_)
        | OpenSamlError::Deflate(_)
        | OpenSamlError::Base64(_)
        | OpenSamlError::UndefinedBinding
        | OpenSamlError::MissingSigAlg => "INVALID_SAML_RESPONSE",
        _ => "INVALID_SAML_RESPONSE",
    }
}

pub fn create_service_provider(
    config: &SamlConfig,
    base_url: &str,
    provider_id: &str,
    opts: &SpBuildOptions,
) -> Result<ServiceProvider, OpenSamlError> {
    if let Some(metadata) = config
        .sp_metadata
        .metadata
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        return ServiceProvider::from_metadata(metadata, sp_entity_setting(config, opts));
    }

    let acs = assertion_consumer_service_url(provider_id, base_url, config);
    let mut slo = Vec::new();
    if opts.single_logout_enabled {
        let slo_url = format!(
            "{}/sso/saml2/sp/slo/{}",
            base_url.trim_end_matches('/'),
            provider_id
        );
        slo.push(Endpoint::new(Binding::Post, slo_url.clone()));
        slo.push(Endpoint::new(Binding::Redirect, slo_url));
    }

    let entity_id = config
        .sp_metadata
        .entity_id
        .as_deref()
        .unwrap_or(config.issuer.as_str())
        .to_owned();

    let mut name_id_format = Vec::new();
    if let Some(format) = &config.identifier_format {
        name_id_format.push(format.clone());
    }

    ServiceProvider::from_config(
        &SpMetadataConfig {
            entity_id,
            signing_certs: sp_signing_certs(config),
            encrypt_certs: Vec::new(),
            authn_requests_signed: config.authn_requests_signed,
            want_assertions_signed: config.want_assertions_signed,
            name_id_format,
            single_logout_service: slo,
            assertion_consumer_service: vec![Endpoint::new(Binding::Post, acs)],
            elements_order: None,
        },
        sp_entity_setting(config, opts),
    )
}

pub fn create_identity_provider(config: &SamlConfig) -> Result<IdentityProvider, OpenSamlError> {
    if let Some(metadata) = config
        .idp_metadata
        .as_ref()
        .and_then(|idp| idp.metadata.as_deref())
        .filter(|value| !value.trim().is_empty())
    {
        return IdentityProvider::from_metadata(metadata, idp_entity_setting(config));
    }

    let entity_id = idp_entity_id(config);

    let mut single_sign_on_service = Vec::new();
    if let Some(services) = config
        .idp_metadata
        .as_ref()
        .and_then(|idp| idp.single_sign_on_service.as_ref())
    {
        for service in services {
            if let Some(binding) = binding_from_urn(&service.binding) {
                single_sign_on_service.push(Endpoint::new(binding, service.location.clone()));
            }
        }
    }
    if single_sign_on_service.is_empty() && !config.entry_point.is_empty() {
        single_sign_on_service.push(Endpoint::new(Binding::Redirect, config.entry_point.clone()));
    }

    let mut single_logout_service = idp_logout_endpoints(config);
    if single_logout_service.is_empty() && !config.entry_point.is_empty() {
        single_logout_service.push(Endpoint::new(Binding::Redirect, config.entry_point.clone()));
    }

    IdentityProvider::from_config(
        &IdpMetadataConfig {
            entity_id,
            signing_certs: idp_signing_certs(config),
            encrypt_certs: Vec::new(),
            want_authn_requests_signed: config.authn_requests_signed,
            name_id_format: Vec::new(),
            single_sign_on_service,
            single_logout_service,
        },
        idp_entity_setting(config),
    )
}

#[cfg(feature = "saml-signed")]
pub fn parse_login_response(
    sp: &ServiceProvider,
    idp: &IdentityProvider,
    encoded_response: &str,
    in_response_to: Option<&str>,
    check_signature: bool,
) -> Result<FlowResult, OpenSamlError> {
    let compact = encoded_response.split_whitespace().collect::<String>();
    let request = HttpRequest::post(vec![("SAMLResponse".to_owned(), compact.clone())]);
    let signing_certs = idp
        .metadata
        .x509_certificates(opensaml::constants::CertUse::Signing);
    let encrypted = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        compact.as_bytes(),
    )
    .ok()
    .and_then(|bytes| String::from_utf8(bytes).ok())
    .is_some_and(|xml| xml.contains("EncryptedAssertion"));
    let decrypt_key = if encrypted {
        sp.setting.enc_private_key.as_deref()
    } else {
        None
    };
    let audience = sp
        .setting
        .entity_id
        .clone()
        .or_else(|| sp.metadata.get_entity_id().map(str::to_string))
        .unwrap_or_default();

    flow(
        &FlowOptions {
            binding: Some(Binding::Post),
            parser_type: Some(opensaml::constants::ParserType::SamlResponse),
            check_signature,
            from_issuer: idp.metadata.get_entity_id(),
            signing_certs: &signing_certs,
            decrypt_key,
            decrypt_key_pass: decrypt_key.and(sp.setting.enc_private_key_pass.as_deref()),
            clock_drifts: sp.setting.clock_drifts,
            expected_audience: sp.setting.validate_audience.then_some(audience.as_str()),
            expected_in_response_to: in_response_to.filter(|value| !value.is_empty()),
        },
        &request,
    )
}

#[cfg(feature = "saml-signed")]
fn sp_has_signing_key(config: &SamlConfig) -> bool {
    config.private_key.is_some() || config.sp_metadata.private_key.is_some()
}

/// Build an outbound SP-initiated [`LogoutRequest`] via opensaml.
#[cfg(feature = "saml-signed")]
#[allow(clippy::too_many_arguments)]
pub fn build_sp_logout_request(
    config: &SamlConfig,
    base_url: &str,
    provider_id: &str,
    opts: &SpBuildOptions,
    request_id: &str,
    name_id: &str,
    session_index: Option<&str>,
    relay_state: Option<&str>,
    binding: Binding,
) -> Result<BindingContext, OpenSamlError> {
    let sp = create_service_provider(config, base_url, provider_id, opts)?;
    let idp = create_identity_provider(config)?;
    create_logout_request_with_id(
        &sp.setting,
        &sp.metadata,
        &idp.metadata,
        binding,
        &User {
            name_id: name_id.to_owned(),
            session_index: session_index.map(str::to_owned),
            attributes: Vec::new(),
        },
        relay_state,
        sp_has_signing_key(config),
        Some(request_id),
    )
}

/// Build an outbound SP [`LogoutResponse`] via opensaml.
#[cfg(feature = "saml-signed")]
#[allow(clippy::too_many_arguments)]
pub fn build_sp_logout_response(
    config: &SamlConfig,
    base_url: &str,
    provider_id: &str,
    opts: &SpBuildOptions,
    response_id: &str,
    in_response_to: &str,
    relay_state: Option<&str>,
    binding: Binding,
) -> Result<BindingContext, OpenSamlError> {
    let sp = create_service_provider(config, base_url, provider_id, opts)?;
    let idp = create_identity_provider(config)?;
    create_logout_response_with_id(
        &sp.setting,
        &sp.metadata,
        &idp.metadata,
        binding,
        Some(in_response_to),
        relay_state,
        sp_has_signing_key(config),
        Some(response_id),
    )
}

/// Parse an inbound IdP-originated [`LogoutRequest`] at this SP.
#[cfg(feature = "saml-signed")]
pub fn parse_inbound_logout_request(
    config: &SamlConfig,
    base_url: &str,
    provider_id: &str,
    opts: &SpBuildOptions,
    binding: Binding,
    request: &HttpRequest,
) -> Result<FlowResult, OpenSamlError> {
    let sp = create_service_provider(config, base_url, provider_id, opts)?;
    let idp = create_identity_provider(config)?;
    parse_logout_request(&sp.setting, &idp.metadata, binding, request)
}

/// Parse an inbound IdP-originated [`LogoutResponse`] at this SP.
#[cfg(feature = "saml-signed")]
pub fn parse_inbound_logout_response(
    config: &SamlConfig,
    base_url: &str,
    provider_id: &str,
    opts: &SpBuildOptions,
    binding: Binding,
    request: &HttpRequest,
) -> Result<FlowResult, OpenSamlError> {
    let sp = create_service_provider(config, base_url, provider_id, opts)?;
    let idp = create_identity_provider(config)?;
    parse_logout_response(&sp.setting, &idp.metadata, binding, request)
}

#[cfg(feature = "saml-signed")]
pub fn map_flow_to_conditions(extract: &Value) -> Option<SamlConditions> {
    let conditions = extract.get("conditions")?;
    Some(SamlConditions {
        not_before: conditions.get_str("notBefore").map(str::to_owned),
        not_on_or_after: conditions.get_str("notOnOrAfter").map(str::to_owned),
    })
}

#[cfg(feature = "saml-signed")]
pub fn map_flow_attributes(extract: &Value) -> std::collections::BTreeMap<String, String> {
    let mut attributes = std::collections::BTreeMap::new();
    let Some(Value::Object(entries)) = extract.get("attributes") else {
        return attributes;
    };
    for (key, value) in entries {
        let mapped = match value {
            Value::Str(text) => text.clone(),
            Value::Array(items) => items
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(","),
            _ => continue,
        };
        attributes.insert(key.clone(), mapped);
    }
    attributes
}

#[cfg(feature = "saml-signed")]
pub fn assertion_id_from_saml_content(xml: &str) -> Option<String> {
    let field = opensaml::xml::ExtractorField::new("id", &["Response", "Assertion"]).attrs(&["ID"]);
    opensaml::xml::extract(xml, std::slice::from_ref(&field))
        .ok()
        .and_then(|value| value.get_str("id").map(str::to_owned))
}

fn sp_entity_setting(config: &SamlConfig, opts: &SpBuildOptions) -> EntitySetting {
    let skew_ms = opts.clock_skew.as_millis().min(i64::MAX as u128) as i64;
    let mut setting = EntitySetting {
        entity_id: config
            .sp_metadata
            .entity_id
            .clone()
            .or_else(|| Some(config.issuer.clone())),
        request_signature_algorithm: resolve_signature_algorithm(config),
        authn_requests_signed: config.authn_requests_signed,
        want_assertions_signed: config.want_assertions_signed,
        want_message_signed: config.want_assertions_signed,
        want_logout_request_signed: opts.want_logout_request_signed,
        want_logout_response_signed: opts.want_logout_response_signed,
        is_assertion_encrypted: config.sp_metadata.is_assertion_encrypted.unwrap_or(false),
        private_key: secret_to_string(config.private_key.as_ref())
            .or_else(|| secret_to_string(config.sp_metadata.private_key.as_ref())),
        private_key_pass: secret_to_string(config.sp_metadata.private_key_pass.as_ref()),
        signing_cert: sp_signing_certs(config).into_iter().next(),
        enc_private_key: secret_to_string(config.decryption_pvk.as_ref())
            .or_else(|| secret_to_string(config.sp_metadata.enc_private_key.as_ref())),
        enc_private_key_pass: secret_to_string(config.sp_metadata.enc_private_key_pass.as_ref()),
        clock_drifts: (-skew_ms, skew_ms),
        relay_state: opts.relay_state.clone().unwrap_or_default(),
        ..EntitySetting::default()
    };
    if let Some(format) = &config.identifier_format {
        setting.name_id_format = vec![format.clone()];
    }
    setting.logout_request_template = Some(
        concat!(
            r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" "#,
            r#"xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" "#,
            r#"IssueInstant="{IssueInstant}" Destination="{Destination}">"#,
            r#"<saml:Issuer>{Issuer}</saml:Issuer><saml:NameID>{NameID}</saml:NameID>"#,
            r#"<samlp:SessionIndex>{SessionIndex}</samlp:SessionIndex></samlp:LogoutRequest>"#
        )
        .to_owned(),
    );
    setting
}

fn idp_entity_setting(config: &SamlConfig) -> EntitySetting {
    EntitySetting {
        entity_id: config
            .idp_metadata
            .as_ref()
            .and_then(|idp| idp.entity_id.clone())
            .or_else(|| Some(config.issuer.clone())),
        want_authn_requests_signed: config.authn_requests_signed,
        ..EntitySetting::default()
    }
}

fn sp_signing_certs(config: &SamlConfig) -> Vec<String> {
    if config.cert.is_empty() {
        Vec::new()
    } else {
        vec![config.cert.clone()]
    }
}

fn idp_signing_certs(config: &SamlConfig) -> Vec<String> {
    if let Some(cert) = config
        .idp_metadata
        .as_ref()
        .and_then(|idp| idp.cert.as_deref())
        .filter(|cert| !cert.is_empty())
    {
        return vec![cert.to_owned()];
    }
    if !config.cert.is_empty() {
        return vec![config.cert.clone()];
    }
    Vec::new()
}

fn idp_logout_endpoints(config: &SamlConfig) -> Vec<Endpoint> {
    let Some(services) = config
        .idp_metadata
        .as_ref()
        .and_then(|idp| idp.single_logout_service.as_ref())
    else {
        return Vec::new();
    };
    services
        .iter()
        .filter_map(|service| {
            binding_from_urn(&service.binding)
                .map(|binding| Endpoint::new(binding, service.location.clone()))
        })
        .collect()
}

fn binding_from_urn(urn: &str) -> Option<Binding> {
    if urn.ends_with("HTTP-Redirect") {
        Some(Binding::Redirect)
    } else if urn.ends_with("HTTP-POST") {
        Some(Binding::Post)
    } else {
        None
    }
}

fn idp_entity_id(config: &SamlConfig) -> String {
    config
        .idp_metadata
        .as_ref()
        .and_then(|idp| idp.entity_id.clone())
        .or_else(|| idp_entity_id_from_entry_point(&config.entry_point))
        .unwrap_or_else(|| config.issuer.clone())
}

fn idp_entity_id_from_entry_point(entry_point: &str) -> Option<String> {
    let url = url::Url::parse(entry_point).ok()?;
    let host = url.host_str()?;
    Some(format!("{}://{}", url.scheme(), host))
}

fn resolve_signature_algorithm(config: &SamlConfig) -> String {
    match config.signature_algorithm.as_deref() {
        Some(value) if value.contains("://") => value.to_owned(),
        Some("sha256") | Some("SHA256") | Some("rsa-sha256") => {
            signature_algorithm::RSA_SHA256.to_owned()
        }
        Some("sha1") | Some("SHA1") | Some("rsa-sha1") => signature_algorithm::RSA_SHA1.to_owned(),
        Some("sha512") | Some("SHA512") | Some("rsa-sha512") => {
            signature_algorithm::RSA_SHA512.to_owned()
        }
        Some(other) => other.to_owned(),
        None => signature_algorithm::RSA_SHA256.to_owned(),
    }
}

fn secret_to_string(secret: Option<&openauth_core::secret::SecretString>) -> Option<String> {
    secret.map(|value| value.expose_secret().to_owned())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn authn_request_for_post_slo_provider_config() {
        use crate::options::{SamlIdpMetadata, SamlService, SamlSpMetadata};
        use crate::saml_impl::authn_request::build_authn_request_redirect;

        let config = SamlConfig {
            issuer: "https://app.example.com/sso/saml2/sp/metadata".to_owned(),
            entry_point: "https://idp.example.com/saml/sso".to_owned(),
            cert: "CERTIFICATE".to_owned(),
            callback_url: "https://app.example.com/sso/saml2/sp/acs/saml-okta".to_owned(),
            acs_url: None,
            audience: None,
            idp_metadata: Some(SamlIdpMetadata {
                single_logout_service: Some(vec![SamlService {
                    binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".to_owned(),
                    location: "https://idp.example.com/saml/slo-post?tenant=acme".to_owned(),
                }]),
                ..Default::default()
            }),
            sp_metadata: SamlSpMetadata {
                entity_id: Some("https://app.example.com/saml/sp".to_owned()),
                ..Default::default()
            },
            mapping: None,
            want_assertions_signed: false,
            authn_requests_signed: false,
            signature_algorithm: None,
            digest_algorithm: None,
            identifier_format: None,
            private_key: None,
            decryption_pvk: None,
            additional_params: None,
        };
        let result = build_authn_request_redirect(
            "saml-okta",
            "https://app.example.com",
            &config,
            "id-test".to_owned(),
            "id-test".to_owned(),
        );
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn create_sp_from_minimal_config() {
        use crate::options::SamlSpMetadata;

        let config = SamlConfig {
            issuer: "https://sp.example.com".to_owned(),
            entry_point: "https://idp.example.com/sso".to_owned(),
            cert: "CERT".to_owned(),
            callback_url: "https://sp.example.com/acs".to_owned(),
            acs_url: None,
            audience: None,
            idp_metadata: None,
            sp_metadata: SamlSpMetadata {
                entity_id: Some("https://sp.example.com".to_owned()),
                ..Default::default()
            },
            mapping: None,
            want_assertions_signed: false,
            authn_requests_signed: false,
            signature_algorithm: None,
            digest_algorithm: None,
            identifier_format: None,
            private_key: None,
            decryption_pvk: None,
            additional_params: None,
        };
        let sp = create_service_provider(
            &config,
            "https://app.example.com",
            "provider-1",
            &SpBuildOptions::default(),
        )
        .expect("sp");
        assert_eq!(sp.metadata.get_entity_id(), Some("https://sp.example.com"));
    }

    #[cfg(feature = "saml-signed")]
    #[test]
    fn build_logout_request_includes_session_index() {
        use std::io::Read;

        use crate::options::SamlSpMetadata;
        use base64::Engine;

        let config = SamlConfig {
            issuer: "https://app.example.com/sso/saml2/sp/metadata".to_owned(),
            entry_point: "https://idp.example.com/saml/sso".to_owned(),
            cert: "CERTIFICATE".to_owned(),
            callback_url: "https://app.example.com/sso/saml2/sp/acs/saml-okta".to_owned(),
            acs_url: None,
            audience: None,
            idp_metadata: None,
            sp_metadata: SamlSpMetadata {
                entity_id: Some("https://app.example.com/saml/sp".to_owned()),
                ..Default::default()
            },
            mapping: None,
            want_assertions_signed: false,
            authn_requests_signed: false,
            signature_algorithm: None,
            digest_algorithm: None,
            identifier_format: None,
            private_key: None,
            decryption_pvk: None,
            additional_params: None,
        };
        let ctx = build_sp_logout_request(
            &config,
            "https://app.example.com",
            "saml-okta",
            &SpBuildOptions::default(),
            "logout-req-test-id",
            "user@example.com",
            Some("session-1"),
            Some("/done"),
            Binding::Redirect,
        )
        .expect("logout request");
        let url = url::Url::parse(&ctx.context).expect("redirect url");
        let encoded = url
            .query_pairs()
            .find(|(key, _)| key == "SAMLRequest")
            .map(|(_, value)| value.into_owned())
            .expect("SAMLRequest");
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .expect("base64 decode");
        let mut xml = String::new();
        flate2::read::DeflateDecoder::new(bytes.as_slice())
            .read_to_string(&mut xml)
            .expect("deflate");
        assert!(xml.contains("<samlp:SessionIndex>session-1</samlp:SessionIndex>"));
        assert!(xml.contains("user@example.com"));
        assert!(xml.contains(r#"ID="logout-req-test-id""#));
        assert_eq!(ctx.id, "logout-req-test-id");
    }
}
