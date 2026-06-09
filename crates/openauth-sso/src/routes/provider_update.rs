use std::sync::Arc;

use http::Method;
use openauth_core::api::{
    create_auth_endpoint, parse_request_body, AsyncAuthEndpoint, AuthEndpointOptions,
    OpenApiOperation,
};
use serde::Deserialize;
use serde_json::json;

use crate::audit;
use crate::linking_impl::validate_provider_domains;
#[cfg(feature = "oidc")]
use crate::oidc_impl::discovery::{validate_configured_oidc_endpoint_origins, validate_issuer_url};
use crate::openapi::{sso_provider_response, update_provider_body_schema};
#[cfg(feature = "saml")]
use crate::options::SamlConfig;
use crate::options::{
    OidcConfig, OidcMapping, SamlMapping, SsoAuditEvent, SsoAuditEventKind, SsoAuditSeverity,
    SsoOptions, TokenEndpointAuthentication,
};
use crate::org::{can_manage_provider, can_register_for_organization};
use crate::store::{SsoProviderStore, UpdateSsoProviderInput};
use crate::utils;

use super::support::{authenticated_user, invalid_provider_id, unauthorized, valid_provider_id};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateProviderBody {
    provider_id: String,
    issuer: Option<String>,
    domain: Option<String>,
    organization_id: Option<String>,
    oidc_config: Option<UpdateOidcConfig>,
    saml_config: Option<UpdateSamlConfig>,
}

impl UpdateProviderBody {
    fn has_update_fields(&self) -> bool {
        self.issuer.is_some()
            || self.domain.is_some()
            || self.organization_id.is_some()
            || self.oidc_config.is_some()
            || self.saml_config.is_some()
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateOidcConfig {
    client_id: Option<String>,
    client_secret: Option<String>,
    issuer: Option<String>,
    pkce: Option<bool>,
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    user_info_endpoint: Option<String>,
    token_endpoint_authentication: Option<TokenEndpointAuthentication>,
    jwks_endpoint: Option<String>,
    revocation_endpoint: Option<String>,
    end_session_endpoint: Option<String>,
    introspection_endpoint: Option<String>,
    discovery_endpoint: Option<String>,
    scopes: Option<Vec<String>>,
    mapping: Option<OidcMapping>,
    override_user_info: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(
    not(feature = "saml"),
    expect(
        dead_code,
        reason = "SAML update payload is rejected when the feature is disabled"
    )
)]
#[serde(rename_all = "camelCase")]
struct UpdateSamlConfig {
    issuer: Option<String>,
    entry_point: Option<String>,
    cert: Option<String>,
    callback_url: Option<String>,
    acs_url: Option<String>,
    audience: Option<String>,
    idp_metadata: Option<crate::options::SamlIdpMetadata>,
    sp_metadata: Option<crate::options::SamlSpMetadata>,
    mapping: Option<SamlMapping>,
    want_assertions_signed: Option<bool>,
    authn_requests_signed: Option<bool>,
    signature_algorithm: Option<String>,
    digest_algorithm: Option<String>,
    identifier_format: Option<String>,
    private_key: Option<String>,
    decryption_pvk: Option<String>,
    additional_params: Option<std::collections::BTreeMap<String, serde_json::Value>>,
}

pub(super) fn endpoint(options: Arc<SsoOptions>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/sso/update-provider",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("updateSSOProvider")
            .body_schema(update_provider_body_schema())
            .openapi(
                OpenApiOperation::new("updateSSOProvider")
                    .tag("SSO")
                    .response("200", sso_provider_response("Updated SSO provider")),
            ),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                let Some((adapter, user_id)) = authenticated_user(context, &request).await? else {
                    return unauthorized();
                };
                let body = parse_request_body::<UpdateProviderBody>(&request)?;
                if !valid_provider_id(&body.provider_id) {
                    return invalid_provider_id();
                }
                if !body.has_update_fields() {
                    return utils::json(
                        http::StatusCode::BAD_REQUEST,
                        &json!({"code": "NO_UPDATE_FIELDS"}),
                    );
                }
                let store = SsoProviderStore::new_with_options(adapter.as_ref(), &options);
                let Some(existing) = store.find_by_provider_id(&body.provider_id).await? else {
                    return utils::json(
                        http::StatusCode::NOT_FOUND,
                        &json!({"code": "PROVIDER_NOT_FOUND"}),
                    );
                };
                if !can_manage_provider(context, adapter.as_ref(), &user_id, &existing).await? {
                    return utils::json(http::StatusCode::FORBIDDEN, &json!({"code": "FORBIDDEN"}));
                }
                if let Some(issuer) = &body.issuer {
                    if url::Url::parse(issuer).is_err() {
                        return utils::json(
                            http::StatusCode::BAD_REQUEST,
                            &json!({"code": "INVALID_ISSUER", "message": "Invalid issuer. Must be a valid URL"}),
                        );
                    }
                }
                if let Some(domain) = &body.domain {
                    if !validate_provider_domains(domain) {
                        return utils::json(
                            http::StatusCode::BAD_REQUEST,
                            &json!({"code": "INVALID_DOMAIN"}),
                        );
                    }
                }
                if let Some(organization_id) = &body.organization_id {
                    if !can_register_for_organization(
                        context,
                        adapter.as_ref(),
                        &user_id,
                        organization_id,
                    )
                    .await?
                    {
                        return utils::json(
                            http::StatusCode::BAD_REQUEST,
                            &json!({
                                "code": "ORGANIZATION_MEMBERSHIP_REQUIRED",
                                "message": "You are not a member of the organization"
                            }),
                        );
                    }
                }
                let mut oidc_trust_boundary_changed = false;
                let merged_oidc_config = if let Some(update) = body.oidc_config {
                    #[cfg(not(feature = "oidc"))]
                    {
                        let _ = update;
                        return utils::json(
                            http::StatusCode::BAD_REQUEST,
                            &json!({"code": "OIDC_FEATURE_DISABLED", "message": "OIDC support is not enabled"}),
                        );
                    }
                    #[cfg(feature = "oidc")]
                    {
                        let existing_config = existing
                            .oidc_config
                            .as_deref()
                            .and_then(|value| serde_json::from_str::<OidcConfig>(value).ok());
                        let Some(existing_config) = existing_config else {
                            return utils::json(
                                http::StatusCode::BAD_REQUEST,
                                &json!({"code": "OIDC_CONFIG_NOT_CONFIGURED"}),
                            );
                        };
                        let merged = merge_oidc_config(existing_config.clone(), update);
                        oidc_trust_boundary_changed =
                            oidc_config_changes_trust_boundary(&existing_config, &merged);
                        if !is_valid_oidc_config_urls(&merged) {
                            return utils::json(
                                http::StatusCode::BAD_REQUEST,
                                &json!({"code": "INVALID_OIDC_CONFIG"}),
                            );
                        }
                        if options.oidc.strict_manual_endpoint_origins {
                            if let Err(error) =
                                validate_configured_oidc_endpoint_origins(&merged, |url| {
                                    super::oidc::is_trusted_oidc_url(context, &request, url)
                                })
                            {
                                return super::registration::oidc_discovery_error_response(error);
                            }
                        }
                        Some(serde_json::to_string(&merged).map_err(|error| {
                            openauth_core::error::OpenAuthError::Api(format!(
                                "failed to serialize OIDC config: {error}"
                            ))
                        })?)
                    }
                } else {
                    None
                };
                #[cfg(feature = "saml")]
                let mut saml_trust_boundary_changed = false;
                #[cfg(not(feature = "saml"))]
                let saml_trust_boundary_changed = false;
                let merged_saml_config = if let Some(update) = body.saml_config {
                    #[cfg(not(feature = "saml"))]
                    {
                        let _ = update;
                        return utils::json(
                            http::StatusCode::BAD_REQUEST,
                            &json!({"code": "SAML_FEATURE_DISABLED", "message": "SAML support is not enabled"}),
                        );
                    }
                    #[cfg(feature = "saml")]
                    {
                        let existing_config = existing
                            .saml_config
                            .as_deref()
                            .and_then(|value| serde_json::from_str::<SamlConfig>(value).ok());
                        let Some(existing_config) = existing_config else {
                            return utils::json(
                                http::StatusCode::BAD_REQUEST,
                                &json!({"code": "SAML_CONFIG_NOT_CONFIGURED"}),
                            );
                        };
                        let merged = match super::saml_config::normalize_saml_config(
                            merge_saml_config(existing_config.clone(), update),
                            &options,
                        ) {
                            Ok(config) => config,
                            Err(error) => return super::saml_config::error_response(error),
                        };
                        saml_trust_boundary_changed =
                            saml_config_changes_trust_boundary(&existing_config, &merged);
                        if let Err(error) =
                            super::validate_configured_saml_algorithms(&merged, &options)
                        {
                            return super::saml_algorithm_error_response(error);
                        }
                        Some(serde_json::to_string(&merged).map_err(|error| {
                            openauth_core::error::OpenAuthError::Api(format!(
                                "failed to serialize SAML config: {error}"
                            ))
                        })?)
                    }
                } else {
                    None
                };
                let issuer_changed = body
                    .issuer
                    .as_ref()
                    .is_some_and(|issuer| issuer != &existing.issuer);
                let domain_changed = body
                    .domain
                    .as_ref()
                    .is_some_and(|domain| domain != &existing.domain);
                let reset_domain_verified = options.domain_verification.enabled
                    && (issuer_changed
                        || domain_changed
                        || oidc_trust_boundary_changed
                        || saml_trust_boundary_changed);
                let was_domain_verified = existing.domain_verified.unwrap_or(false);
                let updated = store
                    .update(
                        &body.provider_id,
                        UpdateSsoProviderInput {
                            issuer: body.issuer,
                            domain: body.domain,
                            organization_id: body.organization_id,
                            oidc_config: merged_oidc_config.map(Some),
                            saml_config: merged_saml_config.map(Some),
                            domain_verified: reset_domain_verified.then_some(false),
                        },
                    )
                    .await?;
                let Some(updated) = updated else {
                    return utils::json(
                        http::StatusCode::NOT_FOUND,
                        &json!({"code": "PROVIDER_NOT_FOUND"}),
                    );
                };
                let mut event =
                    SsoAuditEvent::new(SsoAuditEventKind::ProviderUpdated, SsoAuditSeverity::Info)
                        .provider_id(updated.provider_id.clone())
                        .user_id(user_id.clone());
                if let Some(organization_id) = updated.organization_id.clone() {
                    event = event.organization_id(organization_id);
                }
                audit::emit(context, &options, event).await;
                if reset_domain_verified && was_domain_verified {
                    let mut revoked = SsoAuditEvent::new(
                        SsoAuditEventKind::DomainVerificationRevoked,
                        SsoAuditSeverity::Warn,
                    )
                    .provider_id(updated.provider_id.clone())
                    .user_id(user_id.clone())
                    .reason(domain_verification_revocation_reason(
                        issuer_changed,
                        domain_changed,
                        oidc_trust_boundary_changed,
                        saml_trust_boundary_changed,
                    ));
                    if let Some(organization_id) = updated.organization_id.clone() {
                        revoked = revoked.organization_id(organization_id);
                    }
                    audit::emit(context, &options, revoked).await;
                }
                utils::json(
                    http::StatusCode::OK,
                    &updated.sanitized_with_options(&context.base_url, Some(&options)),
                )
            })
        },
    )
}

fn domain_verification_revocation_reason(
    issuer_changed: bool,
    domain_changed: bool,
    oidc_trust_boundary_changed: bool,
    saml_trust_boundary_changed: bool,
) -> String {
    let mut reasons = Vec::new();
    if issuer_changed {
        reasons.push("issuer_changed");
    }
    if domain_changed {
        reasons.push("domain_changed");
    }
    if oidc_trust_boundary_changed {
        reasons.push("oidc_trust_boundary_changed");
    }
    if saml_trust_boundary_changed {
        reasons.push("saml_trust_boundary_changed");
    }
    reasons.join(",")
}

fn normalize_stored_oidc_endpoint(endpoint: Option<String>) -> Option<String> {
    endpoint.filter(|value| !value.is_empty())
}

fn merge_oidc_config(mut existing: OidcConfig, update: UpdateOidcConfig) -> OidcConfig {
    if let Some(value) = update.client_id {
        existing.client_id = value;
    }
    if let Some(value) = update.client_secret {
        existing.client_secret = value.into();
    }
    if let Some(value) = update.issuer {
        existing.issuer = value;
    }
    if let Some(value) = update.pkce {
        existing.pkce = value;
    }
    if update.authorization_endpoint.is_some() {
        existing.authorization_endpoint =
            normalize_stored_oidc_endpoint(update.authorization_endpoint);
    }
    if update.token_endpoint.is_some() {
        existing.token_endpoint = normalize_stored_oidc_endpoint(update.token_endpoint);
    }
    if update.user_info_endpoint.is_some() {
        existing.user_info_endpoint = normalize_stored_oidc_endpoint(update.user_info_endpoint);
    }
    if let Some(value) = update.token_endpoint_authentication {
        existing.token_endpoint_authentication = Some(value);
    }
    if update.jwks_endpoint.is_some() {
        existing.jwks_endpoint = normalize_stored_oidc_endpoint(update.jwks_endpoint);
    }
    if update.revocation_endpoint.is_some() {
        existing.revocation_endpoint = normalize_stored_oidc_endpoint(update.revocation_endpoint);
    }
    if update.end_session_endpoint.is_some() {
        existing.end_session_endpoint = normalize_stored_oidc_endpoint(update.end_session_endpoint);
    }
    if update.introspection_endpoint.is_some() {
        existing.introspection_endpoint =
            normalize_stored_oidc_endpoint(update.introspection_endpoint);
    }
    if let Some(value) = update.discovery_endpoint {
        existing.discovery_endpoint = value;
    }
    if update.scopes.is_some() {
        existing.scopes = update.scopes;
    }
    if update.mapping.is_some() {
        existing.mapping = update.mapping;
    }
    if let Some(value) = update.override_user_info {
        existing.override_user_info = value;
    }
    existing
}

#[cfg(feature = "oidc")]
fn is_valid_oidc_config_urls(config: &OidcConfig) -> bool {
    validate_issuer_url(&config.issuer).is_ok()
        && super::optional_http_url(config.authorization_endpoint.as_deref())
        && super::optional_http_url(config.token_endpoint.as_deref())
        && super::optional_http_url(config.user_info_endpoint.as_deref())
        && super::optional_http_url(config.jwks_endpoint.as_deref())
        && super::optional_http_url(config.revocation_endpoint.as_deref())
        && super::optional_http_url(config.end_session_endpoint.as_deref())
        && super::optional_http_url(config.introspection_endpoint.as_deref())
        && super::is_valid_http_url(&config.discovery_endpoint)
}

#[cfg(feature = "saml")]
fn merge_saml_config(mut existing: SamlConfig, update: UpdateSamlConfig) -> SamlConfig {
    if let Some(value) = update.issuer {
        existing.issuer = value;
    }
    if let Some(value) = update.entry_point {
        existing.entry_point = value;
    }
    if let Some(value) = update.cert {
        existing.cert = value;
    }
    if let Some(value) = update.callback_url {
        existing.callback_url = value;
    }
    if let Some(value) = update.acs_url {
        existing.acs_url = Some(value);
    }
    if let Some(value) = update.audience {
        existing.audience = Some(value);
    }
    if let Some(value) = update.idp_metadata {
        existing.idp_metadata = Some(value);
    }
    if let Some(value) = update.sp_metadata {
        existing.sp_metadata = value;
    }
    if let Some(value) = update.mapping {
        existing.mapping = Some(value);
    }
    if let Some(value) = update.want_assertions_signed {
        existing.want_assertions_signed = value;
    }
    if let Some(value) = update.authn_requests_signed {
        existing.authn_requests_signed = value;
    }
    if let Some(value) = update.signature_algorithm {
        existing.signature_algorithm = Some(value);
    }
    if let Some(value) = update.digest_algorithm {
        existing.digest_algorithm = Some(value);
    }
    if let Some(value) = update.identifier_format {
        existing.identifier_format = Some(value);
    }
    if let Some(value) = update.private_key {
        existing.private_key = Some(value.into());
    }
    if let Some(value) = update.decryption_pvk {
        existing.decryption_pvk = Some(value.into());
    }
    if let Some(value) = update.additional_params {
        existing.additional_params = Some(value);
    }
    existing
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct IdentityClaimMapping {
    id: Option<String>,
    email: Option<String>,
    email_verified: Option<String>,
}

impl IdentityClaimMapping {
    fn from_oidc(mapping: &OidcMapping) -> Self {
        Self {
            id: mapping.id.clone(),
            email: mapping.email.clone(),
            email_verified: mapping.email_verified.clone(),
        }
    }

    #[cfg(feature = "saml")]
    fn from_saml(mapping: &SamlMapping) -> Self {
        Self {
            id: mapping.id.clone(),
            email: mapping.email.clone(),
            email_verified: mapping.email_verified.clone(),
        }
    }
}

fn identity_claim_mapping_changed(
    before: &Option<OidcMapping>,
    after: &Option<OidcMapping>,
) -> bool {
    match (before, after) {
        (None, None) => false,
        (None, Some(after)) => {
            IdentityClaimMapping::from_oidc(after) != IdentityClaimMapping::default()
        }
        (Some(before), None) => {
            IdentityClaimMapping::from_oidc(before) != IdentityClaimMapping::default()
        }
        (Some(before), Some(after)) => {
            IdentityClaimMapping::from_oidc(before) != IdentityClaimMapping::from_oidc(after)
        }
    }
}

#[cfg(feature = "saml")]
fn saml_identity_claim_mapping_changed(
    before: &Option<SamlMapping>,
    after: &Option<SamlMapping>,
) -> bool {
    match (before, after) {
        (None, None) => false,
        (None, Some(after)) => {
            IdentityClaimMapping::from_saml(after) != IdentityClaimMapping::default()
        }
        (Some(before), None) => {
            IdentityClaimMapping::from_saml(before) != IdentityClaimMapping::default()
        }
        (Some(before), Some(after)) => {
            IdentityClaimMapping::from_saml(before) != IdentityClaimMapping::from_saml(after)
        }
    }
}

#[cfg(feature = "oidc")]
fn oidc_config_changes_trust_boundary(before: &OidcConfig, after: &OidcConfig) -> bool {
    before.issuer != after.issuer
        || before.discovery_endpoint != after.discovery_endpoint
        || before.authorization_endpoint != after.authorization_endpoint
        || before.token_endpoint != after.token_endpoint
        || before.user_info_endpoint != after.user_info_endpoint
        || before.jwks_endpoint != after.jwks_endpoint
        || before.client_id != after.client_id
        || before.client_secret != after.client_secret
        || before.token_endpoint_authentication != after.token_endpoint_authentication
        || before.override_user_info != after.override_user_info
        || identity_claim_mapping_changed(&before.mapping, &after.mapping)
}

#[cfg(feature = "saml")]
fn saml_config_changes_trust_boundary(before: &SamlConfig, after: &SamlConfig) -> bool {
    before.issuer != after.issuer
        || before.entry_point != after.entry_point
        || before.cert != after.cert
        || before.idp_metadata != after.idp_metadata
        || before.sp_metadata.entity_id != after.sp_metadata.entity_id
        || before.sp_metadata.metadata != after.sp_metadata.metadata
        || before.audience != after.audience
        || before.want_assertions_signed != after.want_assertions_signed
        || before.authn_requests_signed != after.authn_requests_signed
        || before.signature_algorithm != after.signature_algorithm
        || before.digest_algorithm != after.digest_algorithm
        || before.private_key != after.private_key
        || before.decryption_pvk != after.decryption_pvk
        || saml_identity_claim_mapping_changed(&before.mapping, &after.mapping)
}

#[cfg(test)]
mod trust_boundary_tests {
    use super::*;
    use openauth_oidc::SecretString;

    #[cfg(feature = "oidc")]
    fn sample_oidc_config() -> OidcConfig {
        OidcConfig {
            issuer: "https://idp.example.com".to_owned(),
            pkce: true,
            client_id: "client".to_owned(),
            client_secret: SecretString::new("secret"),
            discovery_endpoint: "https://idp.example.com/.well-known/openid-configuration"
                .to_owned(),
            authorization_endpoint: Some("https://idp.example.com/authorize".to_owned()),
            token_endpoint: Some("https://idp.example.com/token".to_owned()),
            user_info_endpoint: Some("https://idp.example.com/userinfo".to_owned()),
            jwks_endpoint: Some("https://idp.example.com/keys".to_owned()),
            revocation_endpoint: None,
            end_session_endpoint: None,
            introspection_endpoint: None,
            token_endpoint_authentication: None,
            scopes: Some(vec!["openid".to_owned()]),
            mapping: None,
            override_user_info: false,
        }
    }

    #[test]
    #[cfg(feature = "oidc")]
    fn oidc_trust_boundary_ignores_pkce_and_auxiliary_endpoints() {
        let before = sample_oidc_config();
        let mut after = before.clone();
        after.pkce = false;
        after.scopes = Some(vec!["openid".to_owned(), "profile".to_owned()]);
        after.revocation_endpoint = Some("https://idp.example.com/revoke".to_owned());
        assert!(!oidc_config_changes_trust_boundary(&before, &after));
    }

    #[test]
    #[cfg(feature = "oidc")]
    fn oidc_trust_boundary_detects_jwks_endpoint_change() {
        let before = sample_oidc_config();
        let mut after = before.clone();
        after.jwks_endpoint = Some("https://evil.example.com/keys".to_owned());
        assert!(oidc_config_changes_trust_boundary(&before, &after));
    }

    #[test]
    #[cfg(feature = "saml")]
    fn saml_trust_boundary_detects_idp_metadata_entity_id_change() {
        use crate::options::{SamlIdpMetadata, SamlSpMetadata};

        let before = SamlConfig {
            issuer: "https://sp.example.com/metadata".to_owned(),
            entry_point: "https://idp.example.com/sso".to_owned(),
            cert: "CERT".to_owned(),
            callback_url: "https://sp.example.com/acs".to_owned(),
            acs_url: None,
            audience: None,
            idp_metadata: Some(SamlIdpMetadata {
                entity_id: Some("https://idp.example.com".to_owned()),
                ..SamlIdpMetadata::default()
            }),
            sp_metadata: SamlSpMetadata {
                entity_id: Some("https://sp.example.com".to_owned()),
                ..SamlSpMetadata::default()
            },
            mapping: None,
            want_assertions_signed: true,
            authn_requests_signed: false,
            signature_algorithm: None,
            digest_algorithm: None,
            identifier_format: None,
            private_key: None,
            decryption_pvk: None,
            additional_params: None,
        };
        let mut after = before.clone();
        after.idp_metadata = Some(SamlIdpMetadata {
            entity_id: Some("https://evil.example.com".to_owned()),
            ..SamlIdpMetadata::default()
        });
        assert!(saml_config_changes_trust_boundary(&before, &after));
    }

    #[test]
    #[cfg(feature = "saml")]
    fn saml_trust_boundary_ignores_callback_url_change() {
        use crate::options::SamlSpMetadata;

        let before = SamlConfig {
            issuer: "https://sp.example.com/metadata".to_owned(),
            entry_point: "https://idp.example.com/sso".to_owned(),
            cert: "CERT".to_owned(),
            callback_url: "https://sp.example.com/acs".to_owned(),
            acs_url: None,
            audience: None,
            idp_metadata: None,
            sp_metadata: SamlSpMetadata {
                entity_id: Some("https://sp.example.com".to_owned()),
                ..SamlSpMetadata::default()
            },
            mapping: None,
            want_assertions_signed: true,
            authn_requests_signed: false,
            signature_algorithm: None,
            digest_algorithm: None,
            identifier_format: None,
            private_key: None,
            decryption_pvk: None,
            additional_params: None,
        };
        let mut after = before.clone();
        after.callback_url = "https://sp.example.com/acs/updated".to_owned();
        assert!(!saml_config_changes_trust_boundary(&before, &after));
    }
}
