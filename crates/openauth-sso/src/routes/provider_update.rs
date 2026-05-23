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
use crate::options::{
    OidcConfig, OidcMapping, SamlConfig, SamlMapping, SsoAuditEvent, SsoAuditEventKind,
    SsoAuditSeverity, SsoOptions, TokenEndpointAuthentication,
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
                        let merged = merge_oidc_config(existing_config, update);
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
                            merge_saml_config(existing_config, update),
                            &options,
                        ) {
                            Ok(config) => config,
                            Err(error) => return super::saml_config::error_response(error),
                        };
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
                let reset_domain_verified = options.domain_verification.enabled
                    && (body.issuer.is_some() || body.domain.is_some());
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
                        .user_id(user_id);
                if let Some(organization_id) = updated.organization_id.clone() {
                    event = event.organization_id(organization_id);
                }
                audit::emit(context, &options, event).await;
                utils::json(
                    http::StatusCode::OK,
                    &updated.sanitized_with_options(&context.base_url, Some(&options)),
                )
            })
        },
    )
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
        existing.authorization_endpoint = update.authorization_endpoint;
    }
    if update.token_endpoint.is_some() {
        existing.token_endpoint = update.token_endpoint;
    }
    if update.user_info_endpoint.is_some() {
        existing.user_info_endpoint = update.user_info_endpoint;
    }
    if let Some(value) = update.token_endpoint_authentication {
        existing.token_endpoint_authentication = Some(value);
    }
    if update.jwks_endpoint.is_some() {
        existing.jwks_endpoint = update.jwks_endpoint;
    }
    if update.revocation_endpoint.is_some() {
        existing.revocation_endpoint = update.revocation_endpoint;
    }
    if update.end_session_endpoint.is_some() {
        existing.end_session_endpoint = update.end_session_endpoint;
    }
    if update.introspection_endpoint.is_some() {
        existing.introspection_endpoint = update.introspection_endpoint;
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
