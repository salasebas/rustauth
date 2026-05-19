use std::sync::Arc;

use http::Method;
use openauth_core::api::{
    create_auth_endpoint, parse_request_body, AsyncAuthEndpoint, AuthEndpointOptions,
    OpenApiOperation,
};
use openauth_core::context::AuthContext;
use openauth_core::crypto::random::generate_random_string;
use serde::Deserialize;
use serde_json::json;
use time::{Duration, OffsetDateTime};

use crate::audit;
use crate::linking::validate_provider_domains;
use crate::oidc::discovery::{
    compute_discovery_url, discover_oidc_config_with_origin_validator, validate_issuer_url,
    PartialOidcDiscoveryConfig,
};
use crate::openapi::register_body_schema;
use crate::options::{
    OidcConfig, OidcMapping, SamlConfig, SsoAuditEvent, SsoAuditEventKind, SsoAuditSeverity,
    SsoOptions, TokenEndpointAuthentication,
};
use crate::org::can_register_for_organization;
use crate::state::SsoStateStore;
use crate::store::{CreateSsoProviderInput, SsoProviderStore};
use crate::utils;

use super::support::authenticated_session_user;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterBody {
    provider_id: String,
    issuer: String,
    domain: String,
    #[serde(default)]
    organization_id: Option<String>,
    #[serde(default)]
    oidc_config: Option<RegisterOidcConfig>,
    #[serde(default)]
    saml_config: Option<SamlConfig>,
    #[serde(default)]
    override_user_info: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterOidcConfig {
    client_id: String,
    client_secret: String,
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    user_info_endpoint: Option<String>,
    token_endpoint_authentication: Option<TokenEndpointAuthentication>,
    jwks_endpoint: Option<String>,
    discovery_endpoint: Option<String>,
    #[serde(default)]
    skip_discovery: bool,
    scopes: Option<Vec<String>>,
    pkce: Option<bool>,
    mapping: Option<OidcMapping>,
}

pub(super) fn endpoint(options: Arc<SsoOptions>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/sso/register",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("registerSSOProvider")
            .allowed_media_types(["application/json", "application/x-www-form-urlencoded"])
            .body_schema(register_body_schema())
            .openapi(OpenApiOperation::new("registerSSOProvider").tag("SSO")),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                let Some((adapter, user)) = authenticated_session_user(context, &request).await?
                else {
                    return utils::json(
                        http::StatusCode::UNAUTHORIZED,
                        &json!({"code": "UNAUTHORIZED", "message": "Authentication required"}),
                    );
                };
                let user_id = user.id.clone();
                let body = parse_request_body::<RegisterBody>(&request)?;
                let providers_limit = options.resolve_providers_limit(user).await?;
                if providers_limit == 0 {
                    return utils::json(
                        http::StatusCode::FORBIDDEN,
                        &json!({"code": "SSO_PROVIDER_REGISTRATION_DISABLED"}),
                    );
                }
                if validate_issuer_url(&body.issuer).is_err() {
                    return utils::json(
                        http::StatusCode::BAD_REQUEST,
                        &json!({"code": "INVALID_ISSUER", "message": "Invalid issuer. Must be a valid URL"}),
                    );
                }
                if !validate_provider_domains(&body.domain) {
                    return utils::json(
                        http::StatusCode::BAD_REQUEST,
                        &json!({"code": "INVALID_DOMAIN"}),
                    );
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
                let store = SsoProviderStore::new(adapter.as_ref());
                let existing = store.find_by_provider_id(&body.provider_id).await?;
                if existing.is_some() {
                    return utils::json(
                        http::StatusCode::UNPROCESSABLE_ENTITY,
                        &json!({"code": "PROVIDER_EXISTS", "message": "SSO provider with this providerId already exists"}),
                    );
                }
                if store.list_by_user(&user_id).await?.len() >= providers_limit {
                    return utils::json(
                        http::StatusCode::FORBIDDEN,
                        &json!({"code": "SSO_PROVIDERS_LIMIT_REACHED"}),
                    );
                }
                let saml_config = if let Some(config) = body.saml_config {
                    let config = match super::saml_config::normalize_saml_config(config, &options) {
                        Ok(config) => config,
                        Err(error) => return super::saml_config::error_response(error),
                    };
                    if let Err(error) =
                        super::validate_configured_saml_algorithms(&config, &options)
                    {
                        return super::saml_algorithm_error_response(error);
                    }
                    Some(config)
                } else {
                    None
                };
                if let Some(config) = &body.oidc_config {
                    if !is_valid_register_oidc_config_urls(&body.issuer, config) {
                        return utils::json(
                            http::StatusCode::BAD_REQUEST,
                            &json!({"code": "INVALID_OIDC_CONFIG"}),
                        );
                    }
                }
                let oidc_config = match body.oidc_config {
                    Some(config) => match build_oidc_config(
                        context,
                        &request,
                        &body.issuer,
                        config,
                        &options,
                        body.override_user_info,
                    )
                    .await
                    {
                        Ok(config) => Some(config),
                        Err(BuildOidcConfigError::Discovery(error)) => {
                            return oidc_discovery_error_response(error);
                        }
                        Err(BuildOidcConfigError::Api(message)) => {
                            return Err(openauth_core::error::OpenAuthError::Api(message));
                        }
                    },
                    None => None,
                };
                let created = store
                    .create(CreateSsoProviderInput {
                        provider_id: body.provider_id,
                        issuer: body.issuer.clone(),
                        domain: body.domain,
                        user_id,
                        organization_id: body.organization_id,
                        oidc_config,
                        saml_config: saml_config
                            .map(|config| serde_json::to_string(&config))
                            .transpose()
                            .map_err(|error| {
                                openauth_core::error::OpenAuthError::Api(format!(
                                    "failed to serialize SAML config: {error}"
                                ))
                            })?,
                        domain_verified: options.domain_verification.enabled.then_some(false),
                    })
                    .await?;
                let sanitized = created.sanitized_with_options(&context.base_url, Some(&options));
                let mut response = serde_json::to_value(&sanitized).map_err(|error| {
                    openauth_core::error::OpenAuthError::Api(format!(
                        "failed to serialize SSO provider response: {error}"
                    ))
                })?;
                if options.domain_verification.enabled {
                    let token = generate_random_string(24);
                    SsoStateStore::new(context, adapter.as_ref())
                        .create(
                            super::domain_verification::verification_identifier(
                                &options,
                                &created.provider_id,
                            ),
                            token.clone(),
                            OffsetDateTime::now_utc()
                                + Duration::seconds(
                                    options.domain_verification.token_ttl_seconds as i64,
                                ),
                        )
                        .await?;
                    if let Some(object) = response.as_object_mut() {
                        object.insert("domainVerificationToken".to_owned(), json!(token));
                    }
                }
                let mut event = SsoAuditEvent::new(
                    SsoAuditEventKind::ProviderRegistered,
                    SsoAuditSeverity::Info,
                )
                .provider_id(created.provider_id.clone())
                .user_id(created.user_id.clone());
                if let Some(organization_id) = created.organization_id.clone() {
                    event = event.organization_id(organization_id);
                }
                audit::emit(context, &options, event).await;
                utils::json(http::StatusCode::OK, &response)
            })
        },
    )
}

async fn build_oidc_config(
    context: &AuthContext,
    request: &openauth_core::api::ApiRequest,
    issuer: &str,
    input: RegisterOidcConfig,
    options: &SsoOptions,
    override_user_info: bool,
) -> Result<String, BuildOidcConfigError> {
    let config = if input.skip_discovery {
        let discovery_endpoint = input
            .discovery_endpoint
            .unwrap_or_else(|| compute_discovery_url(issuer));
        OidcConfig {
            issuer: issuer.to_owned(),
            pkce: input.pkce.unwrap_or(true),
            client_id: input.client_id,
            client_secret: input.client_secret.into(),
            discovery_endpoint,
            authorization_endpoint: input.authorization_endpoint,
            token_endpoint: input.token_endpoint,
            user_info_endpoint: input.user_info_endpoint,
            jwks_endpoint: input.jwks_endpoint,
            token_endpoint_authentication: Some(
                input
                    .token_endpoint_authentication
                    .unwrap_or(TokenEndpointAuthentication::ClientSecretBasic),
            ),
            scopes: input.scopes,
            mapping: input.mapping,
            override_user_info: override_user_info || options.default_override_user_info,
        }
    } else {
        let hydrated = discover_oidc_config_with_origin_validator(
            issuer,
            input.discovery_endpoint.as_deref(),
            PartialOidcDiscoveryConfig {
                authorization_endpoint: input.authorization_endpoint.as_deref(),
                token_endpoint: input.token_endpoint.as_deref(),
                user_info_endpoint: input.user_info_endpoint.as_deref(),
                jwks_endpoint: input.jwks_endpoint.as_deref(),
                token_endpoint_authentication: input.token_endpoint_authentication,
                ..PartialOidcDiscoveryConfig::default()
            },
            |url| super::oidc::is_trusted_oidc_url(context, request, url),
        )
        .await
        .map_err(BuildOidcConfigError::Discovery)?;
        OidcConfig {
            issuer: hydrated.issuer,
            pkce: input.pkce.unwrap_or(true),
            client_id: input.client_id,
            client_secret: input.client_secret.into(),
            discovery_endpoint: hydrated.discovery_endpoint,
            authorization_endpoint: Some(hydrated.authorization_endpoint),
            token_endpoint: Some(hydrated.token_endpoint),
            user_info_endpoint: hydrated.user_info_endpoint,
            jwks_endpoint: Some(hydrated.jwks_endpoint),
            token_endpoint_authentication: Some(hydrated.token_endpoint_authentication),
            scopes: input.scopes.or(hydrated.scopes_supported),
            mapping: input.mapping,
            override_user_info: override_user_info || options.default_override_user_info,
        }
    };
    if input.skip_discovery
        && (config.authorization_endpoint.is_none()
            || config.token_endpoint.is_none()
            || config.jwks_endpoint.is_none())
    {
        return Err(BuildOidcConfigError::Api(
            "skipDiscovery requires authorizationEndpoint, tokenEndpoint, and jwksEndpoint"
                .to_owned(),
        ));
    }
    serde_json::to_string(&config).map_err(|error| {
        BuildOidcConfigError::Api(format!("failed to serialize OIDC config: {error}"))
    })
}

#[derive(Debug)]
enum BuildOidcConfigError {
    Discovery(crate::oidc::discovery::OidcDiscoveryError),
    Api(String),
}

fn oidc_discovery_error_response(
    error: crate::oidc::discovery::OidcDiscoveryError,
) -> Result<openauth_core::api::ApiResponse, openauth_core::error::OpenAuthError> {
    utils::json(
        error.status(),
        &json!({"code": error.code(), "message": error.to_string()}),
    )
}

fn is_valid_register_oidc_config_urls(issuer: &str, config: &RegisterOidcConfig) -> bool {
    let discovery_endpoint = config
        .discovery_endpoint
        .clone()
        .unwrap_or_else(|| compute_discovery_url(issuer));
    validate_issuer_url(issuer).is_ok()
        && super::optional_http_url(config.authorization_endpoint.as_deref())
        && super::optional_http_url(config.token_endpoint.as_deref())
        && super::optional_http_url(config.user_info_endpoint.as_deref())
        && super::optional_http_url(config.jwks_endpoint.as_deref())
        && super::is_valid_http_url(&discovery_endpoint)
}
