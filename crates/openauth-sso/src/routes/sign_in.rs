#[cfg(feature = "oidc")]
use std::collections::BTreeMap;
use std::sync::Arc;

use http::Method;
use openauth_core::api::{
    create_auth_endpoint, parse_request_body, AsyncAuthEndpoint, AuthEndpointOptions,
    OpenApiOperation,
};
#[cfg(feature = "oidc")]
use openauth_core::auth::oauth::{generate_oauth_state, OAuthStateInput};
use openauth_core::context::AuthContext;
#[cfg(any(feature = "oidc", feature = "saml"))]
use openauth_core::crypto::random::generate_random_string;
#[cfg(feature = "saml")]
use openauth_core::db::DbAdapter;
#[cfg(feature = "oidc")]
use openauth_oauth::oauth2::{
    create_authorization_url, AuthorizationUrlRequest, ClientId, ProviderOptions,
};
use serde::Deserialize;
use serde_json::json;
#[cfg(feature = "saml")]
use time::OffsetDateTime;

use crate::linking_impl::provider_matches_email_domain;
#[cfg(feature = "oidc")]
use crate::oidc_impl::flow::oidc_redirect_uri;
use crate::openapi::{sign_in_body_schema, sign_in_sso_response};
#[cfg(feature = "oidc")]
use crate::options::OidcConfig;
#[cfg(feature = "saml")]
use crate::options::SamlConfig;
use crate::options::{SsoOptions, SsoProvider};
use crate::org::organization_id_by_slug;
#[cfg(feature = "saml")]
use crate::saml_impl::authn_request::{build_authn_request_redirect, SamlAuthnRequestError};
#[cfg(feature = "saml")]
use crate::saml_impl::state::authn_request_key;
#[cfg(feature = "saml")]
use crate::state::SsoStateStore;
use crate::store::SsoProviderStore;
use crate::utils;

#[cfg(any(feature = "oidc", feature = "saml"))]
use super::support::{optional_safe_redirect_field, redirect_json_response, safe_redirect_field};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignInSsoBody {
    email: Option<String>,
    domain: Option<String>,
    provider_id: Option<String>,
    organization_slug: Option<String>,
    callback_url: Option<String>,
    #[serde(alias = "callbackURL")]
    callback_url_alias: Option<String>,
    error_callback_url: Option<String>,
    #[serde(alias = "errorCallbackURL")]
    error_callback_url_alias: Option<String>,
    new_user_callback_url: Option<String>,
    #[serde(alias = "newUserCallbackURL")]
    new_user_callback_url_alias: Option<String>,
    login_hint: Option<String>,
    scopes: Option<Vec<String>>,
    provider_type: Option<String>,
    #[serde(default)]
    request_sign_up: bool,
}

pub(super) fn endpoint(options: Arc<SsoOptions>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/sign-in/sso",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("signInWithSSO")
            .allowed_media_types(["application/json", "application/x-www-form-urlencoded"])
            .body_schema(sign_in_body_schema())
            .openapi(
                OpenApiOperation::new("signInWithSSO")
                    .tag("SSO")
                    .response("200", sign_in_sso_response()),
            ),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                let body = parse_request_body::<SignInSsoBody>(&request)?;
                if !matches!(
                    body.provider_type.as_deref(),
                    None | Some("oidc") | Some("saml")
                ) {
                    return utils::json(
                        http::StatusCode::BAD_REQUEST,
                        &json!({"code": crate::errors::INVALID_PROVIDER_TYPE}),
                    );
                }
                let provider = find_sign_in_provider(context, &options, &body).await?;
                let Some(provider) = provider else {
                    return utils::json(
                        http::StatusCode::NOT_FOUND,
                        &json!({"code": "PROVIDER_NOT_FOUND", "message": "No provider found for the issuer"}),
                    );
                };
                if options.domain_verification.enabled && !provider.domain_verified.unwrap_or(false)
                {
                    return utils::json(
                        http::StatusCode::UNAUTHORIZED,
                        &json!({"code": "DOMAIN_NOT_VERIFIED", "message": "Provider domain has not been verified"}),
                    );
                }
                if body.provider_type.as_deref() == Some("saml")
                    || (provider.saml_config.is_some() && provider.oidc_config.is_none())
                {
                    #[cfg(feature = "saml")]
                    {
                        let Some(adapter) = context.adapter.as_deref() else {
                            return Err(openauth_core::error::OpenAuthError::Adapter(
                                "SSO sign-in requires an adapter".to_owned(),
                            ));
                        };
                        return saml_sign_in(context, adapter, options.as_ref(), provider, body)
                            .await;
                    }
                    #[cfg(not(feature = "saml"))]
                    {
                        return utils::json(
                            http::StatusCode::BAD_REQUEST,
                            &json!({"code": "SAML_FEATURE_DISABLED", "message": "SAML support is not enabled"}),
                        );
                    }
                }
                #[cfg(not(feature = "oidc"))]
                {
                    let _ = (context, request, options, provider, body);
                    return utils::json(
                        http::StatusCode::BAD_REQUEST,
                        &json!({"code": "OIDC_FEATURE_DISABLED", "message": "OIDC support is not enabled"}),
                    );
                }
                #[cfg(feature = "oidc")]
                {
                    let Some(adapter) = context.adapter.as_deref() else {
                        return Err(openauth_core::error::OpenAuthError::Adapter(
                            "SSO sign-in requires an adapter".to_owned(),
                        ));
                    };
                    let Some(config) = provider
                        .oidc_config
                        .as_deref()
                        .and_then(|value| serde_json::from_str::<OidcConfig>(value).ok())
                    else {
                        return utils::json(
                            http::StatusCode::BAD_REQUEST,
                            &json!({"code": "OIDC_PROVIDER_NOT_CONFIGURED", "message": "OIDC provider is not configured"}),
                        );
                    };
                    let config = match super::oidc::ensure_runtime_oidc_config(
                        context,
                        &request,
                        &provider.issuer,
                        config,
                        &options,
                        super::oidc::OidcRuntimeRequirement::SignIn,
                    )
                    .await
                    {
                        Ok(config) => config,
                        Err(error) => {
                            return utils::json(
                                error.status(),
                                &json!({"code": error.code(), "message": error.to_string()}),
                            )
                        }
                    };
                    let Some(authorization_endpoint) = config.authorization_endpoint.clone() else {
                        return utils::json(
                            http::StatusCode::BAD_REQUEST,
                            &json!({"code": "INVALID_OIDC_CONFIG", "message": "Invalid OIDC configuration. Authorization URL not found."}),
                        );
                    };
                    let raw_callback_url = body
                        .callback_url
                        .or(body.callback_url_alias)
                        .unwrap_or_else(|| "/".to_owned());
                    let callback_url = match safe_redirect_field(
                        context,
                        raw_callback_url,
                        "INVALID_CALLBACK_URL",
                    )? {
                        Ok(url) => url,
                        Err(response) => return Ok(response),
                    };
                    let error_url = match optional_safe_redirect_field(
                        context,
                        body.error_callback_url.or(body.error_callback_url_alias),
                        "INVALID_ERROR_CALLBACK_URL",
                    )? {
                        Ok(url) => url,
                        Err(response) => return Ok(response),
                    };
                    let new_user_url = match optional_safe_redirect_field(
                        context,
                        body.new_user_callback_url
                            .or(body.new_user_callback_url_alias),
                        "INVALID_NEW_USER_CALLBACK_URL",
                    )? {
                        Ok(url) => url,
                        Err(response) => return Ok(response),
                    };
                    let oidc_nonce = generate_random_string(32);
                    let state = generate_oauth_state(
                        context,
                        Some(adapter),
                        OAuthStateInput {
                            callback_url,
                            error_url,
                            new_user_url,
                            request_sign_up: body.request_sign_up,
                            additional_data: json!({
                                "ssoProviderId": provider.provider_id,
                                "oidcNonce": oidc_nonce,
                            }),
                            ..OAuthStateInput::default()
                        },
                    )
                    .await?;
                    let redirect_uri = oidc_redirect_uri(
                        &context.base_url,
                        &provider.provider_id,
                        options.as_ref(),
                    );
                    let scopes = body
                        .scopes
                        .or(config.scopes)
                        .unwrap_or_else(default_oidc_scopes);
                    let authorization_url = create_authorization_url(AuthorizationUrlRequest {
                        id: provider.issuer,
                        options: ProviderOptions {
                            client_id: Some(ClientId::Single(config.client_id)),
                            client_secret: Some(config.client_secret.into_inner()),
                            ..ProviderOptions::default()
                        },
                        authorization_endpoint,
                        redirect_uri,
                        state: state.state,
                        code_verifier: config.pkce.then_some(state.data.code_verifier),
                        scopes,
                        login_hint: body.login_hint.or(body.email),
                        additional_params: BTreeMap::from([(
                            "nonce".to_owned(),
                            state
                                .data
                                .additional_data
                                .get("oidcNonce")
                                .and_then(serde_json::Value::as_str)
                                .unwrap_or_default()
                                .to_owned(),
                        )]),
                        ..AuthorizationUrlRequest::default()
                    })
                    .map_err(|error| {
                        openauth_core::error::OpenAuthError::OAuth(error.to_string())
                    })?;
                    redirect_json_response(authorization_url.to_string(), true)
                }
            })
        },
    )
}

#[cfg(feature = "saml")]
#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SamlAuthnRequestRecord {
    pub(super) id: String,
    pub(super) provider_id: String,
    pub(super) callback_url: String,
    pub(super) error_url: Option<String>,
    pub(super) new_user_url: Option<String>,
    pub(super) request_sign_up: bool,
    pub(super) created_at: i64,
    pub(super) expires_at: i64,
}

#[cfg(feature = "saml")]
async fn saml_sign_in(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    options: &SsoOptions,
    provider: crate::SsoProviderRecord,
    body: SignInSsoBody,
) -> Result<openauth_core::api::ApiResponse, openauth_core::error::OpenAuthError> {
    let Some(config) = provider
        .saml_config
        .as_deref()
        .and_then(|value| serde_json::from_str::<SamlConfig>(value).ok())
    else {
        return utils::json(
            http::StatusCode::BAD_REQUEST,
            &json!({"code": "SAML_PROVIDER_NOT_CONFIGURED", "message": "SAML provider is not configured"}),
        );
    };
    let request_id = format!("id-{}", generate_random_string(32));
    let relay_state = request_id.clone();
    let authn_request = match build_authn_request_redirect(
        &provider.provider_id,
        &context.base_url,
        &config,
        request_id,
        relay_state,
    ) {
        Ok(authn_request) => authn_request,
        Err(error) => return saml_authn_request_error_response(error),
    };
    let callback_url = body
        .callback_url
        .or(body.callback_url_alias)
        .unwrap_or_else(|| "/".to_owned());
    let callback_url = match safe_redirect_field(context, callback_url, "INVALID_CALLBACK_URL")? {
        Ok(url) => url,
        Err(response) => return Ok(response),
    };
    let error_url = match optional_safe_redirect_field(
        context,
        body.error_callback_url.or(body.error_callback_url_alias),
        "INVALID_ERROR_CALLBACK_URL",
    )? {
        Ok(url) => url,
        Err(response) => return Ok(response),
    };
    let new_user_url = match optional_safe_redirect_field(
        context,
        body.new_user_callback_url
            .or(body.new_user_callback_url_alias),
        "INVALID_NEW_USER_CALLBACK_URL",
    )? {
        Ok(url) => url,
        Err(response) => return Ok(response),
    };
    let now = OffsetDateTime::now_utc();
    let expires_at = now + options.saml.request_ttl;
    let record = SamlAuthnRequestRecord {
        id: authn_request.id.clone(),
        provider_id: provider.provider_id,
        callback_url,
        error_url,
        new_user_url,
        request_sign_up: body.request_sign_up,
        created_at: now.unix_timestamp(),
        expires_at: expires_at.unix_timestamp(),
    };
    SsoStateStore::new(context, adapter)
        .create(
            authn_request_key(&authn_request.id),
            serde_json::to_string(&record).map_err(|error| {
                openauth_core::error::OpenAuthError::Api(format!(
                    "failed to serialize SAML AuthnRequest state: {error}"
                ))
            })?,
            expires_at,
        )
        .await?;

    redirect_json_response(authn_request.redirect_url, true)
}

#[cfg(feature = "saml")]
fn saml_authn_request_error_response(
    error: SamlAuthnRequestError,
) -> Result<openauth_core::api::ApiResponse, openauth_core::error::OpenAuthError> {
    match error {
        SamlAuthnRequestError::SigningNotSupported => utils::json(
            http::StatusCode::BAD_REQUEST,
            &json!({"code": "SAML_AUTHN_REQUEST_SIGNING_NOT_SUPPORTED", "message": error.to_string()}),
        ),
        SamlAuthnRequestError::PrivateKeyRequired => utils::json(
            http::StatusCode::BAD_REQUEST,
            &json!({"code": "SAML_AUTHN_REQUEST_PRIVATE_KEY_REQUIRED", "message": error.to_string()}),
        ),
        SamlAuthnRequestError::InvalidPrivateKey(_) | SamlAuthnRequestError::Sign(_) => {
            utils::json(
                http::StatusCode::BAD_REQUEST,
                &json!({"code": "SAML_AUTHN_REQUEST_SIGNING_FAILED", "message": error.to_string()}),
            )
        }
        SamlAuthnRequestError::InvalidEntryPoint(_) | SamlAuthnRequestError::Encode(_) => {
            Err(openauth_core::error::OpenAuthError::Api(error.to_string()))
        }
    }
}

async fn find_sign_in_provider(
    context: &AuthContext,
    options: &SsoOptions,
    body: &SignInSsoBody,
) -> Result<Option<crate::SsoProviderRecord>, openauth_core::error::OpenAuthError> {
    if let Some(provider_id) = &body.provider_id {
        if let Some(provider) = default_sso_by_provider_id(options, provider_id)? {
            return Ok(Some(provider));
        }
    }

    let domain = body.domain.clone().or_else(|| {
        body.email
            .as_deref()
            .and_then(email_domain)
            .map(str::to_owned)
    });
    if body.provider_id.is_none() {
        if let Some(domain) = domain.as_deref() {
            if let Some(provider) = default_sso_by_domain(options, domain)? {
                return Ok(Some(provider));
            }
        }
    }

    let Some(adapter) = context.adapter.as_deref() else {
        return Ok(None);
    };
    let store = SsoProviderStore::new_with_options(adapter, options);
    if let Some(provider_id) = &body.provider_id {
        return store.find_by_provider_id(provider_id).await;
    }
    if let Some(organization_slug) = &body.organization_slug {
        let Some(organization_id) =
            organization_id_by_slug(context, adapter, organization_slug).await?
        else {
            return Ok(None);
        };
        return store.find_by_organization_id(&organization_id).await;
    }

    let Some(domain) = domain else {
        return Err(openauth_core::error::OpenAuthError::Api(
            "email, organizationSlug, domain or providerId is required".to_owned(),
        ));
    };

    let providers = store.list().await?;
    let lookup_email = format!("user@{domain}");
    Ok(providers
        .into_iter()
        .find(|provider| provider_matches_email_domain(provider, &lookup_email)))
}

pub(super) fn default_sso_by_provider_id(
    options: &SsoOptions,
    provider_id: &str,
) -> Result<Option<crate::SsoProviderRecord>, openauth_core::error::OpenAuthError> {
    options
        .default_sso
        .iter()
        .find(|provider| provider.provider_id == provider_id)
        .map(|provider| default_sso_provider_record(options, provider))
        .transpose()
}

fn default_sso_by_domain(
    options: &SsoOptions,
    domain: &str,
) -> Result<Option<crate::SsoProviderRecord>, openauth_core::error::OpenAuthError> {
    let providers = options
        .default_sso
        .iter()
        .map(|provider| default_sso_provider_record(options, provider))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(providers
        .into_iter()
        .find(|provider| provider_matches_email_domain(provider, &format!("user@{domain}"))))
}

fn default_sso_provider_record(
    options: &SsoOptions,
    provider: &SsoProvider,
) -> Result<crate::SsoProviderRecord, openauth_core::error::OpenAuthError> {
    let oidc_config = provider
        .oidc_config
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|error| {
            openauth_core::error::OpenAuthError::Api(format!(
                "failed to serialize default OIDC config: {error}"
            ))
        })?;
    let saml_config = provider
        .saml_config
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|error| {
            openauth_core::error::OpenAuthError::Api(format!(
                "failed to serialize default SAML config: {error}"
            ))
        })?;
    Ok(crate::SsoProviderRecord {
        id: format!("default:{}", provider.provider_id),
        issuer: provider.issuer.clone(),
        oidc_config,
        saml_config,
        user_id: "default".to_owned(),
        provider_id: provider.provider_id.clone(),
        organization_id: provider.organization_id.clone(),
        domain: provider.domain.clone(),
        domain_verified: options.domain_verification.enabled.then_some(true),
        created_at: None,
    })
}

fn email_domain(email: &str) -> Option<&str> {
    email.rsplit_once('@').map(|(_, domain)| domain)
}

#[cfg(feature = "oidc")]
fn default_oidc_scopes() -> Vec<String> {
    ["openid", "email", "profile", "offline_access"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}
