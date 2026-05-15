use http::{header, HeaderValue, StatusCode};
use openauth_core::api::{ApiRequest, ApiResponse, PathParams};
use openauth_core::auth::oauth::OAuthUserInfoError;
use openauth_core::context::AuthContext;
use openauth_core::cookies::{get_session_cookie, verify_cookie_value};
use openauth_core::db::DbAdapter;
use openauth_core::error::OpenAuthError;
use openauth_core::session::DbSessionStore;
use openauth_core::user::DbUserStore;
use serde::Serialize;
use std::sync::Arc;

use super::config::{
    GenericOAuthConfig, GenericOAuthFlow, GenericOAuthOptions, GenericOAuthParamsContext,
};
use super::discovery::DiscoveryCache;
use super::route_http::{api_error, json_response};

#[derive(Debug, Serialize)]
struct RedirectBody {
    url: String,
    redirect: bool,
}

pub(super) async fn resolved_config(
    options: &GenericOAuthOptions,
    discovery_cache: &DiscoveryCache,
    provider_id: &str,
) -> Result<GenericOAuthConfig, OpenAuthError> {
    let mut config = options
        .find(provider_id)
        .cloned()
        .ok_or_else(|| api_error_value(super::errors::PROVIDER_CONFIG_NOT_FOUND))?;
    if let Some(discovery) = discovery_cache.fetch(&config).await? {
        config.authorization_url = config
            .authorization_url
            .or(discovery.authorization_endpoint);
        config.token_url = config.token_url.or(discovery.token_endpoint);
        config.user_info_url = config.user_info_url.or(discovery.userinfo_endpoint);
        config.issuer = config.issuer.or(discovery.issuer);
    }
    if config.provider_id.trim().is_empty() {
        return Err(api_error_value(super::errors::PROVIDER_ID_REQUIRED));
    }
    if config.client_id.trim().is_empty() {
        return Err(api_error_value(super::errors::INVALID_OAUTH_CONFIG));
    }
    if config.authorization_url.is_none() {
        return Err(api_error_value(super::errors::INVALID_OAUTH_CONFIGURATION));
    }
    if config.token_url.is_none() {
        return Err(api_error_value(super::errors::TOKEN_URL_NOT_FOUND));
    }
    if config.require_issuer_validation && config.issuer.is_none() {
        return Err(api_error_value(super::errors::ISSUER_MISSING));
    }
    Ok(config)
}

pub(super) async fn resolve_authorization_url_params(
    config: &mut GenericOAuthConfig,
    flow: GenericOAuthFlow,
    redirect_uri: String,
) -> Result<(), OpenAuthError> {
    let Some(callback) = config.authorization_url_params_callback.clone() else {
        return Ok(());
    };
    let params = callback(GenericOAuthParamsContext {
        provider_id: config.provider_id.clone(),
        flow,
        redirect_uri,
    })
    .await
    .map_err(|error| OpenAuthError::Api(error.to_string()))?;
    config.authorization_url_params.extend(params);
    Ok(())
}

pub(super) async fn resolve_token_url_params(
    config: &mut GenericOAuthConfig,
    flow: GenericOAuthFlow,
    redirect_uri: String,
) -> Result<(), OpenAuthError> {
    let Some(callback) = config.token_url_params_callback.clone() else {
        return Ok(());
    };
    let params = callback(GenericOAuthParamsContext {
        provider_id: config.provider_id.clone(),
        flow,
        redirect_uri,
    })
    .await
    .map_err(|error| OpenAuthError::Api(error.to_string()))?;
    config.token_url_params.extend(params);
    Ok(())
}

pub(super) fn issuer_error(
    config: &GenericOAuthConfig,
    received: Option<&str>,
) -> Option<&'static str> {
    let expected = config.issuer.as_deref()?;
    match received {
        Some(received) if received == expected => None,
        Some(_) => Some("issuer_mismatch"),
        None if config.require_issuer_validation => Some("issuer_missing"),
        None => None,
    }
}

pub(super) fn adapter(context: &AuthContext) -> Result<Arc<dyn DbAdapter>, OpenAuthError> {
    context.adapter().ok_or_else(|| {
        OpenAuthError::InvalidConfig("generic-oauth routes require an adapter".to_owned())
    })
}

pub(super) async fn current_session(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    request: &ApiRequest,
) -> Result<Option<(openauth_core::db::Session, openauth_core::db::User)>, OpenAuthError> {
    let Some(cookie_header) = request
        .headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
    else {
        return Ok(None);
    };
    let Some(signed_token) = get_session_cookie(cookie_header, None, None) else {
        return Ok(None);
    };
    let Some(token) = verify_cookie_value(&signed_token, &context.secret)? else {
        return Ok(None);
    };
    let Some(session) = DbSessionStore::new(adapter).find_session(&token).await? else {
        return Ok(None);
    };
    let Some(user) = DbUserStore::new(adapter)
        .find_user_by_id(&session.user_id)
        .await?
    else {
        return Ok(None);
    };
    Ok(Some((session, user)))
}

pub(super) fn path_param<'a>(
    request: &'a ApiRequest,
    name: &str,
) -> Result<&'a str, OpenAuthError> {
    request
        .extensions()
        .get::<PathParams>()
        .and_then(|params| params.get(name))
        .ok_or_else(|| OpenAuthError::Api(format!("missing path param `{name}`")))
}

pub(super) fn query_param(request: &ApiRequest, name: &str) -> Option<String> {
    request.uri().query().and_then(|query| {
        url::form_urlencoded::parse(query.as_bytes())
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
    })
}

pub(super) fn oauth2_redirect_uri(context: &AuthContext, provider_id: &str) -> String {
    format!(
        "{}/oauth2/callback/{provider_id}",
        context.base_url.trim_end_matches('/')
    )
}

pub(super) fn callback_redirect_uri(context: &AuthContext, config: &GenericOAuthConfig) -> String {
    config
        .redirect_uri
        .clone()
        .unwrap_or_else(|| oauth2_redirect_uri(context, &config.provider_id))
}

pub(super) fn default_error_url(context: &AuthContext) -> String {
    format!("{}/error", context.base_url.trim_end_matches('/'))
}

pub(super) fn config_error_response(error: OpenAuthError) -> Result<ApiResponse, OpenAuthError> {
    let OpenAuthError::Api(code) = error else {
        return Err(error);
    };
    let (status, message) = match code.as_str() {
        super::errors::PROVIDER_CONFIG_NOT_FOUND => {
            (StatusCode::NOT_FOUND, "No config found for provider")
        }
        super::errors::PROVIDER_ID_REQUIRED => (StatusCode::BAD_REQUEST, "Provider ID is required"),
        super::errors::TOKEN_URL_NOT_FOUND => (
            StatusCode::BAD_REQUEST,
            "Invalid OAuth configuration. Token URL not found.",
        ),
        super::errors::ISSUER_MISSING => (
            StatusCode::BAD_REQUEST,
            "OAuth issuer parameter missing. The authorization server did not include the required iss parameter (RFC 9207).",
        ),
        super::errors::INVALID_OAUTH_CONFIG => {
            (StatusCode::BAD_REQUEST, "Invalid OAuth configuration.")
        }
        _ => (StatusCode::BAD_REQUEST, "Invalid OAuth configuration"),
    };
    api_error(status, &code, message)
}

pub(super) fn redirect_json_response(
    url: String,
    redirect: bool,
) -> Result<ApiResponse, OpenAuthError> {
    let mut response = json_response(
        StatusCode::OK,
        &RedirectBody {
            url: url.clone(),
            redirect,
        },
    )?;
    if redirect {
        response.headers_mut().insert(
            header::LOCATION,
            HeaderValue::from_str(&url).map_err(|error| OpenAuthError::Api(error.to_string()))?,
        );
    }
    Ok(response)
}

fn api_error_value(code: &str) -> OpenAuthError {
    OpenAuthError::Api(code.to_owned())
}

pub(super) fn oauth_user_info_error(error: OAuthUserInfoError) -> &'static str {
    match error {
        OAuthUserInfoError::AccountNotLinked => "account_not_linked",
        OAuthUserInfoError::SignupDisabled => "signup_disabled",
        OAuthUserInfoError::UnableToCreateUser => "unable_to_create_user",
        OAuthUserInfoError::UnableToCreateSession => "unable_to_create_session",
        OAuthUserInfoError::UnableToLinkAccount => "unable_to_link_account",
    }
}
