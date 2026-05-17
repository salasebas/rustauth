//! API key plugin.

mod cleanup;
mod errors;
mod hashing;
mod models;
mod options;
mod organization;
mod permissions;
mod rate_limit;
mod routes;
mod schema;
mod storage;

use std::sync::Arc;

use http::{header, StatusCode};
use openauth_core::context::request_state;
use openauth_core::db::Session;
use openauth_core::error::OpenAuthError;
use openauth_core::plugin::{AuthPlugin, PluginBeforeHookAction};
use openauth_core::user::DbUserStore;
use serde::Serialize;
use time::{Duration, OffsetDateTime};

pub use errors::*;
pub use hashing::default_key_hasher;
pub use models::{ApiKeyCreateRecord, ApiKeyPublicRecord, ApiKeyRecord};
pub use options::{
    ApiKeyConfiguration, ApiKeyExpirationOptions, ApiKeyGenerator, ApiKeyGeneratorInput,
    ApiKeyGetter, ApiKeyOptions, ApiKeyOptionsError, ApiKeyPermissions, ApiKeyRateLimitOptions,
    ApiKeyReference, ApiKeyStorageMode, ApiKeyValidator, StartingCharactersConfig,
};
pub use routes::{
    CreateApiKeyRequest, DeleteApiKeyRequest, GetApiKeyQuery, ListApiKeysQuery,
    UpdateApiKeyRequest, UpdateField, VerifyApiKeyRequest, VerifyApiKeyResponse,
};
pub use schema::ApiKeySchemaOptions;

pub const UPSTREAM_PLUGIN_ID: &str = "api-key";
pub const API_KEY_MODEL: &str = "api_key";
pub const API_KEY_TABLE: &str = "api_keys";

pub fn api_key() -> AuthPlugin {
    api_key_with_options(ApiKeyOptions::default())
}

pub fn api_key_with_options(options: ApiKeyOptions) -> AuthPlugin {
    build_plugin(options::ResolvedConfigurations::single(
        options.configuration,
    ))
}

pub fn api_key_with_configurations(
    configurations: Vec<ApiKeyConfiguration>,
) -> Result<AuthPlugin, ApiKeyOptionsError> {
    Ok(build_plugin(options::ResolvedConfigurations::multiple(
        configurations,
    )?))
}

fn build_plugin(configurations: options::ResolvedConfigurations) -> AuthPlugin {
    let configurations = Arc::new(configurations);
    let mut plugin = AuthPlugin::new(UPSTREAM_PLUGIN_ID)
        .with_version(crate::VERSION)
        .with_schema(schema::schema_contribution(&ApiKeySchemaOptions::default()))
        .with_endpoint(routes::create_endpoint(Arc::clone(&configurations)))
        .with_endpoint(routes::verify_endpoint(Arc::clone(&configurations)))
        .with_endpoint(routes::get_endpoint(Arc::clone(&configurations)))
        .with_endpoint(routes::update_endpoint(Arc::clone(&configurations)))
        .with_endpoint(routes::delete_endpoint(Arc::clone(&configurations)))
        .with_endpoint(routes::list_endpoint(Arc::clone(&configurations)))
        .with_endpoint(routes::delete_expired_endpoint(Arc::clone(&configurations)))
        .with_async_before_hook("*", move |context, request| {
            let configurations = Arc::clone(&configurations);
            Box::pin(async move { session_hook(context, request, configurations).await })
        });
    for error_code in errors::plugin_error_codes() {
        plugin = plugin.with_error_code(error_code);
    }
    plugin
}

async fn session_hook(
    context: &openauth_core::context::AuthContext,
    request: openauth_core::plugin::PluginRequest,
    configurations: Arc<options::ResolvedConfigurations>,
) -> Result<PluginBeforeHookAction, OpenAuthError> {
    let Some((raw_key, options)) = find_session_key(context, &request, &configurations).await?
    else {
        return Ok(PluginBeforeHookAction::Continue(request));
    };
    if raw_key.len() < options.default_key_length {
        return errors::error_response(StatusCode::FORBIDDEN, errors::INVALID_API_KEY)
            .map(PluginBeforeHookAction::Respond);
    }
    if let Some(validator) = &options.custom_api_key_validator {
        if !validator(context, &raw_key).await? {
            return Ok(PluginBeforeHookAction::Continue(request));
        }
    }
    let hashed = if options.disable_key_hashing {
        raw_key.clone()
    } else {
        hashing::default_key_hasher(&raw_key)
    };
    let api_key = match routes::validate_api_key(context, &options, &hashed, None).await {
        Ok(api_key) => api_key,
        Err(_) => return Ok(PluginBeforeHookAction::Continue(request)),
    };
    if options.reference != ApiKeyReference::User {
        return Ok(PluginBeforeHookAction::Continue(request));
    }
    let Some(adapter) = context.adapter() else {
        return Ok(PluginBeforeHookAction::Continue(request));
    };
    let Some(user) = DbUserStore::new(adapter.as_ref())
        .find_user_by_id(&api_key.reference_id)
        .await?
    else {
        return Ok(PluginBeforeHookAction::Continue(request));
    };
    let now = OffsetDateTime::now_utc();
    let expires_at = api_key.expires_at.unwrap_or_else(|| {
        now + Duration::seconds(i64::try_from(context.session_config.expires_in).unwrap_or(0))
    });
    let session = Session {
        id: api_key.id.clone(),
        user_id: api_key.reference_id.clone(),
        expires_at,
        token: raw_key,
        ip_address: None,
        user_agent: request
            .headers()
            .get(header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        created_at: now,
        updated_at: now,
    };
    if request_state::has_request_state() {
        request_state::set_current_session(session.clone(), user.clone())?;
    }
    if request.uri().path().ends_with("/get-session") {
        return session_response(session, user).map(PluginBeforeHookAction::Respond);
    }
    Ok(PluginBeforeHookAction::Continue(request))
}

async fn find_session_key(
    context: &openauth_core::context::AuthContext,
    request: &openauth_core::plugin::PluginRequest,
    configurations: &options::ResolvedConfigurations,
) -> Result<Option<(String, ApiKeyConfiguration)>, OpenAuthError> {
    for configuration in configurations
        .all()
        .iter()
        .filter(|configuration| configuration.enable_session_for_api_keys)
    {
        if let Some(getter) = &configuration.custom_api_key_getter {
            if let Some(key) = getter(context, request).await? {
                return Ok(Some((key, configuration.clone())));
            }
            continue;
        }
        for header_name in &configuration.api_key_headers {
            if let Some(value) = request
                .headers()
                .get(header_name)
                .and_then(|value| value.to_str().ok())
            {
                return Ok(Some((value.to_owned(), configuration.clone())));
            }
        }
    }
    Ok(None)
}

#[derive(Serialize)]
struct SessionResponse {
    session: Session,
    user: openauth_core::db::User,
}

fn session_response(
    session: Session,
    user: openauth_core::db::User,
) -> Result<openauth_core::plugin::PluginResponse, OpenAuthError> {
    let body = serde_json::to_vec(&SessionResponse { session, user })
        .map_err(|error| OpenAuthError::Api(error.to_string()))?;
    http::Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .map_err(|error| OpenAuthError::Api(error.to_string()))
}
