use std::sync::Arc;

use http::{header, Method, StatusCode};
use openauth_core::api::{
    create_auth_endpoint, parse_request_body, ApiRequest, ApiResponse, AuthEndpointOptions,
    BodyField, BodySchema, JsonSchemaType,
};
use openauth_core::context::{request_state, AuthContext};
use openauth_core::db::{DbAdapter, DbRecord, DbValue};
use openauth_core::error::OpenAuthError;
use openauth_core::plugin::PluginEndpoint;
use openauth_core::session::{CreateSessionInput, DbSessionStore};
use openauth_core::user::DbUserStore;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use crate::device_authorization::errors::{oauth_error_response, OAuthDeviceError};
use crate::device_authorization::options::DeviceAuthorizationOptions;
use crate::device_authorization::store::{
    DeviceAuthorizationStatus, DeviceCodeRecord, DeviceCodeStore,
};

const DEVICE_CODE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct DeviceTokenRequest {
    pub grant_type: String,
    pub device_code: String,
    pub client_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct DeviceTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub scope: String,
}

pub fn device_token(options: Arc<DeviceAuthorizationOptions>) -> PluginEndpoint {
    create_auth_endpoint(
        "/device/token",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("deviceToken")
            .allowed_media_types(["application/json", "application/x-www-form-urlencoded"])
            .openapi(super::openapi::device_token_operation())
            .body_schema(BodySchema::object([
                BodyField::new("grant_type", JsonSchemaType::String),
                BodyField::new("device_code", JsonSchemaType::String),
                BodyField::new("client_id", JsonSchemaType::String),
            ])),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                let body = parse_request_body::<DeviceTokenRequest>(&request)?;
                if body.grant_type != DEVICE_CODE_GRANT_TYPE {
                    return token_oauth_error_response(
                        StatusCode::BAD_REQUEST,
                        OAuthDeviceError::InvalidRequest,
                        "Invalid grant type",
                    );
                }
                if let Some(validate_client) = &options.validate_client {
                    if !(validate_client)(body.client_id.clone()).await? {
                        return token_oauth_error_response(
                            StatusCode::BAD_REQUEST,
                            OAuthDeviceError::InvalidGrant,
                            "Invalid client ID",
                        );
                    }
                }

                let adapter = required_adapter(context)?;
                let store = DeviceCodeStore::new(adapter.as_ref());
                let Some(record) = store.find_by_device_code(&body.device_code).await? else {
                    return token_oauth_error_response(
                        StatusCode::BAD_REQUEST,
                        OAuthDeviceError::InvalidGrant,
                        "Invalid device code",
                    );
                };
                if record
                    .client_id
                    .as_ref()
                    .is_some_and(|client_id| client_id != &body.client_id)
                {
                    return token_oauth_error_response(
                        StatusCode::BAD_REQUEST,
                        OAuthDeviceError::InvalidGrant,
                        "Client ID mismatch",
                    );
                }
                if polling_too_fast(&record) {
                    return token_oauth_error_response(
                        StatusCode::BAD_REQUEST,
                        OAuthDeviceError::SlowDown,
                        "Polling too frequently",
                    );
                }
                store.mark_polled(&record.id).await?;
                if record.expires_at < OffsetDateTime::now_utc() {
                    store.delete(&record.id).await?;
                    return token_oauth_error_response(
                        StatusCode::BAD_REQUEST,
                        OAuthDeviceError::ExpiredToken,
                        "Device code has expired",
                    );
                }

                match record.status {
                    DeviceAuthorizationStatus::Pending => token_oauth_error_response(
                        StatusCode::BAD_REQUEST,
                        OAuthDeviceError::AuthorizationPending,
                        "Authorization pending",
                    ),
                    DeviceAuthorizationStatus::Denied => {
                        store.delete(&record.id).await?;
                        token_oauth_error_response(
                            StatusCode::BAD_REQUEST,
                            OAuthDeviceError::AccessDenied,
                            "Access denied",
                        )
                    }
                    DeviceAuthorizationStatus::Approved => {
                        approved_response(context, adapter.as_ref(), &store, &record, &request)
                            .await
                    }
                }
            })
        },
    )
}

pub(super) fn required_adapter(context: &AuthContext) -> Result<Arc<dyn DbAdapter>, OpenAuthError> {
    context.adapter().ok_or_else(|| {
        OpenAuthError::Adapter("device authorization requires a database adapter".to_owned())
    })
}

async fn approved_response(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    store: &DeviceCodeStore<'_>,
    record: &DeviceCodeRecord,
    request: &ApiRequest,
) -> Result<ApiResponse, OpenAuthError> {
    let Some(user_id) = &record.user_id else {
        return token_oauth_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            OAuthDeviceError::ServerError,
            "Invalid device code status",
        );
    };
    let Some(user) = DbUserStore::new(adapter).find_user_by_id(user_id).await? else {
        return token_oauth_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            OAuthDeviceError::ServerError,
            "User not found",
        );
    };
    let expires_at =
        OffsetDateTime::now_utc() + Duration::seconds(context.session_config.expires_in as i64);
    let mut input = CreateSessionInput::new(user.id.clone(), expires_at)
        .additional_fields(additional_session_create_values(context));
    if let Some(ip_address) = request_ip(request) {
        input = input.ip_address(ip_address);
    }
    if let Some(user_agent) = request_user_agent(request) {
        input = input.user_agent(user_agent);
    }
    let session = match DbSessionStore::new(adapter).create_session(input).await {
        Ok(session) => session,
        Err(_) => {
            return token_oauth_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                OAuthDeviceError::ServerError,
                "Failed to create session",
            );
        }
    };
    if request_state::has_request_state() {
        request_state::set_current_new_session(session.clone(), user)?;
    }
    store.delete(&record.id).await?;

    let expires_in = (session.expires_at - OffsetDateTime::now_utc())
        .whole_seconds()
        .max(0);
    let mut response = super::json_response(
        StatusCode::OK,
        &DeviceTokenResponse {
            access_token: session.token,
            token_type: "Bearer".to_owned(),
            expires_in,
            scope: record.scope.clone().unwrap_or_default(),
        },
    )?;
    add_token_cache_headers(&mut response);
    Ok(response)
}

fn polling_too_fast(record: &DeviceCodeRecord) -> bool {
    let (Some(last_polled_at), Some(interval)) = (record.last_polled_at, record.polling_interval)
    else {
        return false;
    };
    let elapsed = OffsetDateTime::now_utc() - last_polled_at;
    elapsed.whole_milliseconds() < i128::from(interval)
}

fn token_oauth_error_response(
    status: StatusCode,
    error: OAuthDeviceError,
    description: &str,
) -> Result<ApiResponse, OpenAuthError> {
    let mut response = oauth_error_response(status, error, description)?;
    add_token_cache_headers(&mut response);
    Ok(response)
}

fn add_token_cache_headers(response: &mut ApiResponse) {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    response
        .headers_mut()
        .insert(header::PRAGMA, http::HeaderValue::from_static("no-cache"));
}

fn additional_session_create_values(context: &AuthContext) -> DbRecord {
    context
        .options
        .session
        .additional_fields
        .iter()
        .map(|(name, field)| {
            (
                name.clone(),
                field.default_value.clone().unwrap_or(DbValue::Null),
            )
        })
        .collect()
}

fn request_user_agent(request: &ApiRequest) -> Option<String> {
    request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn request_ip(request: &ApiRequest) -> Option<String> {
    request
        .headers()
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            request
                .headers()
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        })
}
