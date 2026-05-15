use http::{Method, StatusCode};
use openauth_core::api::{create_auth_endpoint, AuthEndpointOptions};
use openauth_core::plugin::PluginEndpoint;
use serde::{Deserialize, Serialize};
use url::form_urlencoded;

use crate::device_authorization::errors::{oauth_error_response, OAuthDeviceError};
use crate::device_authorization::routes::token::required_adapter;
use crate::device_authorization::store::DeviceCodeStore;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct DeviceVerificationResponse {
    pub user_code: String,
    pub status: String,
}

pub fn device_verify() -> PluginEndpoint {
    create_auth_endpoint(
        "/device",
        Method::GET,
        AuthEndpointOptions::new()
            .operation_id("deviceVerify")
            .openapi(super::openapi::device_verify_operation()),
        |_context, request| {
            Box::pin(async move {
                let Some(user_code) = query_param(request.uri().query(), "user_code") else {
                    return oauth_error_response(
                        StatusCode::BAD_REQUEST,
                        OAuthDeviceError::InvalidRequest,
                        "Invalid user code",
                    );
                };
                let adapter = required_adapter(_context)?;
                let store = DeviceCodeStore::new(adapter.as_ref());
                let clean = super::clean_user_code(&user_code);
                let Some(record) = store.find_by_user_code(&clean).await? else {
                    return oauth_error_response(
                        StatusCode::BAD_REQUEST,
                        OAuthDeviceError::InvalidRequest,
                        "Invalid user code",
                    );
                };
                if record.expires_at < time::OffsetDateTime::now_utc() {
                    return oauth_error_response(
                        StatusCode::BAD_REQUEST,
                        OAuthDeviceError::ExpiredToken,
                        "User code has expired",
                    );
                }
                super::json_response(
                    StatusCode::OK,
                    &DeviceVerificationResponse {
                        user_code,
                        status: record.status.as_str().to_owned(),
                    },
                )
            })
        },
    )
}

fn query_param(query: Option<&str>, name: &str) -> Option<String> {
    form_urlencoded::parse(query?.as_bytes())
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}
