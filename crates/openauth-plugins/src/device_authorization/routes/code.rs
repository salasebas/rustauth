use std::sync::Arc;

use http::{header, Method, StatusCode};
use openauth_core::api::{
    create_auth_endpoint, parse_request_body, AuthEndpointOptions, BodyField, BodySchema,
    JsonSchemaType,
};
use openauth_core::context::AuthContext;
use openauth_core::crypto::random::generate_random_string;
use openauth_core::db::DbAdapter;
use openauth_core::error::OpenAuthError;
use openauth_core::plugin::PluginEndpoint;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use url::Url;

use crate::device_authorization::errors::{oauth_error_response, OAuthDeviceError};
use crate::device_authorization::options::{AsyncDeviceCodeGenerator, DeviceAuthorizationOptions};
use crate::device_authorization::store::{CreateDeviceCodeInput, DeviceCodeStore};

const DEFAULT_USER_CODE_CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct DeviceCodeRequest {
    pub client_id: String,
    pub scope: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct DeviceCodeResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: i64,
    pub interval: i64,
}

pub fn device_code(options: Arc<DeviceAuthorizationOptions>) -> PluginEndpoint {
    create_auth_endpoint(
        "/device/code",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("deviceCode")
            .allowed_media_types(["application/json", "application/x-www-form-urlencoded"])
            .openapi(super::openapi::device_code_operation())
            .body_schema(BodySchema::object([
                BodyField::new("client_id", JsonSchemaType::String),
                BodyField::optional("scope", JsonSchemaType::String),
            ])),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                let body = parse_request_body::<DeviceCodeRequest>(&request)?;
                if let Some(validate_client) = &options.validate_client {
                    if !(validate_client)(body.client_id.clone()).await? {
                        return oauth_error_response(
                            StatusCode::BAD_REQUEST,
                            OAuthDeviceError::InvalidClient,
                            "Invalid client ID",
                        );
                    }
                }
                if let Some(hook) = &options.on_device_auth_request {
                    (hook)(body.client_id.clone(), body.scope.clone()).await?;
                }

                let adapter = required_adapter(context)?;
                let device_code = generate_code(
                    options.generate_device_code.as_ref(),
                    options.device_code_length,
                    default_device_code,
                )
                .await;
                let user_code = generate_code(
                    options.generate_user_code.as_ref(),
                    options.user_code_length,
                    default_user_code,
                )
                .await;
                let expires_in = options.expires_in.whole_seconds();
                let interval = options.interval.whole_seconds();
                let polling_interval = i64::try_from(options.interval.whole_milliseconds())
                    .map_err(|_| {
                        OpenAuthError::InvalidConfig(
                            "device authorization interval is too large".to_owned(),
                        )
                    })?;

                DeviceCodeStore::new(adapter.as_ref())
                    .create(CreateDeviceCodeInput {
                        device_code: device_code.clone(),
                        user_code: super::clean_user_code(&user_code),
                        expires_at: OffsetDateTime::now_utc() + options.expires_in,
                        polling_interval,
                        client_id: body.client_id,
                        scope: body.scope,
                    })
                    .await?;

                let (verification_uri, verification_uri_complete) = build_verification_uris(
                    &options.verification_uri,
                    &context.base_url,
                    &user_code,
                )?;
                let mut response = super::json_response(
                    StatusCode::OK,
                    &DeviceCodeResponse {
                        device_code,
                        user_code,
                        verification_uri,
                        verification_uri_complete,
                        expires_in,
                        interval,
                    },
                )?;
                response.headers_mut().insert(
                    header::CACHE_CONTROL,
                    http::HeaderValue::from_static("no-store"),
                );
                Ok(response)
            })
        },
    )
}

fn required_adapter(context: &AuthContext) -> Result<Arc<dyn DbAdapter>, OpenAuthError> {
    context.adapter().ok_or_else(|| {
        OpenAuthError::Adapter("device authorization requires a database adapter".to_owned())
    })
}

async fn generate_code(
    generator: Option<&AsyncDeviceCodeGenerator>,
    length: usize,
    fallback: fn(usize) -> String,
) -> String {
    match generator {
        Some(generator) => generator().await,
        None => fallback(length),
    }
}

fn default_device_code(length: usize) -> String {
    generate_random_string(length)
}

fn default_user_code(length: usize) -> String {
    let mut bytes = vec![0_u8; length];
    OsRng.fill_bytes(&mut bytes);
    bytes
        .into_iter()
        .map(|byte| {
            let index = usize::from(byte) % DEFAULT_USER_CODE_CHARSET.len();
            char::from(DEFAULT_USER_CODE_CHARSET[index])
        })
        .collect()
}

fn build_verification_uris(
    verification_uri: &str,
    base_url: &str,
    user_code: &str,
) -> Result<(String, String), OpenAuthError> {
    let verification_url = Url::parse(verification_uri)
        .or_else(|_| Url::parse(base_url).and_then(|base| base.join(verification_uri)))
        .map_err(|error| OpenAuthError::InvalidConfig(error.to_string()))?;
    let mut complete = verification_url.clone();
    complete
        .query_pairs_mut()
        .append_pair("user_code", user_code);
    Ok((verification_url.to_string(), complete.to_string()))
}
