mod create;
mod delete;
mod delete_expired;
mod get;
mod list;
mod update;
mod verify;

use std::sync::Arc;

use http::{header, Method, StatusCode};
use openauth_core::api::{
    create_auth_endpoint, parse_request_body, ApiRequest, ApiResponse, AuthEndpointOptions,
    BodyField, BodySchema, JsonSchemaType, OpenApiOperation,
};
use openauth_core::auth::session::{GetSessionInput, SessionAuth};
use openauth_core::context::AuthContext;
use openauth_core::db::User;
use openauth_core::error::OpenAuthError;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use time::{Duration, OffsetDateTime};
use url::form_urlencoded;

pub use create::{create_endpoint, CreateApiKeyRequest};
pub use delete::{delete_endpoint, DeleteApiKeyRequest};
pub use delete_expired::delete_expired_endpoint;
pub use get::{get_endpoint, GetApiKeyQuery};
pub use list::{list_endpoint, ListApiKeysQuery};
pub use update::{update_endpoint, UpdateApiKeyRequest, UpdateField};
pub use verify::{validate_api_key, verify_endpoint, VerifyApiKeyRequest, VerifyApiKeyResponse};

use super::errors;
use super::options::ResolvedConfigurations;

pub(crate) type SharedConfigurations = Arc<ResolvedConfigurations>;

#[derive(Debug, Clone)]
pub(crate) struct CurrentIdentity {
    pub user: User,
}

pub(crate) fn endpoint(
    path: &'static str,
    method: Method,
    configurations: SharedConfigurations,
    handler: impl for<'a> Fn(
            &'a AuthContext,
            ApiRequest,
            SharedConfigurations,
        ) -> openauth_core::api::EndpointFuture<'a>
        + Send
        + Sync
        + 'static,
) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        path,
        method,
        endpoint_options(path),
        move |context, request| handler(context, request, configurations.clone()),
    )
}

fn endpoint_options(path: &str) -> AuthEndpointOptions {
    let (operation_id, summary, body_schema) = match path {
        "/api-key/create" => (
            "createApiKey",
            "Create API key",
            Some(create_api_key_body_schema()),
        ),
        "/api-key/verify" => (
            "verifyApiKey",
            "Verify API key",
            Some(verify_api_key_body_schema()),
        ),
        "/api-key/get" => ("getApiKey", "Get API key", None),
        "/api-key/update" => (
            "updateApiKey",
            "Update API key",
            Some(update_api_key_body_schema()),
        ),
        "/api-key/delete" => (
            "deleteApiKey",
            "Delete API key",
            Some(delete_api_key_body_schema()),
        ),
        "/api-key/list" => ("listApiKeys", "List API keys", None),
        "/api-key/delete-all-expired-api-keys" => {
            ("deleteAllExpiredApiKeys", "Delete expired API keys", None)
        }
        _ => ("apiKeyEndpoint", "API key endpoint", None),
    };

    let operation = OpenApiOperation::new(operation_id)
        .summary(summary)
        .description(format!("{summary} endpoint"))
        .tag("API Key")
        .response("200", openapi_object_response("API key response"));
    let options = AuthEndpointOptions::new()
        .operation_id(operation_id)
        .openapi(operation);
    match body_schema {
        Some(schema) => options
            .allowed_media_types(["application/json"])
            .body_schema(schema),
        None => options,
    }
}

fn create_api_key_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::optional("configId", JsonSchemaType::String),
        BodyField::optional("name", JsonSchemaType::String),
        BodyField::optional("expiresIn", JsonSchemaType::Number),
        BodyField::optional("prefix", JsonSchemaType::String),
        BodyField::optional("remaining", JsonSchemaType::Number),
        BodyField::optional("metadata", JsonSchemaType::Object),
        BodyField::optional("refillAmount", JsonSchemaType::Number),
        BodyField::optional("refillInterval", JsonSchemaType::Number),
        BodyField::optional("rateLimitTimeWindow", JsonSchemaType::Number),
        BodyField::optional("rateLimitMax", JsonSchemaType::Number),
        BodyField::optional("rateLimitEnabled", JsonSchemaType::Boolean),
        BodyField::optional("permissions", JsonSchemaType::Object),
        BodyField::optional("userId", JsonSchemaType::String),
        BodyField::optional("organizationId", JsonSchemaType::String),
    ])
}

fn verify_api_key_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::optional("configId", JsonSchemaType::String),
        BodyField::new("key", JsonSchemaType::String),
        BodyField::optional("permissions", JsonSchemaType::Object),
    ])
}

fn update_api_key_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("keyId", JsonSchemaType::String),
        BodyField::optional("configId", JsonSchemaType::String),
        BodyField::optional("userId", JsonSchemaType::String),
        BodyField::optional("name", JsonSchemaType::String),
        BodyField::optional("enabled", JsonSchemaType::Boolean),
        BodyField::optional("remaining", JsonSchemaType::Number),
        BodyField::optional("refillAmount", JsonSchemaType::Number),
        BodyField::optional("refillInterval", JsonSchemaType::Number),
        BodyField::optional("metadata", JsonSchemaType::Object),
        BodyField::optional("expiresIn", JsonSchemaType::Number),
        BodyField::optional("rateLimitEnabled", JsonSchemaType::Boolean),
        BodyField::optional("rateLimitTimeWindow", JsonSchemaType::Number),
        BodyField::optional("rateLimitMax", JsonSchemaType::Number),
        BodyField::optional("permissions", JsonSchemaType::Object),
    ])
}

fn delete_api_key_body_schema() -> BodySchema {
    BodySchema::object([BodyField::new("keyId", JsonSchemaType::String)])
}

fn openapi_object_response(description: &str) -> Value {
    serde_json::json!({
        "description": description,
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                },
            },
        },
    })
}

pub(crate) fn json<T: Serialize>(
    status: StatusCode,
    body: &T,
) -> Result<ApiResponse, OpenAuthError> {
    let body = serde_json::to_vec(body).map_err(|error| OpenAuthError::Api(error.to_string()))?;
    http::Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .map_err(|error| OpenAuthError::Api(error.to_string()))
}

pub(crate) fn error(status: StatusCode, code: &str) -> Result<ApiResponse, OpenAuthError> {
    errors::error_response(status, code)
}

pub(crate) fn body<T: DeserializeOwned>(request: &ApiRequest) -> Result<T, OpenAuthError> {
    parse_request_body(request)
}

pub(crate) fn query_param(request: &ApiRequest, name: &str) -> Option<String> {
    form_urlencoded::parse(request.uri().query()?.as_bytes())
        .find_map(|(key, value)| (key == name).then(|| value.into_owned()))
}

pub(crate) fn query_usize(request: &ApiRequest, name: &str) -> Option<usize> {
    query_param(request, name)?.parse().ok()
}

pub(crate) async fn current_identity(
    context: &AuthContext,
    request: &ApiRequest,
) -> Result<Option<CurrentIdentity>, OpenAuthError> {
    let Some(adapter) = context.adapter() else {
        return Ok(None);
    };
    let cookie_header = request
        .headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let Some(result) = SessionAuth::new(adapter.as_ref(), context)
        .get_session(GetSessionInput::new(cookie_header))
        .await?
    else {
        return Ok(None);
    };
    let Some(user) = result.user else {
        return Ok(None);
    };
    Ok(Some(CurrentIdentity { user }))
}

pub(crate) fn metadata_is_object(metadata: &Option<Value>) -> bool {
    matches!(metadata, None | Some(Value::Object(_)))
}

pub(crate) fn future_expiration(seconds: Option<i64>) -> Option<OffsetDateTime> {
    seconds.map(|seconds| OffsetDateTime::now_utc() + Duration::seconds(seconds))
}

pub(crate) fn valid_prefix(prefix: &str) -> bool {
    prefix
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

pub(crate) fn is_default_config_id(config_id: &str) -> bool {
    config_id == "default" || config_id.is_empty()
}

pub(crate) fn config_id_matches(actual: &str, expected: &str) -> bool {
    actual == expected || (is_default_config_id(actual) && is_default_config_id(expected))
}
