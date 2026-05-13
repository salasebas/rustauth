//! Framework-neutral API contracts.

pub mod body;
pub mod routes;

use http::{header, Method, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::auth::trusted_origins::OriginMatchSettings;
use crate::context::request_state::run_with_request_state;
use crate::context::AuthContext;
use crate::error::OpenAuthError;
use crate::plugin::PluginRequestAction;
use crate::rate_limit::{on_request_rate_limit, on_response_rate_limit, RateLimitRejection};
use crate::utils::url::normalize_pathname;
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

pub use body::parse_request_body;
pub use routes::core_auth_async_endpoints;

pub type Body = Vec<u8>;
pub type ApiRequest = Request<Body>;
pub type ApiResponse = Response<Body>;
pub type EndpointHandler = fn(&AuthContext, ApiRequest) -> Result<ApiResponse, OpenAuthError>;
pub type EndpointFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ApiResponse, OpenAuthError>> + Send + 'a>>;
pub type AsyncEndpointHandler =
    Arc<dyn for<'a> Fn(&'a AuthContext, ApiRequest) -> EndpointFuture<'a> + Send + Sync>;
pub type EndpointMiddlewareFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Option<ApiResponse>, OpenAuthError>> + Send + 'a>>;
pub type EndpointMiddlewareHandler = Arc<
    dyn for<'a> Fn(&'a AuthContext, &'a ApiRequest) -> EndpointMiddlewareFuture<'a> + Send + Sync,
>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiErrorCode {
    NotFound,
    InvalidOrigin,
    InvalidCallbackUrl,
    InvalidRedirectUrl,
    InvalidErrorCallbackUrl,
    InvalidNewUserCallbackUrl,
    MissingOrNullOrigin,
    CrossSiteNavigationLoginBlocked,
    TooManyRequests,
}

impl ApiErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "NOT_FOUND",
            Self::InvalidOrigin => "INVALID_ORIGIN",
            Self::InvalidCallbackUrl => "INVALID_CALLBACK_URL",
            Self::InvalidRedirectUrl => "INVALID_REDIRECT_URL",
            Self::InvalidErrorCallbackUrl => "INVALID_ERROR_CALLBACK_URL",
            Self::InvalidNewUserCallbackUrl => "INVALID_NEW_USER_CALLBACK_URL",
            Self::MissingOrNullOrigin => "MISSING_OR_NULL_ORIGIN",
            Self::CrossSiteNavigationLoginBlocked => "CROSS_SITE_NAVIGATION_LOGIN_BLOCKED",
            Self::TooManyRequests => "TOO_MANY_REQUESTS",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::NotFound => "Not Found",
            Self::InvalidOrigin => "Invalid origin",
            Self::InvalidCallbackUrl => "Invalid callbackURL",
            Self::InvalidRedirectUrl => "Invalid redirectURL",
            Self::InvalidErrorCallbackUrl => "Invalid errorCallbackURL",
            Self::InvalidNewUserCallbackUrl => "Invalid newUserCallbackURL",
            Self::MissingOrNullOrigin => "Missing or null Origin",
            Self::CrossSiteNavigationLoginBlocked => {
                "Cross-site navigation login blocked. This request appears to be a CSRF attack."
            }
            Self::TooManyRequests => "Too many requests. Please try again later.",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiErrorResponse {
    pub code: String,
    pub message: String,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "originalMessage")]
    pub original_message: Option<String>,
}

#[derive(Clone)]
pub struct EndpointMiddleware {
    pub handler: EndpointMiddlewareHandler,
}

impl EndpointMiddleware {
    pub fn new<F>(handler: F) -> Self
    where
        F: for<'a> Fn(&'a AuthContext, &'a ApiRequest) -> EndpointMiddlewareFuture<'a>
            + Send
            + Sync
            + 'static,
    {
        Self {
            handler: Arc::new(handler),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JsonSchemaType {
    String,
    Number,
    Boolean,
    Array,
    Object,
}

impl JsonSchemaType {
    fn as_str(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Number => "number",
            Self::Boolean => "boolean",
            Self::Array => "array",
            Self::Object => "object",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BodyField {
    pub name: String,
    pub schema_type: JsonSchemaType,
    pub required: bool,
    pub format: Option<String>,
    pub description: Option<String>,
}

impl BodyField {
    pub fn new(name: impl Into<String>, schema_type: JsonSchemaType) -> Self {
        Self {
            name: name.into(),
            schema_type,
            required: true,
            format: None,
            description: None,
        }
    }

    pub fn optional(name: impl Into<String>, schema_type: JsonSchemaType) -> Self {
        Self {
            required: false,
            ..Self::new(name, schema_type)
        }
    }

    #[must_use]
    pub fn format(mut self, format: impl Into<String>) -> Self {
        self.format = Some(format.into());
        self
    }

    #[must_use]
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BodySchema {
    pub fields: Vec<BodyField>,
}

impl BodySchema {
    pub fn object(fields: impl IntoIterator<Item = BodyField>) -> Self {
        Self {
            fields: fields.into_iter().collect(),
        }
    }

    fn validate(&self, value: &Value) -> Result<(), String> {
        let Some(object) = value.as_object() else {
            return Err("request body must be an object".to_owned());
        };
        for field in &self.fields {
            let Some(value) = object.get(&field.name) else {
                if field.required {
                    return Err(format!("missing required field `{}`", field.name));
                }
                continue;
            };
            if !json_type_matches(value, field.schema_type) {
                return Err(format!(
                    "field `{}` must be {}",
                    field.name,
                    field.schema_type.as_str()
                ));
            }
        }
        Ok(())
    }

    fn openapi_schema(&self) -> Value {
        let mut properties = serde_json::Map::new();
        let mut required = Vec::new();
        for field in &self.fields {
            let mut schema = serde_json::Map::new();
            schema.insert(
                "type".to_owned(),
                Value::String(field.schema_type.as_str().to_owned()),
            );
            if let Some(format) = &field.format {
                schema.insert("format".to_owned(), Value::String(format.clone()));
            }
            if let Some(description) = &field.description {
                schema.insert("description".to_owned(), Value::String(description.clone()));
            }
            properties.insert(field.name.clone(), Value::Object(schema));
            if field.required {
                required.push(Value::String(field.name.clone()));
            }
        }
        json!({
            "type": "object",
            "properties": properties,
            "required": required,
        })
    }
}

fn json_type_matches(value: &Value, schema_type: JsonSchemaType) -> bool {
    match schema_type {
        JsonSchemaType::String => value.is_string(),
        JsonSchemaType::Number => value.is_number(),
        JsonSchemaType::Boolean => value.is_boolean(),
        JsonSchemaType::Array => value.is_array(),
        JsonSchemaType::Object => value.is_object(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenApiOperation {
    pub operation_id: Option<String>,
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub parameters: Vec<Value>,
    pub request_body: Option<Value>,
    pub responses: BTreeMap<String, Value>,
}

impl OpenApiOperation {
    pub fn new(operation_id: impl Into<String>) -> Self {
        Self {
            operation_id: Some(operation_id.into()),
            description: None,
            tags: Vec::new(),
            parameters: Vec::new(),
            request_body: None,
            responses: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    #[must_use]
    pub fn tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    #[must_use]
    pub fn request_body(mut self, request_body: Value) -> Self {
        self.request_body = Some(request_body);
        self
    }

    #[must_use]
    pub fn parameter(mut self, parameter: Value) -> Self {
        self.parameters.push(parameter);
        self
    }

    #[must_use]
    pub fn response(mut self, status: impl Into<String>, response: Value) -> Self {
        self.responses.insert(status.into(), response);
        self
    }
}

#[derive(Clone, Default)]
pub struct AuthEndpointOptions {
    pub operation_id: Option<String>,
    pub allowed_media_types: Vec<String>,
    pub body_schema: Option<BodySchema>,
    pub middlewares: Vec<EndpointMiddleware>,
    pub openapi: Option<OpenApiOperation>,
}

impl AuthEndpointOptions {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn operation_id(mut self, operation_id: impl Into<String>) -> Self {
        self.operation_id = Some(operation_id.into());
        self
    }

    #[must_use]
    pub fn allowed_media_types<I, S>(mut self, media_types: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allowed_media_types = media_types.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn body_schema(mut self, schema: BodySchema) -> Self {
        self.body_schema = Some(schema);
        self
    }

    #[must_use]
    pub fn middleware(mut self, middleware: EndpointMiddleware) -> Self {
        self.middlewares.push(middleware);
        self
    }

    #[must_use]
    pub fn openapi(mut self, operation: OpenApiOperation) -> Self {
        self.openapi = Some(operation);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointKind {
    Sync,
    Async,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointInfo {
    pub path: String,
    pub method: http::Method,
    pub kind: EndpointKind,
    pub operation_id: Option<String>,
    pub allowed_media_types: Vec<String>,
}

#[derive(Clone)]
pub struct AuthEndpoint {
    pub path: String,
    pub method: http::Method,
    pub handler: EndpointHandler,
}

#[derive(Clone)]
pub struct AsyncAuthEndpoint {
    pub path: String,
    pub method: http::Method,
    pub handler: AsyncEndpointHandler,
    pub options: AuthEndpointOptions,
}

impl AsyncAuthEndpoint {
    pub fn new<F>(path: impl Into<String>, method: http::Method, handler: F) -> Self
    where
        F: for<'a> Fn(&'a AuthContext, ApiRequest) -> EndpointFuture<'a> + Send + Sync + 'static,
    {
        Self {
            path: path.into(),
            method,
            handler: Arc::new(handler),
            options: AuthEndpointOptions::default(),
        }
    }
}

pub fn create_auth_endpoint<F>(
    path: impl Into<String>,
    method: http::Method,
    options: AuthEndpointOptions,
    handler: F,
) -> AsyncAuthEndpoint
where
    F: for<'a> Fn(&'a AuthContext, ApiRequest) -> EndpointFuture<'a> + Send + Sync + 'static,
{
    AsyncAuthEndpoint {
        path: path.into(),
        method,
        handler: Arc::new(handler),
        options,
    }
}

#[derive(Clone)]
pub struct AuthRouter {
    context: AuthContext,
    endpoints: Vec<AuthEndpoint>,
    async_endpoints: Vec<AsyncAuthEndpoint>,
}

impl AuthRouter {
    pub fn new(context: AuthContext, endpoints: Vec<AuthEndpoint>) -> Self {
        Self {
            context,
            endpoints,
            async_endpoints: Vec::new(),
        }
    }

    pub fn try_new(
        context: AuthContext,
        endpoints: Vec<AuthEndpoint>,
    ) -> Result<Self, OpenAuthError> {
        validate_endpoint_conflicts(&endpoints, &[])?;
        Ok(Self {
            context,
            endpoints,
            async_endpoints: Vec::new(),
        })
    }

    pub fn with_async_endpoints(
        context: AuthContext,
        endpoints: Vec<AuthEndpoint>,
        async_endpoints: Vec<AsyncAuthEndpoint>,
    ) -> Result<Self, OpenAuthError> {
        validate_endpoint_conflicts(&endpoints, &async_endpoints)?;
        Ok(Self {
            context,
            endpoints,
            async_endpoints,
        })
    }

    pub fn endpoint_registry(&self) -> Vec<EndpointInfo> {
        let sync_endpoints = self.endpoints.iter().map(|endpoint| EndpointInfo {
            path: endpoint.path.clone(),
            method: endpoint.method.clone(),
            kind: EndpointKind::Sync,
            operation_id: None,
            allowed_media_types: Vec::new(),
        });
        let async_endpoints = self.async_endpoints.iter().map(|endpoint| EndpointInfo {
            path: endpoint.path.clone(),
            method: endpoint.method.clone(),
            kind: EndpointKind::Async,
            operation_id: endpoint
                .options
                .operation_id
                .clone()
                .or_else(|| endpoint.options.openapi.as_ref()?.operation_id.clone()),
            allowed_media_types: endpoint.options.allowed_media_types.clone(),
        });
        sync_endpoints.chain(async_endpoints).collect()
    }

    pub fn openapi_schema(&self) -> Value {
        let mut paths = serde_json::Map::new();
        for endpoint in &self.async_endpoints {
            let path = paths
                .entry(to_openapi_path(&endpoint.path))
                .or_insert_with(|| Value::Object(serde_json::Map::new()));
            let Value::Object(methods) = path else {
                continue;
            };
            methods.insert(
                endpoint.method.as_str().to_ascii_lowercase(),
                openapi_operation_for_endpoint(endpoint),
            );
        }
        json!({
            "openapi": "3.1.1",
            "info": {
                "title": "OpenAuth",
                "description": "API Reference for your OpenAuth instance",
                "version": crate::VERSION,
            },
            "components": {
                "schemas": openapi_model_schemas(),
                "securitySchemes": {
                    "apiKeyCookie": {
                        "type": "apiKey",
                        "in": "cookie",
                        "name": "apiKeyCookie",
                        "description": "API Key authentication via cookie",
                    },
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                        "description": "Bearer token authentication",
                    },
                },
            },
            "security": [
                {
                    "apiKeyCookie": [],
                    "bearerAuth": [],
                },
            ],
            "servers": [
                {
                    "url": self.context.base_url,
                },
            ],
            "tags": [
                {
                    "name": "Default",
                    "description": "Default endpoints that are included with OpenAuth by default. These endpoints are not part of any plugin.",
                },
            ],
            "paths": paths,
        })
    }

    pub fn handle(&self, mut request: ApiRequest) -> Result<ApiResponse, OpenAuthError> {
        let normalized_path =
            normalize_pathname(&request.uri().to_string(), &self.context.base_path);
        if self
            .context
            .disabled_paths
            .iter()
            .any(|item| item == &normalized_path)
        {
            return api_error(StatusCode::NOT_FOUND, ApiErrorCode::NotFound);
        }
        request = match run_on_request_plugins(&self.context, request)? {
            PluginRequestAction::Continue(request) => request,
            PluginRequestAction::Respond(response) => return Ok(response),
        };
        if let Some(rejection) = validate_request_security(&self.context, &request)? {
            return Ok(rejection);
        }
        let path = route_pathname(
            &request.uri().to_string(),
            &self.context.base_path,
            self.context.options.advanced.skip_trailing_slashes,
        );
        let Some(endpoint) = self
            .endpoints
            .iter()
            .find(|endpoint| endpoint.method == *request.method() && endpoint.path == path)
        else {
            if self
                .async_endpoints
                .iter()
                .any(|endpoint| endpoint.method == *request.method() && endpoint.path == path)
            {
                return Err(OpenAuthError::Api(
                    "async endpoint requires AuthRouter::handle_async".to_owned(),
                ));
            }
            return api_error(StatusCode::NOT_FOUND, ApiErrorCode::NotFound);
        };
        if let Some(response) = run_matching_middlewares(&self.context, &request, &path)? {
            return Ok(response);
        }
        if let Some(rejection) = on_request_rate_limit(&self.context, &request)? {
            return rate_limit_response(rejection);
        }
        let response = (endpoint.handler)(&self.context, request.clone())?;
        on_response_rate_limit(&self.context, &request)?;
        run_on_response_plugins(&self.context, &request, response)
    }

    pub async fn handle_async(&self, request: ApiRequest) -> Result<ApiResponse, OpenAuthError> {
        run_with_request_state(self.handle_async_scoped(request)).await
    }

    async fn handle_async_scoped(
        &self,
        mut request: ApiRequest,
    ) -> Result<ApiResponse, OpenAuthError> {
        let normalized_path =
            normalize_pathname(&request.uri().to_string(), &self.context.base_path);
        if self
            .context
            .disabled_paths
            .iter()
            .any(|item| item == &normalized_path)
        {
            return api_error(StatusCode::NOT_FOUND, ApiErrorCode::NotFound);
        }
        request = match run_on_request_plugins(&self.context, request)? {
            PluginRequestAction::Continue(request) => request,
            PluginRequestAction::Respond(response) => return Ok(response),
        };
        if let Some(rejection) = validate_request_security(&self.context, &request)? {
            return Ok(rejection);
        }
        let path = route_pathname(
            &request.uri().to_string(),
            &self.context.base_path,
            self.context.options.advanced.skip_trailing_slashes,
        );
        let async_endpoint = self
            .async_endpoints
            .iter()
            .find(|endpoint| endpoint.method == *request.method() && endpoint.path == path);
        let sync_endpoint = self
            .endpoints
            .iter()
            .find(|endpoint| endpoint.method == *request.method() && endpoint.path == path);
        if async_endpoint.is_none() && sync_endpoint.is_none() {
            return api_error(StatusCode::NOT_FOUND, ApiErrorCode::NotFound);
        }
        if let Some(response) = run_matching_middlewares(&self.context, &request, &path)? {
            return Ok(response);
        }
        if let Some(rejection) = on_request_rate_limit(&self.context, &request)? {
            return rate_limit_response(rejection);
        }
        if let Some(endpoint) = async_endpoint {
            if let Some(response) = validate_async_endpoint_request(endpoint, &request)? {
                return Ok(response);
            }
            if let Some(response) =
                run_endpoint_middlewares(&self.context, endpoint, &request).await?
            {
                return Ok(response);
            }
            let response = (endpoint.handler)(&self.context, request.clone()).await?;
            on_response_rate_limit(&self.context, &request)?;
            return run_on_response_plugins(&self.context, &request, response);
        }
        if let Some(endpoint) = sync_endpoint {
            let response = (endpoint.handler)(&self.context, request.clone())?;
            on_response_rate_limit(&self.context, &request)?;
            return run_on_response_plugins(&self.context, &request, response);
        }
        unreachable!("endpoint existence checked before rate limiting")
    }
}

pub fn ok_endpoint(
    _context: &AuthContext,
    _request: ApiRequest,
) -> Result<ApiResponse, OpenAuthError> {
    response(StatusCode::OK, b"OK".to_vec())
}

pub fn core_endpoints() -> Vec<AuthEndpoint> {
    vec![AuthEndpoint {
        path: "/ok".to_owned(),
        method: http::Method::GET,
        handler: ok_endpoint,
    }]
}

pub fn response(status: StatusCode, body: Body) -> Result<ApiResponse, OpenAuthError> {
    Response::builder()
        .status(status)
        .body(body)
        .map_err(|error| OpenAuthError::Api(error.to_string()))
}

pub fn api_error(status: StatusCode, code: ApiErrorCode) -> Result<ApiResponse, OpenAuthError> {
    let body = serde_json::to_vec(&ApiErrorResponse {
        code: code.as_str().to_owned(),
        message: code.message().to_owned(),
        original_message: None,
    })
    .map_err(|error| OpenAuthError::Api(error.to_string()))?;

    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .map_err(|error| OpenAuthError::Api(error.to_string()))
}

fn validate_request_security(
    context: &AuthContext,
    request: &ApiRequest,
) -> Result<Option<ApiResponse>, OpenAuthError> {
    if matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    ) {
        return Ok(None);
    }

    if !context.options.advanced.disable_csrf_check
        && !context.options.advanced.disable_origin_check
    {
        if request.headers().contains_key(http::header::COOKIE) {
            if let Some(rejection) = validate_origin_header(context, request)? {
                return Ok(Some(rejection));
            }
        } else if has_fetch_metadata(request) {
            if header_value(request, "sec-fetch-site") == Some("cross-site")
                && header_value(request, "sec-fetch-mode") == Some("navigate")
            {
                return forbidden(ApiErrorCode::CrossSiteNavigationLoginBlocked).map(Some);
            }
            if let Some(rejection) = validate_origin_header(context, request)? {
                return Ok(Some(rejection));
            }
        }
    }

    if context.options.advanced.disable_origin_check {
        return Ok(None);
    }

    for (label, url) in callback_urls(request) {
        let settings = Some(OriginMatchSettings {
            allow_relative_paths: true,
        });
        if !context.is_trusted_origin_for_request(&url, settings, Some(request))? {
            return forbidden(callback_error_code(label)).map(Some);
        }
    }

    Ok(None)
}

fn validate_origin_header(
    context: &AuthContext,
    request: &ApiRequest,
) -> Result<Option<ApiResponse>, OpenAuthError> {
    let Some(origin) = request_origin(request) else {
        return forbidden(ApiErrorCode::MissingOrNullOrigin).map(Some);
    };
    if origin == "null" {
        return forbidden(ApiErrorCode::MissingOrNullOrigin).map(Some);
    }
    if !context.is_trusted_origin_for_request(origin, None, Some(request))? {
        return forbidden(ApiErrorCode::InvalidOrigin).map(Some);
    }
    Ok(None)
}

fn request_origin(request: &ApiRequest) -> Option<&str> {
    request
        .headers()
        .get(http::header::ORIGIN)
        .or_else(|| request.headers().get(http::header::REFERER))
        .and_then(|value| value.to_str().ok())
}

fn has_fetch_metadata(request: &ApiRequest) -> bool {
    ["sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest"]
        .iter()
        .any(|name| header_value(request, name).is_some_and(|value| !value.trim().is_empty()))
}

fn header_value<'a>(request: &'a ApiRequest, name: &str) -> Option<&'a str> {
    request.headers().get(name)?.to_str().ok()
}

fn callback_urls(request: &ApiRequest) -> Vec<(&'static str, String)> {
    let mut urls = Vec::new();
    for key in [
        "callbackURL",
        "redirectTo",
        "errorCallbackURL",
        "newUserCallbackURL",
    ] {
        if let Some(value) = query_param(request.uri().query(), key) {
            urls.push((url_label(key), value));
        }
    }

    if let Ok(Value::Object(body)) = serde_json::from_slice::<Value>(request.body()) {
        for key in [
            "callbackURL",
            "redirectTo",
            "errorCallbackURL",
            "newUserCallbackURL",
        ] {
            if let Some(Value::String(value)) = body.get(key) {
                urls.push((url_label(key), value.clone()));
            }
        }
    }

    urls
}

fn query_param(query: Option<&str>, key: &str) -> Option<String> {
    query?.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (decode_query_component(name) == key).then(|| decode_query_component(value))
    })
}

fn decode_query_component(value: &str) -> String {
    let mut decoded = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let high = hex_value(bytes[index + 1]);
                let low = hex_value(bytes[index + 2]);
                if let (Some(high), Some(low)) = (high, low) {
                    decoded.push((high << 4) | low);
                    index += 3;
                } else {
                    decoded.push(bytes[index]);
                    index += 1;
                }
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }

    String::from_utf8(decoded).unwrap_or_else(|_| value.to_owned())
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn url_label(key: &str) -> &'static str {
    match key {
        "callbackURL" => "callbackURL",
        "redirectTo" => "redirectURL",
        "errorCallbackURL" => "errorCallbackURL",
        "newUserCallbackURL" => "newUserCallbackURL",
        _ => "url",
    }
}

fn callback_error_code(label: &str) -> ApiErrorCode {
    match label {
        "callbackURL" => ApiErrorCode::InvalidCallbackUrl,
        "redirectURL" => ApiErrorCode::InvalidRedirectUrl,
        "errorCallbackURL" => ApiErrorCode::InvalidErrorCallbackUrl,
        "newUserCallbackURL" => ApiErrorCode::InvalidNewUserCallbackUrl,
        _ => ApiErrorCode::InvalidCallbackUrl,
    }
}

fn forbidden(code: ApiErrorCode) -> Result<ApiResponse, OpenAuthError> {
    api_error(StatusCode::FORBIDDEN, code)
}

fn rate_limit_response(rejection: RateLimitRejection) -> Result<ApiResponse, OpenAuthError> {
    let mut response = api_error(StatusCode::TOO_MANY_REQUESTS, ApiErrorCode::TooManyRequests)?;
    response.headers_mut().insert(
        "X-Retry-After",
        http::HeaderValue::from_str(&rejection.retry_after.to_string())
            .map_err(|error| OpenAuthError::Api(error.to_string()))?,
    );
    Ok(response)
}

fn validate_async_endpoint_request(
    endpoint: &AsyncAuthEndpoint,
    request: &ApiRequest,
) -> Result<Option<ApiResponse>, OpenAuthError> {
    if endpoint.options.allowed_media_types.is_empty() && endpoint.options.body_schema.is_none() {
        return Ok(None);
    }

    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if !endpoint.options.allowed_media_types.is_empty() {
        let Some(content_type) = content_type else {
            return invalid_request_response(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "UNSUPPORTED_MEDIA_TYPE",
                "Missing Content-Type",
            )
            .map(Some);
        };
        if !endpoint
            .options
            .allowed_media_types
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(content_type))
        {
            return invalid_request_response(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "UNSUPPORTED_MEDIA_TYPE",
                "Unsupported Content-Type",
            )
            .map(Some);
        }
    }

    if let Some(schema) = &endpoint.options.body_schema {
        let body = match parse_request_body::<Value>(request) {
            Ok(body) => body,
            Err(error) => {
                return invalid_request_response(
                    StatusCode::BAD_REQUEST,
                    "INVALID_REQUEST_BODY",
                    &error.to_string(),
                )
                .map(Some);
            }
        };
        if let Err(message) = schema.validate(&body) {
            return invalid_request_response(
                StatusCode::BAD_REQUEST,
                "INVALID_REQUEST_BODY",
                &message,
            )
            .map(Some);
        }
    }

    Ok(None)
}

async fn run_endpoint_middlewares(
    context: &AuthContext,
    endpoint: &AsyncAuthEndpoint,
    request: &ApiRequest,
) -> Result<Option<ApiResponse>, OpenAuthError> {
    for middleware in &endpoint.options.middlewares {
        if let Some(response) = (middleware.handler)(context, request).await? {
            return Ok(Some(response));
        }
    }
    Ok(None)
}

fn invalid_request_response(
    status: StatusCode,
    code: &str,
    message: &str,
) -> Result<ApiResponse, OpenAuthError> {
    let body = serde_json::to_vec(&ApiErrorResponse {
        code: code.to_owned(),
        message: message.to_owned(),
        original_message: None,
    })
    .map_err(|error| OpenAuthError::Api(error.to_string()))?;

    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .map_err(|error| OpenAuthError::Api(error.to_string()))
}

fn openapi_operation_for_endpoint(endpoint: &AsyncAuthEndpoint) -> Value {
    let operation = endpoint
        .options
        .openapi
        .clone()
        .unwrap_or_else(|| OpenApiOperation {
            operation_id: endpoint.options.operation_id.clone(),
            description: None,
            tags: Vec::new(),
            parameters: Vec::new(),
            request_body: None,
            responses: BTreeMap::new(),
        });
    let request_body = operation.request_body.or_else(|| {
        endpoint
            .options
            .body_schema
            .as_ref()
            .map(|schema| {
                json!({
                    "required": true,
                    "content": {
                        "application/json": {
                            "schema": schema.openapi_schema(),
                        },
                    },
                })
            })
            .or_else(|| {
                method_uses_request_body(&endpoint.method).then(|| {
                    json!({
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {},
                                },
                            },
                        },
                    })
                })
            })
    });
    let mut responses = default_openapi_responses();
    for (status, response) in operation.responses {
        responses.insert(status, response);
    }
    let mut tags = vec!["Default".to_owned()];
    for tag in operation.tags {
        if !tags.iter().any(|existing| existing == &tag) {
            tags.push(tag);
        }
    }

    let mut value = serde_json::Map::new();
    value.insert(
        "tags".to_owned(),
        Value::Array(tags.into_iter().map(Value::String).collect()),
    );
    if let Some(description) = operation.description {
        value.insert("description".to_owned(), Value::String(description));
    }
    if let Some(operation_id) = operation
        .operation_id
        .or_else(|| endpoint.options.operation_id.clone())
    {
        value.insert("operationId".to_owned(), Value::String(operation_id));
    }
    value.insert(
        "security".to_owned(),
        json!([
            {
                "bearerAuth": [],
            },
        ]),
    );
    value.insert("parameters".to_owned(), Value::Array(operation.parameters));
    if let Some(request_body) = request_body {
        value.insert("requestBody".to_owned(), request_body);
    }
    value.insert("responses".to_owned(), Value::Object(responses));
    Value::Object(value)
}

fn method_uses_request_body(method: &Method) -> bool {
    matches!(*method, Method::POST | Method::PATCH | Method::PUT)
}

fn to_openapi_path(path: &str) -> String {
    path.split('/')
        .map(|part| {
            part.strip_prefix(':')
                .map(|name| format!("{{{name}}}"))
                .unwrap_or_else(|| part.to_owned())
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn default_openapi_responses() -> serde_json::Map<String, Value> {
    let mut responses = serde_json::Map::new();
    responses.insert(
        "400".to_owned(),
        openapi_error_response(
            "Bad Request. Usually due to missing parameters, or invalid parameters.",
            true,
        ),
    );
    responses.insert(
        "401".to_owned(),
        openapi_error_response(
            "Unauthorized. Due to missing or invalid authentication.",
            true,
        ),
    );
    responses.insert(
        "403".to_owned(),
        openapi_error_response(
            "Forbidden. You do not have permission to access this resource or to perform this action.",
            false,
        ),
    );
    responses.insert(
        "404".to_owned(),
        openapi_error_response("Not Found. The requested resource was not found.", false),
    );
    responses.insert(
        "429".to_owned(),
        openapi_error_response(
            "Too Many Requests. You have exceeded the rate limit. Try again later.",
            false,
        ),
    );
    responses.insert(
        "500".to_owned(),
        openapi_error_response(
            "Internal Server Error. This is a problem with the server that you cannot fix.",
            false,
        ),
    );
    responses
}

fn openapi_error_response(description: &str, require_message: bool) -> Value {
    let required = require_message.then(|| json!(["message"]));
    let mut schema = serde_json::Map::new();
    schema.insert("type".to_owned(), Value::String("object".to_owned()));
    schema.insert(
        "properties".to_owned(),
        json!({
            "message": {
                "type": "string",
            },
        }),
    );
    if let Some(required) = required {
        schema.insert("required".to_owned(), required);
    }
    json!({
        "content": {
            "application/json": {
                "schema": Value::Object(schema),
            },
        },
        "description": description,
    })
}

fn openapi_model_schemas() -> Value {
    json!({
        "User": {
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "email": { "type": "string", "format": "email" },
                "name": { "type": "string" },
                "image": { "type": "string", "format": "uri", "nullable": true },
                "emailVerified": { "type": "boolean" },
                "createdAt": { "type": "string", "format": "date-time" },
                "updatedAt": { "type": "string", "format": "date-time" },
            },
            "required": ["id", "email", "name", "emailVerified", "createdAt", "updatedAt"],
        },
        "Session": {
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "userId": { "type": "string" },
                "expiresAt": { "type": "string", "format": "date-time" },
                "token": { "type": "string" },
                "ipAddress": { "type": "string", "nullable": true },
                "userAgent": { "type": "string", "nullable": true },
                "createdAt": { "type": "string", "format": "date-time" },
                "updatedAt": { "type": "string", "format": "date-time" },
            },
            "required": ["id", "userId", "expiresAt", "token", "createdAt", "updatedAt"],
        },
        "Account": {
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "providerId": { "type": "string" },
                "accountId": { "type": "string" },
                "userId": { "type": "string" },
                "accessToken": { "type": "string", "nullable": true },
                "refreshToken": { "type": "string", "nullable": true },
                "idToken": { "type": "string", "nullable": true },
                "scope": { "type": "string", "nullable": true },
                "password": { "type": "string", "nullable": true },
                "createdAt": { "type": "string", "format": "date-time" },
                "updatedAt": { "type": "string", "format": "date-time" },
            },
            "required": ["id", "providerId", "accountId", "userId", "createdAt", "updatedAt"],
        },
        "Verification": {
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "identifier": { "type": "string" },
                "value": { "type": "string" },
                "expiresAt": { "type": "string", "format": "date-time" },
                "createdAt": { "type": "string", "format": "date-time" },
                "updatedAt": { "type": "string", "format": "date-time" },
            },
            "required": ["id", "identifier", "value", "expiresAt", "createdAt", "updatedAt"],
        },
    })
}

fn run_on_request_plugins(
    context: &AuthContext,
    mut request: ApiRequest,
) -> Result<PluginRequestAction, OpenAuthError> {
    for plugin in &context.plugins {
        if let Some(hook) = &plugin.on_request {
            match hook(context, request)? {
                PluginRequestAction::Continue(next_request) => request = next_request,
                PluginRequestAction::Respond(response) => {
                    return Ok(PluginRequestAction::Respond(response));
                }
            }
        }
    }
    Ok(PluginRequestAction::Continue(request))
}

fn run_matching_middlewares(
    context: &AuthContext,
    request: &ApiRequest,
    path: &str,
) -> Result<Option<ApiResponse>, OpenAuthError> {
    for plugin in &context.plugins {
        for middleware in &plugin.middlewares {
            if path_matches(&middleware.path, path) {
                if let Some(response) = (middleware.handler)(context, request)? {
                    return Ok(Some(response));
                }
            }
        }
    }
    Ok(None)
}

fn run_on_response_plugins(
    context: &AuthContext,
    request: &ApiRequest,
    mut response: ApiResponse,
) -> Result<ApiResponse, OpenAuthError> {
    for plugin in &context.plugins {
        if let Some(hook) = &plugin.on_response {
            response = hook(context, request, response)?;
        }
    }
    Ok(response)
}

fn validate_endpoint_conflicts(
    endpoints: &[AuthEndpoint],
    async_endpoints: &[AsyncAuthEndpoint],
) -> Result<(), OpenAuthError> {
    let mut seen = HashSet::new();
    for endpoint in endpoints {
        let key = (endpoint.method.clone(), endpoint.path.clone());
        if !seen.insert(key) {
            return Err(OpenAuthError::Api(format!(
                "endpoint conflict for {} {}",
                endpoint.method, endpoint.path
            )));
        }
    }
    for endpoint in async_endpoints {
        let key = (endpoint.method.clone(), endpoint.path.clone());
        if !seen.insert(key) {
            return Err(OpenAuthError::Api(format!(
                "endpoint conflict for {} {}",
                endpoint.method, endpoint.path
            )));
        }
    }
    Ok(())
}

fn path_matches(pattern: &str, path: &str) -> bool {
    if let Some((prefix, suffix)) = pattern.split_once('*') {
        return path.starts_with(prefix) && path.ends_with(suffix);
    }
    pattern == path
}

fn route_pathname(request_url: &str, base_path: &str, skip_trailing_slashes: bool) -> String {
    if skip_trailing_slashes {
        return normalize_pathname(request_url, base_path);
    }

    let Some(pathname) = pathname_from_url(request_url) else {
        return "/".to_owned();
    };
    let base_path = trim_trailing_slashes(base_path);

    if base_path == "/" {
        return pathname;
    }
    if pathname == base_path {
        return "/".to_owned();
    }

    let base_prefix = format!("{base_path}/");
    if let Some(without_base_path) = pathname.strip_prefix(&base_prefix) {
        format!("/{without_base_path}")
    } else {
        pathname
    }
}

fn pathname_from_url(request_url: &str) -> Option<String> {
    let (_, after_scheme) = request_url.split_once("://")?;
    let path_start = after_scheme.find('/')?;
    let path_with_query = &after_scheme[path_start..];
    let path = path_with_query
        .split_once('?')
        .map_or(path_with_query, |(path, _)| path);
    let path = path.split_once('#').map_or(path, |(path, _)| path);

    Some(path.to_owned())
}

fn trim_trailing_slashes(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_owned()
    } else if trimmed.starts_with('/') {
        trimmed.to_owned()
    } else {
        format!("/{trimmed}")
    }
}
