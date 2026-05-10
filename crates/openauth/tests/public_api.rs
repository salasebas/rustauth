use http::{Method, Request, StatusCode};
use openauth::{
    core_auth_async_endpoints, create_auth_endpoint, open_auth, open_auth_with_endpoints,
    ApiErrorResponse, ApiRequest, ApiResponse, AsyncAuthEndpoint, AuthEndpoint,
    AuthEndpointOptions, AuthPlugin, BodyField, BodySchema, CookieCacheStrategy, EndpointKind,
    JsonSchemaType, OpenApiOperation, OpenAuthError, OpenAuthOptions, PluginRequestAction,
    RateLimitOptions, SessionAuth, SignOutResult, TrustedOriginOptions, UpdateUserInput,
};

#[test]
fn openauth_crate_exposes_product_initializer() -> Result<(), Box<dyn std::error::Error>> {
    let auth = open_auth(OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let request = Request::builder()
        .method(Method::GET)
        .uri("http://localhost:3000/api/auth/ok")
        .body(Vec::new())?;

    let response = auth.handler(request)?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.body(), b"OK");
    Ok(())
}

#[test]
fn openauth_crate_reexports_core_primitives() {
    let token = openauth::crypto::random::generate_random_string(16);

    assert_eq!(token.len(), 16);
}

#[tokio::test]
async fn openauth_instance_exposes_async_handler() -> Result<(), Box<dyn std::error::Error>> {
    let auth = open_auth(OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let request = Request::builder()
        .method(Method::GET)
        .uri("http://localhost:3000/api/auth/ok")
        .body(Vec::new())?;

    let response = auth.handler_async(request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.body(), b"OK");
    Ok(())
}

#[test]
fn openauth_crate_reexports_core_contract_types() {
    fn _uses_api_request(_request: ApiRequest) {}
    fn _uses_api_response(_response: ApiResponse) {}
    fn _uses_error(_error: OpenAuthError) {}

    let _endpoint_type: Option<AuthEndpoint> = None;
    let _async_endpoint_type: Option<AsyncAuthEndpoint> = None;
    let _api_error = ApiErrorResponse {
        code: "TEST".to_owned(),
        message: "test".to_owned(),
    };
    let _plugin = AuthPlugin::new("test-plugin");
    let _action_type: Option<PluginRequestAction> = None;
    let _trusted_origins = TrustedOriginOptions::default();
    let _rate_limit = RateLimitOptions::default();
    let _cookie_strategy = CookieCacheStrategy::Jwe;
    let _memory_storage = openauth::rate_limit::MemoryRateLimitStorage::new();
    let _session_auth_type: Option<SessionAuth<'_>> = None;
    let _update_user = UpdateUserInput::new().name("Ada").image(None);
    let _route_builder = core_auth_async_endpoints;
    let _endpoint_options = AuthEndpointOptions::new()
        .operation_id("testOperation")
        .body_schema(BodySchema::object([BodyField::new(
            "email",
            JsonSchemaType::String,
        )]))
        .openapi(OpenApiOperation::new("testOperation"));
    let _built_endpoint = create_auth_endpoint(
        "/test",
        Method::GET,
        AuthEndpointOptions::new(),
        |_context, _request| {
            Box::pin(async move { openauth::api::response(StatusCode::OK, Vec::new()) })
        },
    );
    let _sign_out = SignOutResult {
        success: true,
        cookies: Vec::new(),
    };
}

#[tokio::test]
async fn openauth_initializer_accepts_extra_endpoints_and_exposes_registry(
) -> Result<(), Box<dyn std::error::Error>> {
    let extra = AuthEndpoint {
        path: "/custom".to_owned(),
        method: Method::GET,
        handler: |_context, _request| openauth::api::response(StatusCode::OK, b"CUSTOM".to_vec()),
    };
    let async_extra = AsyncAuthEndpoint::new("/async-custom", Method::GET, |_context, _request| {
        Box::pin(async move { openauth::api::response(StatusCode::OK, b"ASYNC CUSTOM".to_vec()) })
    });
    let auth = open_auth_with_endpoints(
        OpenAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            ..OpenAuthOptions::default()
        },
        vec![extra],
        vec![async_extra],
    )?;

    let registry = auth.endpoint_registry();
    assert!(registry
        .iter()
        .any(|endpoint| endpoint.path == "/ok" && endpoint.kind == EndpointKind::Sync));
    assert!(registry
        .iter()
        .any(|endpoint| endpoint.path == "/custom" && endpoint.kind == EndpointKind::Sync));
    assert!(registry
        .iter()
        .any(|endpoint| endpoint.path == "/async-custom" && endpoint.kind == EndpointKind::Async));

    let sync_response = auth.handler(
        Request::builder()
            .method(Method::GET)
            .uri("http://localhost:3000/api/auth/custom")
            .body(Vec::new())?,
    )?;
    assert_eq!(sync_response.body(), b"CUSTOM");

    let async_response = auth
        .handler_async(
            Request::builder()
                .method(Method::GET)
                .uri("http://localhost:3000/api/auth/async-custom")
                .body(Vec::new())?,
        )
        .await?;
    assert_eq!(async_response.body(), b"ASYNC CUSTOM");
    let openapi = auth.openapi_schema();
    assert_eq!(openapi["openapi"], "3.1.1");
    Ok(())
}

#[test]
fn openauth_initializer_rejects_endpoint_conflicts() -> Result<(), Box<dyn std::error::Error>> {
    let conflicting = AuthEndpoint {
        path: "/ok".to_owned(),
        method: Method::GET,
        handler: |_context, _request| openauth::api::response(StatusCode::OK, Vec::new()),
    };

    let result = open_auth_with_endpoints(
        OpenAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            ..OpenAuthOptions::default()
        },
        vec![conflicting],
        Vec::new(),
    );

    assert!(
        matches!(result, Err(OpenAuthError::Api(message)) if message.contains("endpoint conflict"))
    );
    Ok(())
}
