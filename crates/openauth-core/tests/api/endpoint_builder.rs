use http::{header, Method, Request, StatusCode};
use openauth_core::api::{
    create_auth_endpoint, empty_openapi_response, path_param, query_param,
    redirect_openapi_response, response, AuthEndpointOptions, AuthRouter, BodyField, BodySchema,
    EndpointMiddleware, JsonSchemaType, OpenApiOperation,
};
use openauth_core::context::create_auth_context;
use openauth_core::error::OpenAuthError;
use openauth_core::options::OpenAuthOptions;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[tokio::test]
async fn create_auth_endpoint_exposes_metadata_and_openapi(
) -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = create_auth_endpoint(
        "/sign-up/email",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("signUpWithEmailAndPassword")
            .allowed_media_types(["application/json", "application/x-www-form-urlencoded"])
            .body_schema(sign_up_body_schema())
            .openapi(
                OpenApiOperation::new("signUpWithEmailAndPassword")
                    .description("Sign up a user using email and password")
                    .tag("Default")
                    .response(
                        "200",
                        json!({
                            "description": "Successfully created user",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "token": { "type": "string" },
                                            "user": { "$ref": "#/components/schemas/User" }
                                        },
                                        "required": ["user"]
                                    }
                                }
                            }
                        }),
                    ),
            ),
        |_context, _request| {
            Box::pin(async move { response(StatusCode::OK, br#"{"ok":true}"#.to_vec()) })
        },
    );
    let router = router(vec![endpoint])?;

    let registry = router.endpoint_registry();
    let endpoint = registry
        .iter()
        .find(|endpoint| endpoint.path == "/sign-up/email")
        .ok_or("missing endpoint")?;
    assert_eq!(
        endpoint.operation_id.as_deref(),
        Some("signUpWithEmailAndPassword")
    );
    assert_eq!(
        endpoint.allowed_media_types,
        vec!["application/json", "application/x-www-form-urlencoded"]
    );

    let openapi = router.openapi_schema();
    assert_eq!(openapi["openapi"], "3.1.1");
    assert_eq!(openapi["info"]["title"], "OpenAuth");
    assert_eq!(
        openapi["components"]["securitySchemes"]["bearerAuth"]["scheme"],
        "bearer"
    );
    assert_eq!(openapi["security"][0]["bearerAuth"], json!([]));
    assert_eq!(openapi["servers"][0]["url"], "");
    assert_eq!(openapi["tags"][0]["name"], "Default");
    assert_eq!(
        openapi["components"]["schemas"]["User"]["properties"]["email"]["format"],
        "email"
    );
    assert_eq!(
        openapi["paths"]["/sign-up/email"]["post"]["operationId"],
        "signUpWithEmailAndPassword"
    );
    assert_eq!(
        openapi["paths"]["/sign-up/email"]["post"]["security"][0]["bearerAuth"],
        json!([])
    );
    assert_eq!(
        openapi["paths"]["/sign-up/email"]["post"]["requestBody"]["content"]["application/json"]
            ["schema"]["required"],
        serde_json::json!(["name", "email", "password"])
    );
    assert!(
        openapi["paths"]["/sign-up/email"]["post"]["requestBody"]["content"]
            ["application/x-www-form-urlencoded"]
            .is_null()
    );
    assert_eq!(
        openapi["paths"]["/sign-up/email"]["post"]["responses"]["200"]["description"],
        "Successfully created user"
    );
    assert_eq!(
        openapi["paths"]["/sign-up/email"]["post"]["responses"]["400"]["description"],
        "Bad Request. Usually due to missing parameters, or invalid parameters."
    );
    Ok(())
}

#[tokio::test]
async fn openapi_generation_matches_upstream_route_shape() -> Result<(), Box<dyn std::error::Error>>
{
    let reset_endpoint = create_auth_endpoint(
        "/reset-password/:token",
        Method::GET,
        AuthEndpointOptions::new().openapi(
            OpenApiOperation::new("resetPasswordCallback")
                .description("Reset password callback")
                .parameter(json!({
                    "name": "token",
                    "in": "path",
                    "required": true,
                    "schema": { "type": "string" }
                })),
        ),
        |_context, _request| Box::pin(async move { response(StatusCode::OK, Vec::new()) }),
    );
    let sign_out_endpoint = create_auth_endpoint(
        "/sign-out",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("signOut")
            .openapi(OpenApiOperation::new("signOut").description("Sign out")),
        |_context, _request| Box::pin(async move { response(StatusCode::OK, Vec::new()) }),
    );
    let router = router(vec![reset_endpoint, sign_out_endpoint])?;

    let openapi = router.openapi_schema();

    assert!(openapi["paths"]["/reset-password/{token}"]["get"].is_object());
    assert_eq!(
        openapi["paths"]["/reset-password/{token}"]["get"]["parameters"][0]["name"],
        "token"
    );
    assert_eq!(
        openapi["paths"]["/sign-out"]["post"]["requestBody"]["content"]["application/json"]
            ["schema"],
        json!({
            "type": "object",
            "properties": {}
        })
    );
    assert_eq!(
        openapi["paths"]["/sign-out"]["post"]["responses"]["401"]["description"],
        "Unauthorized. Due to missing or invalid authentication."
    );
    Ok(())
}

#[tokio::test]
async fn openapi_contract_supports_summary_helpers_and_hidden_endpoints(
) -> Result<(), Box<dyn std::error::Error>> {
    let visible = create_auth_endpoint(
        "/oauth/callback/:provider",
        Method::GET,
        AuthEndpointOptions::new().openapi(
            OpenApiOperation::new("oauthCallback")
                .summary("OAuth callback")
                .description("Handle an OAuth provider callback")
                .parameter(path_param("provider", "OAuth provider id"))
                .parameter(query_param("code", "Authorization code"))
                .response("302", redirect_openapi_response("Redirect after callback")),
        ),
        |_context, _request| Box::pin(async move { response(StatusCode::FOUND, Vec::new()) }),
    );
    let hidden = create_auth_endpoint(
        "/reference",
        Method::GET,
        AuthEndpointOptions::new().hide_from_openapi().openapi(
            OpenApiOperation::new("openApiReference")
                .summary("OpenAPI reference")
                .description("Serve the interactive OpenAPI reference")
                .response("200", empty_openapi_response("HTML reference")),
        ),
        |_context, _request| Box::pin(async move { response(StatusCode::OK, Vec::new()) }),
    );
    let router = router(vec![visible, hidden])?;

    let openapi = router.openapi_schema();
    let callback = &openapi["paths"]["/oauth/callback/{provider}"]["get"];

    assert_eq!(callback["summary"], "OAuth callback");
    assert_eq!(callback["parameters"][0]["name"], "provider");
    assert_eq!(callback["parameters"][0]["in"], "path");
    assert_eq!(callback["parameters"][1]["name"], "code");
    assert_eq!(
        callback["responses"]["302"]["headers"]["Location"]["schema"]["type"],
        "string"
    );
    assert!(openapi["paths"]["/reference"].is_null());
    Ok(())
}

#[tokio::test]
async fn create_auth_endpoint_validates_body_schema_before_handler(
) -> Result<(), Box<dyn std::error::Error>> {
    let called = Arc::new(AtomicBool::new(false));
    let called_in_handler = Arc::clone(&called);
    let endpoint = create_auth_endpoint(
        "/sign-up/email",
        Method::POST,
        AuthEndpointOptions::new()
            .allowed_media_types(["application/json"])
            .body_schema(sign_up_body_schema()),
        move |_context, _request| {
            called_in_handler.store(true, Ordering::SeqCst);
            Box::pin(async move { response(StatusCode::OK, Vec::new()) })
        },
    );
    let router = router(vec![endpoint])?;

    let response = router
        .handle_async(
            Request::builder()
                .method(Method::POST)
                .uri("http://localhost:3000/api/auth/sign-up/email")
                .header(header::CONTENT_TYPE, "application/json")
                .body(br#"{"email":"ada@example.com","password":"secret123"}"#.to_vec())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "INVALID_REQUEST_BODY");
    assert!(!called.load(Ordering::SeqCst));
    Ok(())
}

#[tokio::test]
async fn create_auth_endpoint_allows_null_for_optional_body_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = create_auth_endpoint(
        "/sign-up/email",
        Method::POST,
        AuthEndpointOptions::new()
            .allowed_media_types(["application/json"])
            .body_schema(sign_up_body_schema()),
        |_context, _request| Box::pin(async move { response(StatusCode::OK, Vec::new()) }),
    );
    let router = router(vec![endpoint])?;

    let response = router
        .handle_async(
            Request::builder()
                .method(Method::POST)
                .uri("http://localhost:3000/api/auth/sign-up/email")
                .header(header::CONTENT_TYPE, "application/json")
                .body(
                    br#"{"name":"Ada","email":"ada@example.com","password":"secret123","image":null}"#
                        .to_vec(),
                )?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn create_auth_endpoint_runs_endpoint_middleware_before_handler(
) -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = create_auth_endpoint(
        "/blocked",
        Method::POST,
        AuthEndpointOptions::new().middleware(EndpointMiddleware::new(|_context, _request| {
            Box::pin(async move { response(StatusCode::FORBIDDEN, b"blocked".to_vec()).map(Some) })
        })),
        |_context, _request| Box::pin(async move { response(StatusCode::OK, b"handler".to_vec()) }),
    );
    let router = router(vec![endpoint])?;

    let response = router
        .handle_async(
            Request::builder()
                .method(Method::POST)
                .uri("http://localhost:3000/api/auth/blocked")
                .body(Vec::new())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response.body(), b"blocked");
    Ok(())
}

fn router(
    endpoints: Vec<openauth_core::api::AsyncAuthEndpoint>,
) -> Result<AuthRouter, OpenAuthError> {
    let context = create_auth_context(OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    AuthRouter::with_async_endpoints(context, Vec::new(), endpoints)
}

fn sign_up_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("name", JsonSchemaType::String),
        BodyField::new("email", JsonSchemaType::String).format("email"),
        BodyField::new("password", JsonSchemaType::String),
        BodyField::optional("image", JsonSchemaType::String),
        BodyField::optional("rememberMe", JsonSchemaType::Boolean),
    ])
}
