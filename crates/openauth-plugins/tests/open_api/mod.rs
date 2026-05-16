use std::sync::Arc;

use http::{header, Method, Request, StatusCode};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::db::MemoryAdapter;
use openauth_core::error::OpenAuthError;
use openauth_core::options::{AdvancedOptions, OpenAuthOptions};
use openauth_plugins::anonymous::{anonymous, AnonymousOptions};
use openauth_plugins::email_otp::{email_otp, EmailOtpOptions};
use openauth_plugins::generic_oauth::{generic_oauth, GenericOAuthConfig, GenericOAuthOptions};
use openauth_plugins::jwt::jwt;
use openauth_plugins::magic_link::{magic_link, MagicLinkEmail, MagicLinkOptions};
use openauth_plugins::mcp::{mcp, McpOptions};
use openauth_plugins::multi_session::multi_session;
use openauth_plugins::oauth_proxy::oauth_proxy_default;
use openauth_plugins::one_tap::{one_tap, OneTapOptions};
use openauth_plugins::one_time_token::one_time_token;
use openauth_plugins::open_api::{open_api, OpenApiOptions};
use openauth_plugins::organization::{
    organization_with_options, DynamicAccessControlOptions, OrganizationOptions, TeamOptions,
};
use openauth_plugins::phone_number::{phone_number, PhoneNumberOptions};
use openauth_plugins::siwe::{siwe, SiweOptions};
use openauth_plugins::two_factor::{two_factor, TwoFactorOptions};
use openauth_plugins::username::username;
use serde_json::Value;

#[test]
fn exposes_open_api_plugin_builder() {
    let plugin = open_api(OpenApiOptions::default());

    assert_eq!(openauth_plugins::open_api::UPSTREAM_PLUGIN_ID, "open-api");
    assert_eq!(plugin.id, "open-api");
    assert!(plugin
        .endpoints
        .iter()
        .any(|endpoint| endpoint.path == "/open-api/generate-schema"));
    assert!(plugin
        .endpoints
        .iter()
        .any(|endpoint| endpoint.path == "/reference"));
}

#[tokio::test]
async fn generate_schema_endpoint_returns_core_and_plugin_paths(
) -> Result<(), Box<dyn std::error::Error>> {
    let router = router(vec![
        open_api(OpenApiOptions::default()),
        anonymous(AnonymousOptions::default()),
    ])?;

    let response = router
        .handle_async(request(Method::GET, "/api/auth/open-api/generate-schema")?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body["openapi"], "3.1.1");
    assert_eq!(
        body["paths"]["/sign-in/email"]["post"]["operationId"],
        "signInEmail"
    );
    assert_eq!(
        body["paths"]["/sign-in/anonymous"]["post"]["operationId"],
        "signInAnonymous"
    );
    assert_eq!(
        body["paths"]["/open-api/generate-schema"]["get"]["operationId"],
        "generateOpenAPISchema"
    );
    assert!(body["paths"]["/reference"].is_null());
    Ok(())
}

#[tokio::test]
async fn generated_schema_includes_detailed_plugin_metadata(
) -> Result<(), Box<dyn std::error::Error>> {
    let router = router(vec![
        open_api(OpenApiOptions::default()),
        anonymous(AnonymousOptions::default()),
    ])?;

    let response = router
        .handle_async(request(Method::GET, "/api/auth/open-api/generate-schema")?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;
    let anonymous = &body["paths"]["/sign-in/anonymous"]["post"];

    assert_eq!(anonymous["summary"], "Sign in anonymous");
    assert_eq!(anonymous["tags"][0], "Anonymous");
    assert!(anonymous["description"]
        .as_str()
        .is_some_and(|value| !value.is_empty()));
    assert!(anonymous["responses"]["200"].is_object());
    Ok(())
}

#[tokio::test]
async fn generated_schema_audits_all_server_plugin_endpoints(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router(vec![
        open_api(OpenApiOptions::default()),
        anonymous(AnonymousOptions::default()),
        username(),
        multi_session(),
        one_time_token(),
        organization_with_options(
            OrganizationOptions::builder()
                .teams(TeamOptions {
                    enabled: true,
                    create_default_team: true,
                    maximum_teams: None,
                    maximum_members_per_team: None,
                    allow_removing_all_teams: false,
                })
                .dynamic_access_control(DynamicAccessControlOptions {
                    enabled: true,
                    maximum_roles_per_organization: None,
                })
                .build(),
        ),
        jwt()?,
        phone_number(adapter.clone(), PhoneNumberOptions::default()),
        email_otp(adapter.clone(), EmailOtpOptions::default()),
        mcp(McpOptions {
            login_page: "/login".to_owned(),
            ..McpOptions::default()
        })?
        .into_auth_plugin(),
        two_factor(TwoFactorOptions::default()),
        oauth_proxy_default(),
        one_tap(OneTapOptions::default()),
        magic_link(MagicLinkOptions::new(|_email: MagicLinkEmail| {
            Box::pin(async { Ok(()) })
        })),
        siwe(SiweOptions::new(
            "example.com",
            || async { Ok("nonce".to_owned()) },
            |_args| async { Ok(true) },
        ))?,
    ])?;

    let response = router
        .handle_async(request(Method::GET, "/api/auth/open-api/generate-schema")?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;
    let paths = body["paths"].as_object().ok_or("missing paths")?;

    assert!(body["paths"]["/reference"].is_null());
    assert!(paths.len() > 80, "expected broad endpoint coverage");

    for (path, methods) in paths {
        let methods = methods
            .as_object()
            .ok_or_else(|| format!("path {path} is not an object"))?;
        for (method, operation) in methods {
            let context = format!("{method} {path}");
            assert_non_empty_string(operation, "operationId", &context);
            assert_non_empty_string(operation, "summary", &context);
            assert_non_empty_string(operation, "description", &context);
            assert!(
                operation["tags"]
                    .as_array()
                    .is_some_and(|tags| !tags.is_empty()),
                "{context} missing tags"
            );
            assert!(
                has_success_response(operation),
                "{context} missing explicit success or redirect response"
            );
            assert_path_parameters_documented(path, operation, &context);
        }
    }

    for (operation_id, required_property, expected_type) in [
        ("signInPhoneNumber", "phoneNumber", "string"),
        ("sendPhoneNumberOTP", "phoneNumber", "string"),
        ("verifyPhoneNumber", "phoneNumber", "string"),
        ("registerMcpClient", "redirect_uris", "array"),
        ("getSiweNonce", "walletAddress", "string"),
        ("verifySiweMessage", "message", "string"),
    ] {
        let operation = find_operation(paths, operation_id)
            .ok_or_else(|| format!("missing operation {operation_id}"))?;
        assert_eq!(
            operation["requestBody"]["content"]["application/json"]["schema"]["properties"]
                [required_property]["type"],
            expected_type,
            "{operation_id} missing documented request body property {required_property}"
        );
    }

    let generic_schema = plugin_only_openapi(generic_oauth(GenericOAuthOptions {
        config: vec![GenericOAuthConfig::new(
            "example",
            "client-id",
            Some("client-secret"),
            "https://oauth.example/authorize",
            "https://oauth.example/token",
        )],
    }))?;
    let generic_paths = generic_schema["paths"]
        .as_object()
        .ok_or("missing generic paths")?;
    for operation_id in ["signInWithOAuth2", "oAuth2LinkAccount"] {
        let operation = find_operation(generic_paths, operation_id)
            .ok_or_else(|| format!("missing operation {operation_id}"))?;
        assert_eq!(
            operation["requestBody"]["content"]["application/json"]["schema"]["properties"]
                ["providerId"]["type"],
            "string"
        );
    }

    Ok(())
}

#[tokio::test]
async fn reference_endpoint_serves_scalar_html() -> Result<(), Box<dyn std::error::Error>> {
    let router = router(vec![open_api(
        OpenApiOptions::default()
            .path("/docs")
            .theme("moon")
            .nonce("nonce-123"),
    )])?;

    let response = router
        .handle_async(request(Method::GET, "/api/auth/docs")?)
        .await?;
    let body = String::from_utf8(response.body().clone())?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/html; charset=utf-8")
    );
    assert!(body.contains("@scalar/api-reference"));
    assert!(body.contains("theme: \"moon\""));
    assert!(body.contains("nonce=\"nonce-123\""));
    Ok(())
}

#[tokio::test]
async fn reference_endpoint_can_be_disabled() -> Result<(), Box<dyn std::error::Error>> {
    let router = router(vec![open_api(
        OpenApiOptions::default().disable_default_reference(true),
    )])?;

    let response = router
        .handle_async(request(Method::GET, "/api/auth/reference")?)
        .await?;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    Ok(())
}

fn router(plugins: Vec<openauth_core::plugin::AuthPlugin>) -> Result<AuthRouter, OpenAuthError> {
    let adapter = Arc::new(MemoryAdapter::default());
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            base_url: Some("http://localhost:3000".to_owned()),
            secret: Some("test-secret-123456789012345678901234".to_owned()),
            advanced: AdvancedOptions {
                disable_csrf_check: true,
                disable_origin_check: true,
                ..AdvancedOptions::default()
            },
            plugins,
            ..OpenAuthOptions::default()
        },
        adapter.clone(),
    )?;
    AuthRouter::with_async_endpoints(context, Vec::new(), core_auth_async_endpoints(adapter))
}

fn plugin_only_openapi(
    plugin: openauth_core::plugin::AuthPlugin,
) -> Result<Value, Box<dyn std::error::Error>> {
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            base_url: Some("http://localhost:3000".to_owned()),
            secret: Some("test-secret-123456789012345678901234".to_owned()),
            advanced: AdvancedOptions {
                disable_csrf_check: true,
                disable_origin_check: true,
                ..AdvancedOptions::default()
            },
            plugins: vec![plugin],
            ..OpenAuthOptions::default()
        },
        Arc::new(MemoryAdapter::new()),
    )?;
    Ok(AuthRouter::try_new(context, Vec::new())?.openapi_schema())
}

fn request(method: Method, path: &str) -> Result<Request<Vec<u8>>, http::Error> {
    Request::builder()
        .method(method)
        .uri(format!("http://localhost:3000{path}"))
        .body(Vec::new())
}

fn assert_non_empty_string(operation: &Value, field: &str, context: &str) {
    assert!(
        operation[field]
            .as_str()
            .is_some_and(|value| !value.trim().is_empty()),
        "{context} missing {field}"
    );
}

fn has_success_response(operation: &Value) -> bool {
    operation["responses"].as_object().is_some_and(|responses| {
        responses
            .keys()
            .any(|status| status.starts_with('2') || status.starts_with('3'))
    })
}

fn assert_path_parameters_documented(path: &str, operation: &Value, context: &str) {
    for parameter in path
        .split('/')
        .filter_map(|part| part.strip_prefix('{')?.strip_suffix('}'))
    {
        let documented = operation["parameters"]
            .as_array()
            .is_some_and(|parameters| {
                parameters.iter().any(|entry| {
                    entry["name"] == parameter && entry["in"] == "path" && entry["required"] == true
                })
            });
        assert!(
            documented,
            "{context} missing path parameter documentation for {parameter}"
        );
    }
}

fn find_operation<'a>(
    paths: &'a serde_json::Map<String, Value>,
    operation_id: &str,
) -> Option<&'a Value> {
    paths
        .values()
        .filter_map(Value::as_object)
        .flat_map(|methods| methods.values())
        .find(|operation| operation["operationId"] == operation_id)
}
