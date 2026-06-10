use std::sync::Arc;

use http::{header, Method, Request, StatusCode};
use openauth_core::api::{
    core_auth_async_endpoints, create_auth_endpoint, AuthEndpointOptions, AuthRouter,
    OpenApiOperation,
};
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::db::{DbFieldType, DbValue, MemoryAdapter};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{AdvancedOptions, OpenAuthOptions, UserAdditionalField, UserOptions};
use openauth_core::plugin::AuthPlugin;
use openauth_plugins::anonymous::anonymous;
use openauth_plugins::api_key::api_key;
use openauth_plugins::email_otp::{email_otp_with, EmailOtpOptions};
use openauth_plugins::generic_oauth::{
    generic_oauth_with, GenericOAuthConfig, GenericOAuthOptions,
};
use openauth_plugins::jwt::jwt;
use openauth_plugins::magic_link::{magic_link_with, MagicLinkEmail, MagicLinkOptions};
use openauth_plugins::multi_session::multi_session;
use openauth_plugins::oauth_proxy::oauth_proxy;
use openauth_plugins::one_tap::one_tap;
use openauth_plugins::one_time_token::one_time_token;
use openauth_plugins::open_api::{open_api, open_api_with, OpenApiOptions};
use openauth_plugins::organization::{
    organization_with, DynamicAccessControlOptions, OrganizationOptions, TeamOptions,
};
use openauth_plugins::phone_number::{phone_number_with, PhoneNumberOptions};
use openauth_plugins::siwe::{siwe_with, SiweOptions};
use openauth_plugins::two_factor::two_factor;
use openauth_plugins::username::username;
use serde_json::Value;

#[test]
fn exposes_open_api_plugin_builder() {
    let plugin = open_api();

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
    let router = router(vec![open_api(), api_key(), anonymous()])?;

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
    assert_eq!(
        body["paths"]["/api-key/create"]["post"]["operationId"],
        "createApiKey"
    );
    assert!(body["paths"]["/reference"].is_null());
    Ok(())
}

#[tokio::test]
async fn generated_schema_includes_detailed_plugin_metadata(
) -> Result<(), Box<dyn std::error::Error>> {
    let router = router(vec![open_api(), anonymous()])?;

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
async fn generated_schema_declares_user_id_as_string_type() -> Result<(), Box<dyn std::error::Error>>
{
    let router = router(vec![open_api()])?;
    let response = router
        .handle_async(request(Method::GET, "/api/auth/open-api/generate-schema")?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        body["components"]["schemas"]["User"]["properties"]["id"]["type"],
        "string"
    );
    Ok(())
}

#[tokio::test]
async fn generated_schema_uses_runtime_database_schema_components(
) -> Result<(), Box<dyn std::error::Error>> {
    let router = router_with_options(OpenAuthOptions {
        base_url: Some("http://localhost:3000".to_owned()),
        secret: Some("test-secret-123456789012345678901234".to_owned()),
        advanced: AdvancedOptions {
            disable_csrf_check: true,
            disable_origin_check: true,
            ..AdvancedOptions::default()
        },
        user: UserOptions::new().additional_field(
            "role",
            UserAdditionalField::new(DbFieldType::String)
                .default_value(DbValue::String("user".to_owned())),
        ),
        plugins: vec![
            open_api(),
            organization_with(OrganizationOptions::default()),
            phone_number_with(PhoneNumberOptions::default()),
        ],
        ..OpenAuthOptions::default()
    })?;

    let response = router
        .handle_async(request(Method::GET, "/api/auth/open-api/generate-schema")?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;
    let schemas = &body["components"]["schemas"];

    assert_eq!(schemas["User"]["properties"]["role"]["type"], "string");
    assert_eq!(schemas["User"]["properties"]["role"]["default"], "user");
    assert!(schemas["User"]["required"]
        .as_array()
        .is_some_and(|required| required.iter().any(|field| field == "role")));
    assert_eq!(
        schemas["User"]["properties"]["phoneNumber"]["type"],
        serde_json::json!(["string", "null"])
    );
    assert_eq!(
        schemas["Session"]["properties"]["activeOrganizationId"]["type"],
        serde_json::json!(["string", "null"])
    );
    assert_eq!(
        schemas["Organization"]["properties"]["slug"]["type"],
        "string"
    );
    Ok(())
}

#[tokio::test]
async fn generated_schema_audits_all_server_plugin_endpoints(
) -> Result<(), Box<dyn std::error::Error>> {
    let _adapter = Arc::new(MemoryAdapter::new());
    let router = router(vec![
        open_api(),
        api_key(),
        anonymous(),
        username(),
        multi_session(),
        one_time_token(),
        organization_with(
            OrganizationOptions::builder()
                .teams(TeamOptions {
                    enabled: true,
                    create_default_team: true,
                    maximum_teams: None,
                    maximum_members_per_team: None,
                    allow_removing_all_teams: false,
                    ..Default::default()
                })
                .dynamic_access_control(DynamicAccessControlOptions {
                    enabled: true,
                    maximum_roles_per_organization: None,
                })
                .build(),
        ),
        jwt()?,
        phone_number_with(PhoneNumberOptions::default()),
        email_otp_with(EmailOtpOptions::default()),
        two_factor(),
        oauth_proxy(),
        one_tap(),
        magic_link_with(MagicLinkOptions::new(|_email: MagicLinkEmail| {
            Box::pin(async { Ok(()) })
        })),
        siwe_with(SiweOptions::new(
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

    let generic_schema = plugin_only_openapi(generic_oauth_with(GenericOAuthOptions {
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
    let callback = &generic_paths["/oauth2/callback/{providerId}"]["get"];
    assert_eq!(callback["operationId"], "oAuth2Callback");
    assert_eq!(
        callback["responses"]["302"]["description"],
        "OAuth callback redirect"
    );
    assert!(
        callback["parameters"]
            .as_array()
            .is_some_and(|parameters| parameters.iter().any(|parameter| {
                parameter["name"] == "providerId" && parameter["in"] == "path"
            })),
        "generic OAuth callback should document providerId path parameter"
    );

    Ok(())
}

#[tokio::test]
async fn reference_endpoint_serves_scalar_html() -> Result<(), Box<dyn std::error::Error>> {
    let router = router(vec![open_api_with(
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
async fn reference_endpoint_escapes_schema_json_for_script_context(
) -> Result<(), Box<dyn std::error::Error>> {
    let router = router(vec![open_api(), dangerous_doc_plugin()])?;

    let response = router
        .handle_async(request(Method::GET, "/api/auth/reference")?)
        .await?;
    let body = String::from_utf8(response.body().clone())?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(!body.contains("</script><script>alert(1)</script>"));
    assert!(body.contains("\\u003c/script\\u003e\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"));
    Ok(())
}

#[tokio::test]
async fn reference_endpoint_escapes_theme_for_javascript_context(
) -> Result<(), Box<dyn std::error::Error>> {
    let router = router(vec![open_api_with(
        OpenApiOptions::default().theme(r#"</script><script>alert("theme")</script>"#),
    )])?;

    let response = router
        .handle_async(request(Method::GET, "/api/auth/reference")?)
        .await?;
    let body = String::from_utf8(response.body().clone())?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(!body.contains(r#"</script><script>alert("theme")</script>"#));
    assert!(body.contains(
        "\\u003c/script\\u003e\\u003cscript\\u003ealert(\\\"theme\\\")\\u003c/script\\u003e"
    ));
    Ok(())
}

#[tokio::test]
async fn reference_endpoint_can_be_disabled() -> Result<(), Box<dyn std::error::Error>> {
    let router = router(vec![open_api_with(
        OpenApiOptions::default().disable_default_reference(true),
    )])?;

    let response = router
        .handle_async(request(Method::GET, "/api/auth/reference")?)
        .await?;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    Ok(())
}

fn dangerous_doc_plugin() -> AuthPlugin {
    AuthPlugin::new("dangerous-doc").with_endpoint(create_auth_endpoint(
        "/dangerous-doc",
        Method::GET,
        AuthEndpointOptions::new()
            .operation_id("dangerousDoc")
            .openapi(
                OpenApiOperation::new("dangerousDoc")
                    .summary("Dangerous doc")
                    .description("</script><script>alert(1)</script>")
                    .response(
                        "200",
                        serde_json::json!({
                            "description": "Dangerous doc response",
                        }),
                    ),
            ),
        |_context, _request| {
            Box::pin(async move {
                http::Response::builder()
                    .status(StatusCode::OK)
                    .body(Vec::new())
                    .map_err(|error| OpenAuthError::Api(error.to_string()))
            })
        },
    ))
}

fn router(plugins: Vec<openauth_core::plugin::AuthPlugin>) -> Result<AuthRouter, OpenAuthError> {
    router_with_options(OpenAuthOptions {
        base_url: Some("http://localhost:3000".to_owned()),
        secret: Some("test-secret-123456789012345678901234".to_owned()),
        advanced: AdvancedOptions {
            disable_csrf_check: true,
            disable_origin_check: true,
            ..AdvancedOptions::default()
        },
        plugins,
        ..OpenAuthOptions::default()
    })
}

fn router_with_options(options: OpenAuthOptions) -> Result<AuthRouter, OpenAuthError> {
    let adapter = Arc::new(MemoryAdapter::default());
    let context = create_auth_context_with_adapter(options, adapter.clone())?;
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
