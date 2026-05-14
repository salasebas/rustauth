use http::{header, Method, Request, StatusCode};
use openauth::{
    core_auth_async_endpoints, create_auth_endpoint, open_auth, open_auth_with_adapter,
    open_auth_with_endpoints, AdvancedOptions, ApiErrorResponse, ApiRequest, ApiResponse,
    AsyncAuthEndpoint, AuthEndpoint, AuthEndpointOptions, AuthPlugin, BodyField, BodySchema,
    ChangeEmailOptions, CookieCacheStrategy, DeleteUserOptions, EmailVerificationOptions,
    EndpointKind, JsonSchemaType, MemoryAdapter, OpenApiOperation, OpenAuthError, OpenAuthOptions,
    PathParams, PluginRequestAction, ProviderOptions, RateLimitOptions, SessionAdditionalField,
    SessionAuth, SessionOptions, SignOutResult, SocialOAuthProvider, TrustedOriginOptions,
    UpdateUserInput, UserOptions, VerificationEmail,
};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;

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
fn openauth_crate_reexports_adapter_schema_contracts() -> Result<(), Box<dyn std::error::Error>> {
    let schema = openauth::db::auth_schema(openauth::db::AuthSchemaOptions::default());
    let user_table = schema.table("user").ok_or("user table should exist")?;

    assert_eq!(user_table.name, "users");
    assert!(user_table.field("email").is_some());
    Ok(())
}

#[test]
fn openauth_crate_reexports_core_primitives() {
    let token = openauth::crypto::random::generate_random_string(16);

    assert_eq!(token.len(), 16);
}

#[test]
fn openauth_crate_reexports_oauth_and_social_provider_packages() {
    let provider = openauth::oauth::oauth2::OAuthProviderMetadata::new("example", "Example");

    assert_eq!(provider.id(), "example");
    assert!(openauth::social_providers::PROVIDER_IDS.contains(&"github"));
}

#[test]
fn openauth_crate_accepts_social_oauth_runtime_providers() {
    let provider: Arc<dyn SocialOAuthProvider> = Arc::new(
        openauth::social_providers::github::github(ProviderOptions::default()),
    );
    let options = OpenAuthOptions {
        social_providers: vec![provider],
        ..OpenAuthOptions::default()
    };

    assert_eq!(options.social_providers[0].id(), "github");
}

#[test]
fn oauth_public_reexports_include_core_and_oauth_helpers() {
    let _authentication = openauth::oauth::oauth2::ClientAuthentication::Basic;
    let _path_params = PathParams::new(BTreeMap::new());
    let user_info = openauth::auth::oauth::OAuthUserInfo {
        id: "id".to_owned(),
        name: "name".to_owned(),
        email: "user@example.com".to_owned(),
        image: None,
        email_verified: true,
    };

    assert_eq!(user_info.email, "user@example.com");
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
        original_message: None,
    };
    let _plugin = AuthPlugin::new("test-plugin");
    let _action_type: Option<PluginRequestAction> = None;
    let _trusted_origins = TrustedOriginOptions::default();
    let _rate_limit = RateLimitOptions::default();
    let _user_options = UserOptions {
        change_email: ChangeEmailOptions {
            enabled: true,
            update_email_without_verification: true,
        },
        delete_user: DeleteUserOptions { enabled: true },
    };
    let _email_verification = EmailVerificationOptions::default();
    let _verification_email_type: Option<VerificationEmail> = None;
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

#[tokio::test]
async fn openauth_with_adapter_supports_email_password_session_flow(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = open_auth_with_adapter(test_options(), Arc::new(MemoryAdapter::new()))?;

    let sign_up = auth
        .handler_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    assert_eq!(sign_up.status(), StatusCode::OK);
    let cookie = cookie_header(&sign_up);
    assert!(cookie.contains("better-auth.session_token="));

    let session = auth
        .handler_async(json_request(
            Method::GET,
            "/api/auth/get-session",
            "",
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(session.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(session.body())?;
    assert_eq!(body["user"]["email"], "ada@example.com");

    let sign_out = auth
        .handler_async(json_request(
            Method::POST,
            "/api/auth/sign-out",
            "",
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(sign_out.status(), StatusCode::OK);
    assert!(set_cookie_values(&sign_out)
        .iter()
        .any(|value| value.starts_with("better-auth.session_token=;")));

    let after = auth
        .handler_async(json_request(
            Method::GET,
            "/api/auth/get-session",
            "",
            Some(&cookie),
        )?)
        .await?;
    let body: Value = serde_json::from_slice(after.body())?;
    assert!(body.is_null());
    Ok(())
}

#[tokio::test]
async fn openauth_with_adapter_supports_sign_in_and_session_revocation(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = open_auth_with_adapter(test_options(), Arc::new(MemoryAdapter::new()))?;
    let _ = auth
        .handler_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;

    let sign_in = auth
        .handler_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    assert_eq!(sign_in.status(), StatusCode::OK);
    let cookie = cookie_header(&sign_in);

    let sessions = auth
        .handler_async(json_request(
            Method::GET,
            "/api/auth/list-sessions",
            "",
            Some(&cookie),
        )?)
        .await?;
    let body: Value = serde_json::from_slice(sessions.body())?;
    let token = body
        .as_array()
        .and_then(|items| items.first())
        .and_then(|item| item.get("token"))
        .and_then(Value::as_str)
        .ok_or("missing listed session token")?;

    let revoke = auth
        .handler_async(json_request(
            Method::POST,
            "/api/auth/revoke-session",
            &format!(r#"{{"token":"{token}"}}"#),
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(revoke.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(revoke.body())?;
    assert_eq!(body["status"], true);
    Ok(())
}

#[tokio::test]
async fn openauth_with_adapter_supports_update_session_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = open_auth_with_adapter(
        OpenAuthOptions {
            session: SessionOptions {
                additional_fields: BTreeMap::from([(
                    "theme".to_owned(),
                    SessionAdditionalField::new(openauth::db::DbFieldType::String),
                )]),
                ..SessionOptions::default()
            },
            ..test_options()
        },
        Arc::new(MemoryAdapter::new()),
    )?;
    let sign_up = auth
        .handler_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    assert_eq!(sign_up.status(), StatusCode::OK);
    let cookie = cookie_header(&sign_up);

    let updated = auth
        .handler_async(json_request(
            Method::POST,
            "/api/auth/update-session",
            r#"{"theme":"dark"}"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(updated.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(updated.body())?;
    assert_eq!(body["session"]["theme"], "dark");

    let session = auth
        .handler_async(json_request(
            Method::GET,
            "/api/auth/get-session",
            "",
            Some(&cookie),
        )?)
        .await?;
    let body: Value = serde_json::from_slice(session.body())?;
    assert_eq!(body["session"]["theme"], "dark");
    Ok(())
}

#[tokio::test]
async fn openauth_with_adapter_supports_bulk_and_other_session_revocation(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = open_auth_with_adapter(test_options(), Arc::new(MemoryAdapter::new()))?;
    let first = auth
        .handler_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    let first_cookie = cookie_header(&first);
    let second = auth
        .handler_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    let second_cookie = cookie_header(&second);

    let revoke_other = auth
        .handler_async(json_request(
            Method::POST,
            "/api/auth/revoke-other-sessions",
            "",
            Some(&second_cookie),
        )?)
        .await?;
    assert_eq!(revoke_other.status(), StatusCode::OK);
    let first_after: Value = serde_json::from_slice(
        auth.handler_async(json_request(
            Method::GET,
            "/api/auth/get-session",
            "",
            Some(&first_cookie),
        )?)
        .await?
        .body(),
    )?;
    assert!(first_after.is_null());

    let revoke_all = auth
        .handler_async(json_request(
            Method::POST,
            "/api/auth/revoke-sessions",
            "",
            Some(&second_cookie),
        )?)
        .await?;
    assert_eq!(revoke_all.status(), StatusCode::OK);
    let second_after: Value = serde_json::from_slice(
        auth.handler_async(json_request(
            Method::GET,
            "/api/auth/get-session",
            "",
            Some(&second_cookie),
        )?)
        .await?
        .body(),
    )?;
    assert!(second_after.is_null());
    Ok(())
}

#[test]
fn openauth_with_adapter_rejects_core_endpoint_conflicts() -> Result<(), Box<dyn std::error::Error>>
{
    let conflicting = AuthEndpoint {
        path: "/ok".to_owned(),
        method: Method::GET,
        handler: |_context, _request| openauth::api::response(StatusCode::OK, Vec::new()),
    };

    let result = openauth::auth::open_auth_with_adapter_and_endpoints(
        test_options(),
        Arc::new(MemoryAdapter::new()),
        vec![conflicting],
        Vec::new(),
    );

    assert!(
        matches!(result, Err(OpenAuthError::Api(message)) if message.contains("endpoint conflict"))
    );
    Ok(())
}

fn test_options() -> OpenAuthOptions {
    OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        advanced: AdvancedOptions {
            disable_csrf_check: true,
            disable_origin_check: true,
            ..AdvancedOptions::default()
        },
        ..OpenAuthOptions::default()
    }
}

fn json_request(
    method: Method,
    path: &str,
    body: &str,
    cookie: Option<&str>,
) -> Result<Request<Vec<u8>>, http::Error> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://localhost:3000{path}"));
    if !body.is_empty() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(body.as_bytes().to_vec())
}

fn cookie_header(response: &http::Response<Vec<u8>>) -> String {
    set_cookie_values(response)
        .into_iter()
        .filter_map(|value| value.split_once(';').map(|(cookie, _)| cookie.to_owned()))
        .collect::<Vec<_>>()
        .join("; ")
}

fn set_cookie_values(response: &http::Response<Vec<u8>>) -> Vec<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok().map(str::to_owned))
        .collect()
}
