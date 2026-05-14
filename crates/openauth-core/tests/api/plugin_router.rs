use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use http::{Method, Request, StatusCode};
use openauth_core::api::{
    create_auth_endpoint, response, ApiRequest, ApiResponse, AuthEndpoint, AuthEndpointOptions,
    AuthRouter, EndpointMiddleware,
};
use openauth_core::context::{create_auth_context, AuthContext};
use openauth_core::db::{DbField, DbFieldType};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{OpenAuthOptions, RateLimitOptions, RateLimitPathRule, RateLimitRule};
use openauth_core::plugin::{
    AuthPlugin, PluginAfterHookAction, PluginBeforeHookAction, PluginErrorCode, PluginInitOutput,
    PluginRateLimitRule, PluginRequestAction, PluginSchemaContribution,
};

fn endpoint(
    path: &str,
    handler: fn(&AuthContext, ApiRequest) -> Result<ApiResponse, OpenAuthError>,
) -> AuthEndpoint {
    AuthEndpoint {
        path: path.to_owned(),
        method: Method::GET,
        handler,
    }
}

fn ok_handler(_context: &AuthContext, _request: ApiRequest) -> Result<ApiResponse, OpenAuthError> {
    response(StatusCode::OK, b"OK".to_vec())
}

fn header_handler(
    _context: &AuthContext,
    request: ApiRequest,
) -> Result<ApiResponse, OpenAuthError> {
    if request.headers().get("x-plugin").is_some() {
        response(StatusCode::OK, b"PLUGIN".to_vec())
    } else {
        response(StatusCode::BAD_REQUEST, b"MISSING".to_vec())
    }
}

#[test]
fn on_request_plugin_can_replace_request() -> Result<(), Box<dyn std::error::Error>> {
    let plugin = AuthPlugin::new("request-mutator").with_on_request(|_context, mut request| {
        request
            .headers_mut()
            .insert("x-plugin", http::HeaderValue::from_static("1"));
        Ok(PluginRequestAction::Continue(request))
    });
    let context = create_auth_context(OpenAuthOptions {
        plugins: vec![plugin],
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::new(context, vec![endpoint("/ok", header_handler)]);

    let response = router.handle(
        Request::builder()
            .method(Method::GET)
            .uri("http://localhost:3000/api/auth/ok")
            .body(Vec::new())?,
    )?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.body(), b"PLUGIN");
    Ok(())
}

#[test]
fn on_request_plugin_can_short_circuit_response() -> Result<(), Box<dyn std::error::Error>> {
    let plugin = AuthPlugin::new("request-guard").with_on_request(|_context, _request| {
        let response = response(StatusCode::ACCEPTED, b"PLUGIN RESPONSE".to_vec())?;
        Ok(PluginRequestAction::Respond(response))
    });
    let context = create_auth_context(OpenAuthOptions {
        plugins: vec![plugin],
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::new(context, vec![endpoint("/ok", ok_handler)]);

    let response = router.handle(
        Request::builder()
            .method(Method::GET)
            .uri("http://localhost:3000/api/auth/ok")
            .body(Vec::new())?,
    )?;

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(response.body(), b"PLUGIN RESPONSE");
    Ok(())
}

#[test]
fn middleware_matches_path_and_can_block_endpoint() -> Result<(), Box<dyn std::error::Error>> {
    let plugin = AuthPlugin::new("middleware").with_middleware("/admin/*", |_context, _request| {
        response(StatusCode::FORBIDDEN, b"BLOCKED".to_vec()).map(Some)
    });
    let context = create_auth_context(OpenAuthOptions {
        plugins: vec![plugin],
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::new(context, vec![endpoint("/admin/list", ok_handler)]);

    let response = router.handle(
        Request::builder()
            .method(Method::GET)
            .uri("http://localhost:3000/api/auth/admin/list")
            .body(Vec::new())?,
    )?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response.body(), b"BLOCKED");
    Ok(())
}

#[tokio::test]
async fn async_middleware_matches_path_and_can_block_async_endpoint(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin = AuthPlugin::new("async-middleware").with_async_middleware(
        "/admin/*",
        |_context, _request| {
            Box::pin(async { response(StatusCode::FORBIDDEN, b"BLOCKED".to_vec()).map(Some) })
        },
    );
    let context = create_auth_context(OpenAuthOptions {
        plugins: vec![plugin],
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let async_endpoint = create_auth_endpoint(
        "/admin/list",
        Method::GET,
        AuthEndpointOptions::new(),
        |_context, _request| Box::pin(async { response(StatusCode::OK, b"OK".to_vec()) }),
    );
    let router = AuthRouter::with_async_endpoints(context, Vec::new(), vec![async_endpoint])?;

    let response = router
        .handle_async(
            Request::builder()
                .method(Method::GET)
                .uri("http://localhost:3000/api/auth/admin/list")
                .body(Vec::new())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response.body(), b"BLOCKED");
    Ok(())
}

#[tokio::test]
async fn async_middleware_ignores_non_matching_paths() -> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_for_middleware = Arc::clone(&calls);
    let plugin = AuthPlugin::new("async-middleware").with_async_middleware(
        "/admin/*",
        move |_context, _request| {
            let calls = Arc::clone(&calls_for_middleware);
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                response(StatusCode::FORBIDDEN, b"BLOCKED".to_vec()).map(Some)
            })
        },
    );
    let context = create_auth_context(OpenAuthOptions {
        plugins: vec![plugin],
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let async_endpoint = create_auth_endpoint(
        "/account/list",
        Method::GET,
        AuthEndpointOptions::new(),
        |_context, _request| Box::pin(async { response(StatusCode::OK, b"OK".to_vec()) }),
    );
    let router = AuthRouter::with_async_endpoints(context, Vec::new(), vec![async_endpoint])?;

    let response = router
        .handle_async(
            Request::builder()
                .method(Method::GET)
                .uri("http://localhost:3000/api/auth/account/list")
                .body(Vec::new())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn async_middleware_runs_before_endpoint_middleware() -> Result<(), Box<dyn std::error::Error>>
{
    let order = Arc::new(AtomicUsize::new(0));
    let plugin_order = Arc::clone(&order);
    let endpoint_order = Arc::clone(&order);
    let plugin = AuthPlugin::new("async-middleware").with_async_middleware(
        "/protected",
        move |_context, _request| {
            let plugin_order = Arc::clone(&plugin_order);
            Box::pin(async move {
                assert_eq!(plugin_order.fetch_add(1, Ordering::SeqCst), 0);
                Ok(None)
            })
        },
    );
    let context = create_auth_context(OpenAuthOptions {
        plugins: vec![plugin],
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let async_endpoint = create_auth_endpoint(
        "/protected",
        Method::GET,
        AuthEndpointOptions::new().middleware(EndpointMiddleware::new(
            move |_context, _request| {
                let endpoint_order = Arc::clone(&endpoint_order);
                Box::pin(async move {
                    assert_eq!(endpoint_order.fetch_add(1, Ordering::SeqCst), 1);
                    Ok(None)
                })
            },
        )),
        |_context, _request| Box::pin(async { response(StatusCode::OK, b"OK".to_vec()) }),
    );
    let router = AuthRouter::with_async_endpoints(context, Vec::new(), vec![async_endpoint])?;

    let response = router
        .handle_async(
            Request::builder()
                .method(Method::GET)
                .uri("http://localhost:3000/api/auth/protected")
                .body(Vec::new())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(order.load(Ordering::SeqCst), 2);
    Ok(())
}

#[test]
fn on_response_plugin_can_replace_response() -> Result<(), Box<dyn std::error::Error>> {
    let plugin =
        AuthPlugin::new("response-mutator").with_on_response(|_context, _request, mut response| {
            response
                .headers_mut()
                .insert("x-plugin-response", http::HeaderValue::from_static("1"));
            Ok(response)
        });
    let context = create_auth_context(OpenAuthOptions {
        plugins: vec![plugin],
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::new(context, vec![endpoint("/ok", ok_handler)]);

    let response = router.handle(
        Request::builder()
            .method(Method::GET)
            .uri("http://localhost:3000/api/auth/ok")
            .body(Vec::new())?,
    )?;

    assert_eq!(
        response
            .headers()
            .get("x-plugin-response")
            .ok_or("missing plugin response header")?,
        "1"
    );
    Ok(())
}

#[test]
fn try_new_rejects_conflicting_endpoint_method_and_path() -> Result<(), Box<dyn std::error::Error>>
{
    let context = create_auth_context(OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let result = AuthRouter::try_new(
        context,
        vec![endpoint("/ok", ok_handler), endpoint("/ok", ok_handler)],
    );

    assert!(result.is_err());
    Ok(())
}

#[tokio::test]
async fn plugin_endpoint_is_registered_and_handled() -> Result<(), Box<dyn std::error::Error>> {
    let plugin_endpoint = create_auth_endpoint(
        "/plugin/hello",
        Method::GET,
        Default::default(),
        |_context, _request| Box::pin(async { response(StatusCode::OK, b"HELLO".to_vec()) }),
    );
    let plugin = AuthPlugin::new("endpoint-plugin").with_endpoint(plugin_endpoint);
    let context = create_auth_context(OpenAuthOptions {
        plugins: vec![plugin],
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::with_async_endpoints(context, Vec::new(), Vec::new())?;

    let registry = router.endpoint_registry();
    assert!(registry
        .iter()
        .any(|endpoint| endpoint.path == "/plugin/hello" && endpoint.method == Method::GET));

    let response = router
        .handle_async(
            Request::builder()
                .method(Method::GET)
                .uri("http://localhost:3000/api/auth/plugin/hello")
                .body(Vec::new())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.body(), b"HELLO");
    Ok(())
}

#[test]
fn plugin_endpoint_conflicts_with_core_endpoint() -> Result<(), Box<dyn std::error::Error>> {
    let plugin_endpoint = create_auth_endpoint(
        "/ok",
        Method::GET,
        Default::default(),
        |_context, _request| Box::pin(async { response(StatusCode::OK, b"PLUGIN".to_vec()) }),
    );
    let plugin = AuthPlugin::new("endpoint-plugin").with_endpoint(plugin_endpoint);
    let context = create_auth_context(OpenAuthOptions {
        plugins: vec![plugin],
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;

    let result = AuthRouter::try_new(context, vec![endpoint("/ok", ok_handler)]);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn plugin_init_contributions_are_applied_in_order() -> Result<(), Box<dyn std::error::Error>> {
    let first = AuthPlugin::new("first").with_init(|_context| {
        Ok(PluginInitOutput::new()
            .trusted_origin("https://first.example")
            .disabled_path("/disabled-by-first"))
    });
    let second = AuthPlugin::new("second").with_init(|context| {
        assert!(context.is_trusted_origin("https://first.example", None));
        assert!(context
            .disabled_paths
            .iter()
            .any(|path| path == "/disabled-by-first"));
        Ok(PluginInitOutput::new().trusted_origin("https://second.example"))
    });

    let context = create_auth_context(OpenAuthOptions {
        plugins: vec![first, second],
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;

    assert!(context.is_trusted_origin("https://second.example", None));
    Ok(())
}

#[test]
fn plugin_schema_contribution_adds_core_table_field() -> Result<(), Box<dyn std::error::Error>> {
    let plugin = AuthPlugin::new("schema-plugin").with_schema(PluginSchemaContribution::field(
        "user",
        "tenant_id",
        DbField::new("tenant_id", DbFieldType::String).optional(),
    ));

    let context = create_auth_context(OpenAuthOptions {
        plugins: vec![plugin],
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;

    let field = context.db_schema.field("user", "tenant_id")?;
    assert_eq!(field.name, "tenant_id");
    Ok(())
}

#[test]
fn plugin_schema_rejects_conflicting_field() -> Result<(), Box<dyn std::error::Error>> {
    let plugin = AuthPlugin::new("schema-plugin").with_schema(PluginSchemaContribution::field(
        "user",
        "email",
        DbField::new("email", DbFieldType::Number),
    ));

    let result = create_auth_context(OpenAuthOptions {
        plugins: vec![plugin],
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    });

    assert!(matches!(result, Err(OpenAuthError::InvalidConfig(_))));
    Ok(())
}

#[tokio::test]
async fn before_and_after_hooks_wrap_plugin_endpoint() -> Result<(), Box<dyn std::error::Error>> {
    let plugin_endpoint = create_auth_endpoint(
        "/hooked",
        Method::GET,
        Default::default(),
        |_context, request| {
            Box::pin(async move {
                if request.headers().get("x-before").is_some() {
                    response(StatusCode::OK, b"before".to_vec())
                } else {
                    response(StatusCode::BAD_REQUEST, b"missing".to_vec())
                }
            })
        },
    );
    let plugin = AuthPlugin::new("hook-plugin")
        .with_endpoint(plugin_endpoint)
        .with_before_hook("/hooked", |_context, mut request| {
            request
                .headers_mut()
                .insert("x-before", http::HeaderValue::from_static("1"));
            Ok(PluginBeforeHookAction::Continue(request))
        })
        .with_after_hook("/hooked", |_context, _request, mut response| {
            response
                .headers_mut()
                .insert("x-after", http::HeaderValue::from_static("1"));
            Ok(PluginAfterHookAction::Continue(response))
        });
    let context = create_auth_context(OpenAuthOptions {
        plugins: vec![plugin],
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::with_async_endpoints(context, Vec::new(), Vec::new())?;

    let response = router
        .handle_async(
            Request::builder()
                .method(Method::GET)
                .uri("http://localhost:3000/api/auth/hooked")
                .body(Vec::new())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.body(), b"before");
    assert_eq!(
        response
            .headers()
            .get("x-after")
            .ok_or("missing after hook header")?,
        "1"
    );
    Ok(())
}

#[test]
fn plugin_error_codes_are_registered_and_validated() -> Result<(), Box<dyn std::error::Error>> {
    let plugin = AuthPlugin::new("errors")
        .with_error_code(PluginErrorCode::new("PLUGIN_FAILURE", "Plugin failure"));
    let context = create_auth_context(OpenAuthOptions {
        plugins: vec![plugin],
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;

    assert_eq!(
        context
            .plugin_error_codes
            .get("PLUGIN_FAILURE")
            .map(|code| code.message.as_str()),
        Some("Plugin failure")
    );

    let invalid = AuthPlugin::new("bad-errors")
        .with_error_code(PluginErrorCode::new("plugin_failure", "Invalid"));
    let result = create_auth_context(OpenAuthOptions {
        plugins: vec![invalid],
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    });

    assert!(matches!(result, Err(OpenAuthError::InvalidConfig(_))));
    Ok(())
}

#[test]
fn plugin_rate_limit_rules_apply_before_user_custom_overrides(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin = AuthPlugin::new("rate-limit").with_rate_limit(PluginRateLimitRule::new(
        "/plugin/limited",
        RateLimitRule { window: 30, max: 1 },
    ));
    let context = create_auth_context(OpenAuthOptions {
        plugins: vec![plugin],
        rate_limit: RateLimitOptions {
            enabled: Some(true),
            custom_rules: vec![RateLimitPathRule {
                path: "/plugin/limited".to_owned(),
                rule: Some(RateLimitRule { window: 30, max: 3 }),
            }],
            ..RateLimitOptions::default()
        },
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::new(context, vec![endpoint("/plugin/limited", ok_handler)]);

    for attempt in 0..4 {
        let response = router.handle(
            Request::builder()
                .method(Method::GET)
                .uri("http://localhost:3000/api/auth/plugin/limited")
                .body(Vec::new())?,
        )?;
        if attempt < 3 {
            assert_eq!(response.status(), StatusCode::OK);
        } else {
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        }
    }
    Ok(())
}
