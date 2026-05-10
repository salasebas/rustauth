use http::{Method, Request, StatusCode};
use openauth_core::api::{response, ApiRequest, ApiResponse, AuthEndpoint, AuthRouter};
use openauth_core::context::{create_auth_context, AuthContext};
use openauth_core::error::OpenAuthError;
use openauth_core::options::OpenAuthOptions;
use openauth_core::plugin::{AuthPlugin, PluginRequestAction};

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

#[test]
fn on_response_plugin_can_replace_response() -> Result<(), Box<dyn std::error::Error>> {
    let plugin = AuthPlugin::new("response-mutator").with_on_response(|_context, mut response| {
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
