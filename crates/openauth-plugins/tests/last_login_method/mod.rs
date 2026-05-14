use http::{header, HeaderValue, Method, Request, Response, StatusCode};
use openauth_core::context::create_auth_context;
use openauth_core::options::OpenAuthOptions;
use openauth_plugins::last_login_method::{
    last_login_method, LastLoginMethodOptions, LoginMethodContext, DEFAULT_COOKIE_MAX_AGE,
    DEFAULT_COOKIE_NAME, UPSTREAM_PLUGIN_ID,
};

#[test]
fn exposes_last_login_method_plugin_metadata() {
    let plugin = last_login_method(LastLoginMethodOptions::default());

    assert_eq!(plugin.id, UPSTREAM_PLUGIN_ID);
    assert_eq!(plugin.version.as_deref(), Some(openauth_plugins::VERSION));
    assert!(plugin.on_response.is_some());
}

#[test]
fn default_resolver_matches_upstream_login_routes() {
    let cases = [
        ("/callback/google", Some("google")),
        ("/oauth2/callback/my-provider-id", Some("my-provider-id")),
        ("/sign-in/email", Some("email")),
        ("/sign-up/email", Some("email")),
        ("/siwe/verify", Some("siwe")),
        ("/passkey/verify-authentication", Some("passkey")),
        ("/magic-link/verify", Some("magic-link")),
        ("/unknown", None),
    ];

    for (path, expected) in cases {
        let context = LoginMethodContext::new(path);
        assert_eq!(
            openauth_plugins::last_login_method::default_login_method(&context).as_deref(),
            expected
        );
    }
}

#[test]
fn custom_resolver_takes_precedence_over_default_resolver() {
    let options = LastLoginMethodOptions::default().with_resolver(|context| {
        (context.path() == "/sign-in/email").then(|| "custom-email".to_owned())
    });

    assert_eq!(
        options.resolve_login_method(&LoginMethodContext::new("/sign-in/email")),
        Some("custom-email".to_owned())
    );
}

#[test]
fn response_hook_sets_last_method_cookie_when_session_cookie_is_created(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin = last_login_method(LastLoginMethodOptions::default());
    let hook = plugin.on_response.as_ref().ok_or("missing response hook")?;
    let context = create_auth_context(OpenAuthOptions {
        secret: Some(secret().to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let request = request("/api/auth/sign-in/email")?;
    let response = response_with_set_cookie(&format!(
        "{}=signed; Path=/; HttpOnly",
        context.auth_cookies.session_token.name
    ))?;

    let response = hook(&context, &request, response)?;
    let cookies = set_cookie_values(&response);
    let last_method = cookies
        .iter()
        .find(|cookie| cookie.starts_with(DEFAULT_COOKIE_NAME))
        .ok_or("missing last login method cookie")?;

    assert!(last_method.starts_with("better-auth.last_used_login_method=email"));
    assert!(last_method.contains(&format!("Max-Age={DEFAULT_COOKIE_MAX_AGE}")));
    assert!(last_method.contains("Path=/"));
    assert!(!last_method.contains("HttpOnly"));
    Ok(())
}

#[test]
fn response_hook_does_not_set_cookie_without_session_cookie(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin = last_login_method(LastLoginMethodOptions::default());
    let hook = plugin.on_response.as_ref().ok_or("missing response hook")?;
    let context = create_auth_context(OpenAuthOptions {
        secret: Some(secret().to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let request = request("/api/auth/sign-in/email")?;
    let response = Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .body(Vec::new())?;

    let response = hook(&context, &request, response)?;

    assert!(set_cookie_values(&response)
        .iter()
        .all(|cookie| !cookie.starts_with(DEFAULT_COOKIE_NAME)));
    Ok(())
}

#[test]
fn store_in_database_contributes_optional_generated_user_field(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin = last_login_method(LastLoginMethodOptions::default().store_in_database(true));
    let context = create_auth_context(OpenAuthOptions {
        plugins: vec![plugin],
        secret: Some(secret().to_owned()),
        ..OpenAuthOptions::default()
    })?;

    let field = context.db_schema.field("user", "last_login_method")?;

    assert_eq!(field.name, "last_login_method");
    assert!(!field.required);
    assert!(!field.input);
    assert!(field.returned);
    Ok(())
}

#[test]
fn store_in_database_uses_custom_database_field_name() -> Result<(), Box<dyn std::error::Error>> {
    let plugin = last_login_method(
        LastLoginMethodOptions::default()
            .store_in_database(true)
            .database_field_name("last_auth_method"),
    );
    let context = create_auth_context(OpenAuthOptions {
        plugins: vec![plugin],
        secret: Some(secret().to_owned()),
        ..OpenAuthOptions::default()
    })?;

    assert_eq!(
        context.db_schema.field_name("user", "last_login_method")?,
        "last_auth_method"
    );
    Ok(())
}

fn request(path: &str) -> Result<Request<Vec<u8>>, http::Error> {
    Request::builder()
        .method(Method::POST)
        .uri(format!("http://localhost:3000{path}"))
        .body(Vec::new())
}

fn response_with_set_cookie(cookie: &str) -> Result<Response<Vec<u8>>, Box<dyn std::error::Error>> {
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .body(Vec::new())?;
    response
        .headers_mut()
        .append(header::SET_COOKIE, HeaderValue::from_str(cookie)?);
    Ok(response)
}

fn set_cookie_values(response: &Response<Vec<u8>>) -> Vec<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok().map(str::to_owned))
        .collect()
}

fn secret() -> &'static str {
    "test-secret-123456789012345678901234"
}
