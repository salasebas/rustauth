use super::*;

fn test_openauth_options(plugins: Vec<openauth_core::plugin::AuthPlugin>) -> OpenAuthOptions {
    OpenAuthOptions {
        base_url: Some("https://app.example.com".to_owned()),
        secret: Some(SECRET.to_owned()),
        plugins,
        advanced: AdvancedOptions {
            disable_csrf_check: true,
            disable_origin_check: true,
            ..AdvancedOptions::default()
        },
        rate_limit: RateLimitOptions {
            enabled: Some(false),
            ..RateLimitOptions::default()
        },
        ..OpenAuthOptions::default()
    }
}

pub(super) fn router() -> Result<AuthRouter, openauth_core::error::OpenAuthError> {
    router_with_adapter().map(|(_adapter, router)| router)
}

pub(super) fn router_with_adapter(
) -> Result<(Arc<MemoryAdapter>, AuthRouter), openauth_core::error::OpenAuthError> {
    router_with_context(crate::scim_options_for_manual_provider_tokens())
        .map(|(adapter, router, _context)| (adapter, router))
}

pub(super) fn router_with_context(
    options: ScimOptions,
) -> Result<
    (
        Arc<MemoryAdapter>,
        AuthRouter,
        openauth_core::context::AuthContext,
    ),
    openauth_core::error::OpenAuthError,
> {
    let adapter = Arc::new(MemoryAdapter::new());
    let context = create_auth_context_with_adapter(
        test_openauth_options(vec![scim(options)]),
        adapter.clone(),
    )?;
    let router = AuthRouter::with_async_endpoints(
        context.clone(),
        Vec::new(),
        core_auth_async_endpoints(adapter.clone()),
    )?;
    Ok((adapter, router, context))
}

pub(super) fn router_with_context_and_organization(
    options: ScimOptions,
) -> Result<
    (
        Arc<MemoryAdapter>,
        AuthRouter,
        openauth_core::context::AuthContext,
    ),
    openauth_core::error::OpenAuthError,
> {
    router_with_context_and_organization_options(options, OrganizationOptions::default())
}

pub(super) fn router_with_context_and_organization_options(
    options: ScimOptions,
    organization_options: OrganizationOptions,
) -> Result<
    (
        Arc<MemoryAdapter>,
        AuthRouter,
        openauth_core::context::AuthContext,
    ),
    openauth_core::error::OpenAuthError,
> {
    let adapter = Arc::new(MemoryAdapter::new());
    let context = create_auth_context_with_adapter(
        test_openauth_options(vec![
            organization_with_options(organization_options),
            scim(options),
        ]),
        adapter.clone(),
    )?;
    let router = AuthRouter::with_async_endpoints(
        context.clone(),
        Vec::new(),
        core_auth_async_endpoints(adapter.clone()),
    )?;
    Ok((adapter, router, context))
}

pub(super) fn request(method: Method, path: &str) -> Request<Vec<u8>> {
    Request::builder()
        .method(method)
        .uri(path)
        .body(Vec::new())
        .expect("request should build")
}

pub(super) fn auth_request(method: Method, path: &str, token: &str) -> Request<Vec<u8>> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Vec::new())
        .expect("request should build")
}

pub(super) fn session_request(method: Method, path: &str, cookie: &str) -> Request<Vec<u8>> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(header::COOKIE, cookie)
        .body(Vec::new())
        .expect("request should build")
}

pub(super) fn json_request(
    method: Method,
    path: &str,
    body: &str,
    token: Option<&str>,
) -> Request<Vec<u8>> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/scim+json");
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    builder
        .body(body.as_bytes().to_vec())
        .expect("request should build")
}

pub(super) fn session_json_request(
    method: Method,
    path: &str,
    body: &str,
    cookie: &str,
) -> Request<Vec<u8>> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, cookie)
        .body(body.as_bytes().to_vec())
        .expect("request should build")
}

pub(super) async fn session_cookie(
    adapter: &MemoryAdapter,
    context: &openauth_core::context::AuthContext,
    email: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    session_cookie_with_user(adapter, context, email)
        .await
        .map(|(cookie, _user_id)| cookie)
}

pub(super) async fn session_cookie_with_user(
    adapter: &MemoryAdapter,
    context: &openauth_core::context::AuthContext,
    email: &str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let user = DbUserStore::new(adapter)
        .create_user(CreateUserInput::new("Session User", email).email_verified(true))
        .await?;
    let user_id = user.id.clone();
    let session = DbSessionStore::new(adapter)
        .create_session(CreateSessionInput::new(
            user.id,
            OffsetDateTime::now_utc() + Duration::hours(1),
        ))
        .await?;
    let cookies = set_session_cookie(
        &context.auth_cookies,
        &context.secret,
        &session.token,
        SessionCookieOptions::default(),
    )?;
    Ok((cookie_header(&cookies), user_id))
}

pub(super) fn cookie_header(cookies: &[Cookie]) -> String {
    cookies
        .iter()
        .map(|cookie| format!("{}={}", cookie.name, cookie.value))
        .collect::<Vec<_>>()
        .join("; ")
}

pub(super) async fn seed_organization(
    adapter: &dyn DbAdapter,
    id: &str,
) -> Result<(), openauth_core::error::OpenAuthError> {
    let now = OffsetDateTime::now_utc();
    adapter
        .create(
            Create::new("organization")
                .data("id", DbValue::String(id.to_owned()))
                .data("name", DbValue::String("Test Org".to_owned()))
                .data("slug", DbValue::String(id.to_owned()))
                .data("logo", DbValue::Null)
                .data("metadata", DbValue::Null)
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Null)
                .force_allow_id(),
        )
        .await?;
    Ok(())
}

pub(super) async fn seed_member(
    adapter: &dyn DbAdapter,
    organization_id: &str,
    user_id: &str,
    role: &str,
) -> Result<(), openauth_core::error::OpenAuthError> {
    adapter
        .create(
            Create::new("member")
                .data(
                    "id",
                    DbValue::String(format!("member_{organization_id}_{user_id}")),
                )
                .data(
                    "organization_id",
                    DbValue::String(organization_id.to_owned()),
                )
                .data("user_id", DbValue::String(user_id.to_owned()))
                .data("role", DbValue::String(role.to_owned()))
                .data("created_at", DbValue::Timestamp(OffsetDateTime::now_utc()))
                .force_allow_id(),
        )
        .await?;
    Ok(())
}

pub(super) async fn remove_member(
    adapter: &dyn DbAdapter,
    organization_id: &str,
    user_id: &str,
) -> Result<(), openauth_core::error::OpenAuthError> {
    adapter
        .delete(
            Delete::new("member")
                .where_clause(Where::new(
                    "organization_id",
                    DbValue::String(organization_id.to_owned()),
                ))
                .where_clause(Where::new("user_id", DbValue::String(user_id.to_owned()))),
        )
        .await
}

pub(super) async fn generated_token_can_provision_user_with_options(options: ScimOptions) {
    let (adapter, router, context) = router_with_context(options).expect("router");
    let cookie = session_cookie(adapter.as_ref(), &context, "owner@example.com")
        .await
        .expect("session cookie should create");

    let generated = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta"}"#,
            &cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(generated.status(), StatusCode::CREATED);
    let token = json_body(generated)["scimToken"]
        .as_str()
        .expect("token should be string")
        .to_owned();

    let created = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{"userName":"storage-mode@example.com"}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(created.status(), StatusCode::CREATED);
}

pub(super) async fn create_scim_user(
    router: &AuthRouter,
    token: &str,
    user_name: &str,
    formatted_name: &str,
) -> String {
    let body = format!(r#"{{"userName":"{user_name}","name":{{"formatted":"{formatted_name}"}}}}"#);
    let response = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            &body,
            Some(token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(response.status(), StatusCode::CREATED);
    json_body(response)["id"]
        .as_str()
        .expect("user id")
        .to_owned()
}

pub(super) async fn create_scim_group(
    router: &AuthRouter,
    token: &str,
    display_name: &str,
    external_id: &str,
    members: &[&str],
) -> String {
    let members = members
        .iter()
        .map(|member| format!(r#"{{"value":"{member}"}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let body = format!(
        r#"{{"displayName":"{display_name}","externalId":"{external_id}","members":[{members}]}}"#
    );
    let response = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Groups",
            &body,
            Some(token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(response.status(), StatusCode::CREATED);
    json_body(response)["id"]
        .as_str()
        .expect("group id")
        .to_owned()
}

pub(super) async fn generate_scim_token(
    router: &AuthRouter,
    cookie: &str,
    provider_id: &str,
    organization_id: Option<&str>,
) -> String {
    let body = match organization_id {
        Some(organization_id) => {
            format!(r#"{{"providerId":"{provider_id}","organizationId":"{organization_id}"}}"#)
        }
        None => format!(r#"{{"providerId":"{provider_id}"}}"#),
    };
    let response = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            &body,
            cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(response.status(), StatusCode::CREATED);
    json_body(response)["scimToken"]
        .as_str()
        .expect("token should be string")
        .to_owned()
}

pub(super) fn json_body(response: http::Response<Vec<u8>>) -> Value {
    serde_json::from_slice(response.body()).expect("response should be JSON")
}
