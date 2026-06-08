use std::sync::Arc;

use http::{header, Method, Request, StatusCode};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::create_auth_context;
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::db::{DbFieldType, DbValue, MemoryAdapter};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{EmailPasswordOptions, OpenAuthOptions, SessionOptions};
use openauth_core::plugin::AuthPlugin;
use openauth_core::test_utils::MemorySecondaryStorage as TestSecondaryStorage;
use openauth_plugins::additional_fields::{
    additional_fields, AdditionalField, AdditionalFieldsOptions,
};
use openauth_plugins::anonymous::{anonymous, AnonymousOptions};
use serde_json::Value;
use time::OffsetDateTime;

fn secret() -> &'static str {
    "test-secret-123456789012345678901234"
}

fn router(
    adapter: Arc<MemoryAdapter>,
    plugins: Vec<AuthPlugin>,
) -> Result<AuthRouter, OpenAuthError> {
    router_with_options(adapter, plugins, OpenAuthOptions::default())
}

fn router_with_options(
    adapter: Arc<MemoryAdapter>,
    plugins: Vec<AuthPlugin>,
    mut options: OpenAuthOptions,
) -> Result<AuthRouter, OpenAuthError> {
    options.plugins = plugins;
    options.secret = Some(secret().to_owned());
    options.advanced.disable_csrf_check = true;
    options.advanced.disable_origin_check = true;
    if !options.email_password.enabled {
        options.email_password = EmailPasswordOptions::new().enabled(true);
    }
    if !options.production {
        options.development = true;
    }
    let context = create_auth_context_with_adapter(options, adapter.clone())?;
    AuthRouter::with_async_endpoints(context, Vec::new(), core_auth_async_endpoints(adapter))
}

fn session_defaults_plugin() -> AuthPlugin {
    additional_fields(
        AdditionalFieldsOptions::new().session_field(
            "new_field",
            AdditionalField::new(DbFieldType::String)
                .default_value(DbValue::String("default-value".to_owned()))
                .generated(),
        ),
    )
}

fn json_request(method: Method, path: &str, body: Value) -> Result<Request<Vec<u8>>, http::Error> {
    json_request_with_cookie(method, path, body, None)
}

fn json_request_with_cookie(
    method: Method,
    path: &str,
    body: Value,
    cookie: Option<&str>,
) -> Result<Request<Vec<u8>>, http::Error> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://localhost:3000{path}"))
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(serde_json::to_vec(&body).unwrap_or_default())
}

fn request(method: Method, path: &str, cookie: &str) -> Result<Request<Vec<u8>>, http::Error> {
    Request::builder()
        .method(method)
        .uri(format!("http://localhost:3000{path}"))
        .header(header::COOKIE, cookie)
        .body(Vec::new())
}

fn response_cookie_header(response: &http::Response<Vec<u8>>) -> String {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|cookie| cookie.split(';').next().map(str::to_owned))
        .collect::<Vec<_>>()
        .join("; ")
}

#[test]
fn exposes_additional_fields_plugin_id() {
    assert_eq!(
        openauth_plugins::additional_fields::UPSTREAM_PLUGIN_ID,
        "additional-fields"
    );
}

#[test]
fn additional_fields_plugin_registers_user_and_session_schema(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin = additional_fields(
        AdditionalFieldsOptions::new()
            .user_field(
                "role",
                AdditionalField::new(DbFieldType::String)
                    .default_value(DbValue::String("member".to_owned()))
                    .generated(),
            )
            .session_field(
                "theme",
                AdditionalField::new(DbFieldType::String).optional(),
            ),
    );

    let context = create_auth_context(OpenAuthOptions {
        plugins: vec![plugin],
        ..OpenAuthOptions::default()
    })?;

    assert!(context
        .db_schema
        .table("user")
        .and_then(|table| table.field("role"))
        .is_some());
    assert!(context
        .db_schema
        .table("session")
        .and_then(|table| table.field("theme"))
        .is_some());
    assert!(context.options.user.additional_fields.contains_key("role"));
    assert!(context
        .options
        .session
        .additional_fields
        .contains_key("theme"));
    Ok(())
}

#[tokio::test]
async fn session_additional_field_db_name_is_used_for_defaults_and_returned_output(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::default());
    let router = router(
        adapter.clone(),
        vec![additional_fields(
            AdditionalFieldsOptions::new().session_field(
                "theme",
                AdditionalField::new(DbFieldType::String)
                    .default_value(DbValue::String("dark".to_owned()))
                    .generated()
                    .db_name("session_theme"),
            ),
        )],
    )?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            serde_json::json!({
                "name": "Ada",
                "email": "ada@example.test",
                "password": "password123"
            }),
        )?)
        .await?;
    let cookie = response_cookie_header(&response);
    let sessions = adapter.records("session").await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        sessions[0].get("session_theme"),
        Some(&DbValue::String("dark".to_owned()))
    );
    assert_eq!(sessions[0].get("theme"), None);

    let session_response = router
        .handle_async(request(Method::GET, "/api/auth/get-session", &cookie)?)
        .await?;
    let session_body: Value = serde_json::from_slice(session_response.body())?;
    assert_eq!(session_body["session"]["theme"], "dark");
    Ok(())
}

#[tokio::test]
async fn sign_up_applies_user_additional_field_default_values(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::default());
    let router = router(
        adapter.clone(),
        vec![additional_fields(
            AdditionalFieldsOptions::new().user_field(
                "plan",
                AdditionalField::new(DbFieldType::String)
                    .default_value(DbValue::String("free".to_owned()))
                    .generated(),
            ),
        )],
    )?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            serde_json::json!({
                "name": "Ada",
                "email": "ada@example.test",
                "password": "password123"
            }),
        )?)
        .await?;
    let cookie = response_cookie_header(&response);
    let users = adapter.records("user").await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        users[0].get("plan"),
        Some(&DbValue::String("free".to_owned()))
    );

    let session_response = router
        .handle_async(request(Method::GET, "/api/auth/get-session", &cookie)?)
        .await?;
    let session_body: Value = serde_json::from_slice(session_response.body())?;
    assert_eq!(session_body["user"]["plan"], "free");
    Ok(())
}

#[tokio::test]
async fn additional_fields_work_with_other_plugins() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::default());
    let router = router(
        adapter.clone(),
        vec![
            anonymous(AnonymousOptions::default()),
            additional_fields(
                AdditionalFieldsOptions::new().user_field(
                    "tier",
                    AdditionalField::new(DbFieldType::String)
                        .default_value(DbValue::String("guest".to_owned()))
                        .generated(),
                ),
            ),
        ],
    )?;

    let response = router
        .handle_async(
            Request::builder()
                .method(Method::POST)
                .uri("http://localhost:3000/api/auth/sign-in/anonymous")
                .body(Vec::new())?,
        )
        .await?;
    let users = adapter.records("user").await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(users.len(), 1);
    assert_eq!(
        users[0].get("tier"),
        Some(&DbValue::String("guest".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn sign_in_applies_session_additional_field_default_values(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::default());
    let router = router(adapter.clone(), vec![session_defaults_plugin()])?;

    let sign_up = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            serde_json::json!({
                "name": "Ada",
                "email": "ada@example.test",
                "password": "password123"
            }),
        )?)
        .await?;
    assert_eq!(sign_up.status(), StatusCode::OK);

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            serde_json::json!({
                "email": "ada@example.test",
                "password": "password123"
            }),
        )?)
        .await?;
    let cookie = response_cookie_header(&sign_in);

    let session_response = router
        .handle_async(request(Method::GET, "/api/auth/get-session", &cookie)?)
        .await?;
    let session_body: Value = serde_json::from_slice(session_response.body())?;

    assert_eq!(sign_in.status(), StatusCode::OK);
    assert_eq!(session_body["session"]["new_field"], "default-value");
    Ok(())
}

#[tokio::test]
async fn sign_in_applies_session_defaults_with_secondary_storage(
) -> Result<(), Box<dyn std::error::Error>> {
    let storage = Arc::new(TestSecondaryStorage::default());
    let adapter = Arc::new(MemoryAdapter::default());
    let router = router_with_options(
        adapter.clone(),
        vec![session_defaults_plugin()],
        OpenAuthOptions {
            secondary_storage: Some(storage.clone()),
            session: SessionOptions::default().store_session_in_database(true),
            ..OpenAuthOptions::default()
        },
    )?;

    let sign_up = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            serde_json::json!({
                "name": "Ada",
                "email": "ada@example.test",
                "password": "password123"
            }),
        )?)
        .await?;
    assert_eq!(sign_up.status(), StatusCode::OK);
    let sign_up_body: Value = serde_json::from_slice(sign_up.body())?;
    let token = sign_up_body["token"]
        .as_str()
        .ok_or("missing sign-up token")?;
    assert!(storage.value(&format!("session:{token}"))?.is_some());
    assert_eq!(adapter.len("session").await, 1);

    let cookie = response_cookie_header(&sign_up);
    let session_response = router
        .handle_async(request(Method::GET, "/api/auth/get-session", &cookie)?)
        .await?;
    let session_body: Value = serde_json::from_slice(session_response.body())?;

    assert_eq!(session_response.status(), StatusCode::OK);
    assert_eq!(session_body["session"]["new_field"], "default-value");
    Ok(())
}

#[tokio::test]
async fn sign_up_applies_runtime_computed_default_value_at_sign_up(
) -> Result<(), Box<dyn std::error::Error>> {
    let marker = format!("runtime-{}", OffsetDateTime::now_utc().unix_timestamp());
    let adapter = Arc::new(MemoryAdapter::default());
    let router = router(
        adapter.clone(),
        vec![additional_fields(
            AdditionalFieldsOptions::new().user_field(
                "new_field",
                AdditionalField::new(DbFieldType::String)
                    .optional()
                    .default_value(DbValue::String(marker.clone()))
                    .generated(),
            ),
        )],
    )?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            serde_json::json!({
                "name": "Ada",
                "email": "ada@example.test",
                "password": "password123"
            }),
        )?)
        .await?;
    let cookie = response_cookie_header(&response);
    let users = adapter.records("user").await;

    let session_response = router
        .handle_async(request(Method::GET, "/api/auth/get-session", &cookie)?)
        .await?;
    let session_body: Value = serde_json::from_slice(session_response.body())?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        users[0].get("new_field"),
        Some(&DbValue::String(marker.clone()))
    );
    assert_eq!(session_body["user"]["new_field"], marker);
    Ok(())
}
