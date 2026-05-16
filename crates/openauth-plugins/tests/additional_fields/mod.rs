use std::sync::Arc;

use http::{header, Method, Request, StatusCode};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::create_auth_context;
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::db::{DbFieldType, DbValue, MemoryAdapter};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{AdvancedOptions, OpenAuthOptions};
use openauth_plugins::additional_fields::{
    additional_fields, AdditionalField, AdditionalFieldsOptions,
};
use serde_json::Value;

fn secret() -> &'static str {
    "test-secret-123456789012345678901234"
}

fn router(
    adapter: Arc<MemoryAdapter>,
    plugin: openauth_core::plugin::AuthPlugin,
) -> Result<AuthRouter, OpenAuthError> {
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            plugins: vec![plugin],
            secret: Some(secret().to_owned()),
            advanced: AdvancedOptions {
                disable_csrf_check: true,
                disable_origin_check: true,
                ..AdvancedOptions::default()
            },
            ..OpenAuthOptions::default()
        },
        adapter.clone(),
    )?;
    AuthRouter::with_async_endpoints(context, Vec::new(), core_auth_async_endpoints(adapter))
}

fn json_request(method: Method, path: &str, body: Value) -> Result<Request<Vec<u8>>, http::Error> {
    Request::builder()
        .method(method)
        .uri(format!("http://localhost:3000{path}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(serde_json::to_vec(&body).unwrap_or_default())
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
    let plugin = additional_fields(
        AdditionalFieldsOptions::new().session_field(
            "theme",
            AdditionalField::new(DbFieldType::String)
                .default_value(DbValue::String("dark".to_owned()))
                .generated()
                .db_name("session_theme"),
        ),
    );
    let router = router(adapter.clone(), plugin)?;

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
