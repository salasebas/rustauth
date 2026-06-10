use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use openauth_core::api::{core_auth_async_endpoints, ApiErrorResponse, AuthRouter};
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::db::MemoryAdapter;
use openauth_core::error::OpenAuthError;
use openauth_core::options::{AdvancedOptions, OpenAuthOptions};
use openauth_core::plugin::PluginPasswordValidationInput;
use openauth_core::test_utils::with_integration_test_defaults;
use openauth_plugins::have_i_been_pwned::{
    have_i_been_pwned_with, HaveIBeenPwnedCheckError, HaveIBeenPwnedChecker, HaveIBeenPwnedOptions,
    UPSTREAM_PLUGIN_ID,
};

#[test]
fn exposes_haveibeenpwned_upstream_id() {
    assert_eq!(UPSTREAM_PLUGIN_ID, "haveibeenpwned");
}

#[test]
fn options_constructor_preserves_upstream_options_shape() -> Result<(), Box<dyn std::error::Error>>
{
    let plugin = have_i_been_pwned_with(HaveIBeenPwnedOptions {
        enabled: false,
        paths: vec!["/change-password".to_owned()],
        custom_password_compromised_message: Some("Use another password.".to_owned()),
        checker: None,
    });

    assert_eq!(plugin.id, "have-i-been-pwned");
    let Some(options) = plugin.options else {
        return Err("plugin options should be serialized".into());
    };
    assert_eq!(options["enabled"], false);
    assert_eq!(options["paths"], serde_json::json!(["/change-password"]));
    assert_eq!(
        options["customPasswordCompromisedMessage"],
        "Use another password."
    );
    Ok(())
}

#[tokio::test]
async fn compromised_password_blocks_account_creation() -> Result<(), Box<dyn std::error::Error>> {
    let checker = Arc::new(FakeChecker::compromised());
    let adapter = Arc::new(MemoryAdapter::default());
    let router = router_with_adapter(
        adapter.clone(),
        have_i_been_pwned_with(HaveIBeenPwnedOptions::default().checker(checker)),
    )?;

    let response = router
        .handle_async(json_request(
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
        )?)
        .await?;

    assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
    let body: ApiErrorResponse = serde_json::from_slice(response.body())?;
    assert_eq!(body.code, "PASSWORD_COMPROMISED");
    assert_eq!(
        body.message,
        "The password you entered has been compromised. Please choose a different password."
    );
    assert_eq!(adapter.len("user").await, 0);
    assert_eq!(adapter.len("account").await, 0);
    Ok(())
}

#[tokio::test]
async fn uncompromised_password_allows_account_creation() -> Result<(), Box<dyn std::error::Error>>
{
    let checker = Arc::new(FakeChecker::uncompromised());
    let adapter = Arc::new(MemoryAdapter::default());
    let router = router_with_adapter(
        adapter.clone(),
        have_i_been_pwned_with(HaveIBeenPwnedOptions::default().checker(checker)),
    )?;

    let response = router
        .handle_async(json_request(
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
        )?)
        .await?;

    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(adapter.len("user").await, 1);
    Ok(())
}

#[tokio::test]
async fn custom_compromised_message_is_returned() -> Result<(), Box<dyn std::error::Error>> {
    let checker = Arc::new(FakeChecker::compromised());
    let router = router(have_i_been_pwned_with(
        HaveIBeenPwnedOptions {
            custom_password_compromised_message: Some("Choose a safer password.".to_owned()),
            ..HaveIBeenPwnedOptions::default()
        }
        .checker(checker),
    ))?;

    let response = router
        .handle_async(json_request(
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
        )?)
        .await?;

    let body: ApiErrorResponse = serde_json::from_slice(response.body())?;
    assert_eq!(body.message, "Choose a safer password.");
    Ok(())
}

#[tokio::test]
async fn disabled_plugin_skips_compromised_check() -> Result<(), Box<dyn std::error::Error>> {
    let checker = Arc::new(FakeChecker::compromised());
    let adapter = Arc::new(MemoryAdapter::default());
    let router = router_with_adapter(
        adapter.clone(),
        have_i_been_pwned_with(
            HaveIBeenPwnedOptions {
                enabled: false,
                ..HaveIBeenPwnedOptions::default()
            }
            .checker(checker),
        ),
    )?;

    let response = router
        .handle_async(json_request(
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
        )?)
        .await?;

    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(adapter.len("user").await, 1);
    Ok(())
}

#[tokio::test]
async fn custom_paths_skip_unmatched_routes() -> Result<(), Box<dyn std::error::Error>> {
    let checker = Arc::new(FakeChecker::compromised());
    let adapter = Arc::new(MemoryAdapter::default());
    let router = router_with_adapter(
        adapter.clone(),
        have_i_been_pwned_with(
            HaveIBeenPwnedOptions {
                paths: vec!["/change-password".to_owned()],
                ..HaveIBeenPwnedOptions::default()
            }
            .checker(checker),
        ),
    )?;

    let response = router
        .handle_async(json_request(
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
        )?)
        .await?;

    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(adapter.len("user").await, 1);
    Ok(())
}

#[tokio::test]
async fn checker_receives_hash_prefix_and_suffix_not_raw_password(
) -> Result<(), Box<dyn std::error::Error>> {
    let checker = Arc::new(FakeChecker::uncompromised());
    let router = router(have_i_been_pwned_with(
        HaveIBeenPwnedOptions::default().checker(checker.clone()),
    ))?;

    let response = router
        .handle_async(json_request(
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"123456789"}"#,
        )?)
        .await?;

    assert_eq!(response.status(), http::StatusCode::OK);
    let observed = checker
        .observed_hash_parts
        .lock()
        .map_err(|error| OpenAuthError::Api(error.to_string()))?
        .clone();
    assert_eq!(
        observed,
        vec![(
            "F7C3B".to_owned(),
            "C1D808E04732ADF679965CCC34CA7AE3441".to_owned(),
        )]
    );
    assert!(!observed
        .iter()
        .any(|(prefix, suffix)| prefix == "123456789" || suffix == "123456789"));
    Ok(())
}

#[tokio::test]
async fn compromised_password_blocks_change_password() -> Result<(), Box<dyn std::error::Error>> {
    let checker = Arc::new(FakeChecker::compromised());
    let adapter = Arc::new(MemoryAdapter::default());
    let router = router_with_adapter(
        adapter,
        have_i_been_pwned_with(
            HaveIBeenPwnedOptions {
                paths: vec!["/change-password".to_owned()],
                ..HaveIBeenPwnedOptions::default()
            }
            .checker(checker),
        ),
    )?;

    let sign_up_response = router
        .handle_async(json_request(
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
        )?)
        .await?;
    assert_eq!(sign_up_response.status(), http::StatusCode::OK);
    let cookie = cookie_header_from_set_cookie(&sign_up_response);

    let response = router
        .handle_async(json_request_with_cookie(
            "/api/auth/change-password",
            r#"{"currentPassword":"secret123","newPassword":"new-secret123"}"#,
            &cookie,
        )?)
        .await?;

    assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
    let body: ApiErrorResponse = serde_json::from_slice(response.body())?;
    assert_eq!(body.code, "PASSWORD_COMPROMISED");
    Ok(())
}

#[tokio::test]
async fn empty_password_skips_checker() -> Result<(), Box<dyn std::error::Error>> {
    let checker = Arc::new(FakeChecker::compromised());
    let plugin = have_i_been_pwned_with(HaveIBeenPwnedOptions::default().checker(checker.clone()));
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some("test-secret-123456789012345678901234".to_owned()),
            advanced: AdvancedOptions {
                disable_csrf_check: true,
                disable_origin_check: true,
                ..AdvancedOptions::default()
            },
            ..OpenAuthOptions::default()
        },
        Arc::new(MemoryAdapter::default()),
    )?;

    let result = (plugin.password_validators[0].handler)(
        &context,
        PluginPasswordValidationInput::new("/sign-up/email", ""),
    )
    .await;

    assert_eq!(result, Ok(()));
    let observed = checker
        .observed_hash_parts
        .lock()
        .map_err(|error| OpenAuthError::Api(error.to_string()))?;
    assert!(observed.is_empty());
    Ok(())
}

#[tokio::test]
async fn http_status_failure_returns_status_specific_500() -> Result<(), Box<dyn std::error::Error>>
{
    let checker = Arc::new(FakeChecker::http_status(503));
    let router = router(have_i_been_pwned_with(
        HaveIBeenPwnedOptions::default().checker(checker),
    ))?;

    let response = router
        .handle_async(json_request(
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
        )?)
        .await?;

    assert_eq!(response.status(), http::StatusCode::INTERNAL_SERVER_ERROR);
    let body: ApiErrorResponse = serde_json::from_slice(response.body())?;
    assert_eq!(body.code, "INTERNAL_SERVER_ERROR");
    assert_eq!(body.message, "Failed to check password. Status: 503");
    Ok(())
}

#[tokio::test]
async fn transport_failure_returns_generic_500() -> Result<(), Box<dyn std::error::Error>> {
    let checker = Arc::new(FakeChecker::transport("connection failed"));
    let router = router(have_i_been_pwned_with(
        HaveIBeenPwnedOptions::default().checker(checker),
    ))?;

    let response = router
        .handle_async(json_request(
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
        )?)
        .await?;

    assert_eq!(response.status(), http::StatusCode::INTERNAL_SERVER_ERROR);
    let body: ApiErrorResponse = serde_json::from_slice(response.body())?;
    assert_eq!(body.code, "INTERNAL_SERVER_ERROR");
    assert_eq!(
        body.message,
        "Failed to check password. Please try again later."
    );
    Ok(())
}

#[derive(Debug)]
struct FakeChecker {
    result: Result<bool, HaveIBeenPwnedCheckError>,
    observed_hash_parts: Mutex<Vec<(String, String)>>,
}

impl FakeChecker {
    fn compromised() -> Self {
        Self {
            result: Ok(true),
            observed_hash_parts: Mutex::new(Vec::new()),
        }
    }

    fn uncompromised() -> Self {
        Self {
            result: Ok(false),
            observed_hash_parts: Mutex::new(Vec::new()),
        }
    }

    fn http_status(status: u16) -> Self {
        Self {
            result: Err(HaveIBeenPwnedCheckError::HttpStatus(status)),
            observed_hash_parts: Mutex::new(Vec::new()),
        }
    }

    fn transport(message: impl Into<String>) -> Self {
        Self {
            result: Err(HaveIBeenPwnedCheckError::Transport(message.into())),
            observed_hash_parts: Mutex::new(Vec::new()),
        }
    }
}

impl HaveIBeenPwnedChecker for FakeChecker {
    fn is_hash_suffix_compromised<'a>(
        &'a self,
        prefix: &'a str,
        suffix: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<bool, HaveIBeenPwnedCheckError>> + Send + 'a>> {
        Box::pin(async move {
            self.observed_hash_parts
                .lock()
                .map_err(|error| HaveIBeenPwnedCheckError::Transport(error.to_string()))?
                .push((prefix.to_owned(), suffix.to_owned()));
            self.result.clone()
        })
    }
}

fn router(plugin: openauth_core::plugin::AuthPlugin) -> Result<AuthRouter, OpenAuthError> {
    router_with_adapter(Arc::new(MemoryAdapter::default()), plugin)
}

fn router_with_adapter(
    adapter: Arc<MemoryAdapter>,
    plugin: openauth_core::plugin::AuthPlugin,
) -> Result<AuthRouter, OpenAuthError> {
    let context = create_auth_context_with_adapter(
        with_integration_test_defaults(OpenAuthOptions {
            secret: Some("test-secret-123456789012345678901234".to_owned()),
            plugins: vec![plugin],
            advanced: AdvancedOptions {
                disable_csrf_check: true,
                disable_origin_check: true,
                ..AdvancedOptions::default()
            },
            ..OpenAuthOptions::default()
        }),
        adapter.clone(),
    )?;
    AuthRouter::with_async_endpoints(context, Vec::new(), core_auth_async_endpoints(adapter))
}

fn json_request(path: &str, body: &str) -> Result<openauth_core::api::ApiRequest, http::Error> {
    http::Request::builder()
        .method(http::Method::POST)
        .uri(format!("http://localhost:3000{path}"))
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(body.as_bytes().to_vec())
}

fn json_request_with_cookie(
    path: &str,
    body: &str,
    cookie: &str,
) -> Result<openauth_core::api::ApiRequest, http::Error> {
    http::Request::builder()
        .method(http::Method::POST)
        .uri(format!("http://localhost:3000{path}"))
        .header(http::header::CONTENT_TYPE, "application/json")
        .header(http::header::COOKIE, cookie)
        .body(body.as_bytes().to_vec())
}

fn cookie_header_from_set_cookie(response: &http::Response<Vec<u8>>) -> String {
    response
        .headers()
        .get_all(http::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|value| value.split(';').next())
        .collect::<Vec<_>>()
        .join("; ")
}
