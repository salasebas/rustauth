use http::{Method, Request, StatusCode};
use openauth_core::api::{response, ApiRequest, ApiResponse, AuthEndpoint, AuthRouter};
use openauth_core::context::{create_auth_context_with_environment, AuthEnvironment};
use openauth_core::cookies::get_cookies;
use openauth_core::env::{allows_development_defaults, is_production_posture};
use openauth_core::error::OpenAuthError;
use openauth_core::options::OpenAuthOptions;
use openauth_core::rate_limit::resolve_client_ip;
use std::sync::{Mutex, MutexGuard, OnceLock};

struct EnvRestore(Vec<(&'static str, Option<String>)>);

impl EnvRestore {
    fn unset(keys: &[&'static str]) -> Self {
        let saved = keys
            .iter()
            .map(|key| (*key, std::env::var(key).ok()))
            .collect::<Vec<_>>();
        for key in keys {
            std::env::remove_var(key);
        }
        Self(saved)
    }
}

impl Drop for EnvRestore {
    fn drop(&mut self) {
        for (key, value) in &self.0 {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
}

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn lock_ambiguous_env() -> (MutexGuard<'static, ()>, EnvRestore) {
    let guard = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let restore = EnvRestore::unset(&["RUST_ENV", "RUST_TEST_THREADS", "TEST", "NEXTEST"]);
    (guard, restore)
}

fn ambiguous_options() -> OpenAuthOptions {
    OpenAuthOptions::default()
}

#[test]
fn ambiguous_deployment_fails_closed_for_production_posture() {
    let _guard = lock_ambiguous_env();
    let options = ambiguous_options();

    assert!(is_production_posture(&options));
    assert!(!allows_development_defaults(&options));
}

#[test]
fn explicit_development_allows_development_defaults() {
    let _guard = lock_ambiguous_env();
    let options = OpenAuthOptions::default().development(true);

    assert!(!is_production_posture(&options));
    assert!(allows_development_defaults(&options));
}

#[test]
fn ambiguous_deployment_rejects_default_secret() {
    let _guard = lock_ambiguous_env();
    let result =
        create_auth_context_with_environment(ambiguous_options(), AuthEnvironment::default());

    assert!(matches!(
        result,
        Err(OpenAuthError::InvalidConfig(message))
            if message.contains("default secret cannot be used in production")
    ));
}

#[test]
fn ambiguous_deployment_enables_rate_limiting_by_default() -> Result<(), Box<dyn std::error::Error>>
{
    let _guard = lock_ambiguous_env();
    let context = create_auth_context_with_environment(
        OpenAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            ..ambiguous_options()
        },
        AuthEnvironment::default(),
    )?;

    assert!(context.rate_limit.enabled);
    Ok(())
}

#[test]
fn ambiguous_deployment_does_not_fallback_to_localhost_ip() -> Result<(), Box<dyn std::error::Error>>
{
    let _guard = lock_ambiguous_env();
    let context = create_auth_context_with_environment(
        OpenAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            ..ambiguous_options()
        },
        AuthEnvironment::default(),
    )?;
    let request = Request::builder()
        .method(Method::GET)
        .uri("http://localhost:3000/api/auth/ok")
        .body(Vec::new())?;

    assert_eq!(resolve_client_ip(&context, &request), None);
    Ok(())
}

#[test]
fn ambiguous_deployment_defaults_cookies_to_secure_without_base_url(
) -> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_ambiguous_env();
    let cookies = get_cookies(&ambiguous_options())?;

    assert_eq!(cookies.session_token.attributes.secure, Some(true));
    Ok(())
}

#[test]
fn ambiguous_deployment_denies_rate_limited_requests_without_client_ip(
) -> Result<(), Box<dyn std::error::Error>> {
    let _guard = lock_ambiguous_env();
    let context = create_auth_context_with_environment(
        OpenAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            ..ambiguous_options()
        },
        AuthEnvironment::default(),
    )?;
    let router = AuthRouter::new(
        context,
        vec![AuthEndpoint {
            path: "/ok".to_owned(),
            method: Method::GET,
            handler: ok_handler,
        }],
    );

    let response = router.handle(
        Request::builder()
            .method(Method::GET)
            .uri("http://localhost:3000/api/auth/ok")
            .body(Vec::new())?,
    )?;

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    Ok(())
}

fn ok_handler(
    _context: &openauth_core::context::AuthContext,
    _request: ApiRequest,
) -> Result<ApiResponse, OpenAuthError> {
    response(StatusCode::OK, b"OK".to_vec())
}
