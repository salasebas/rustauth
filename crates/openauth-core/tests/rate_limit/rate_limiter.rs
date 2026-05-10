use http::{Method, Request, StatusCode};
use openauth_core::api::{response, ApiRequest, ApiResponse, AuthEndpoint, AuthRouter};
use openauth_core::context::create_auth_context;
use openauth_core::error::OpenAuthError;
use openauth_core::options::{
    DynamicRateLimitPathRule, OpenAuthOptions, RateLimitOptions, RateLimitPathRule,
    RateLimitRecord, RateLimitRule, RateLimitStorage,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

fn endpoint(path: &str, method: Method) -> AuthEndpoint {
    AuthEndpoint {
        path: path.to_owned(),
        method,
        handler: ok_handler,
    }
}

fn ok_handler(
    _context: &openauth_core::context::AuthContext,
    _request: ApiRequest,
) -> Result<ApiResponse, OpenAuthError> {
    response(StatusCode::OK, b"OK".to_vec())
}

fn assert_error_body(
    response: &ApiResponse,
    code: &str,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let body: serde_json::Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], code);
    assert_eq!(body["message"], message);
    Ok(())
}

#[test]
fn rate_limiter_uses_special_sign_in_rule() -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        rate_limit: RateLimitOptions {
            enabled: Some(true),
            window: 10,
            max: 20,
            ..RateLimitOptions::default()
        },
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::new(context, vec![endpoint("/sign-in/email", Method::POST)]);

    for attempt in 0..4 {
        let response = router.handle(
            Request::builder()
                .method(Method::POST)
                .uri("http://localhost:3000/api/auth/sign-in/email")
                .body(Vec::new())?,
        )?;
        if attempt < 3 {
            assert_eq!(response.status(), StatusCode::OK);
        } else {
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(
                response
                    .headers()
                    .get("X-Retry-After")
                    .ok_or("missing retry header")?,
                "10"
            );
            assert_error_body(
                &response,
                "TOO_MANY_REQUESTS",
                "Too many requests. Please try again later.",
            )?;
        }
    }

    Ok(())
}

#[test]
fn rate_limiter_keys_by_normalized_path_without_query() -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        rate_limit: RateLimitOptions {
            enabled: Some(true),
            window: 10,
            max: 2,
            ..RateLimitOptions::default()
        },
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::new(context, vec![endpoint("/ok", Method::GET)]);

    for attempt in 0..3 {
        let response = router.handle(
            Request::builder()
                .method(Method::GET)
                .uri(format!("http://localhost:3000/api/auth/ok?nonce={attempt}"))
                .body(Vec::new())?,
        )?;
        if attempt < 2 {
            assert_eq!(response.status(), StatusCode::OK);
        } else {
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        }
    }

    Ok(())
}

#[test]
fn rate_limiter_keeps_client_ips_separate() -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        rate_limit: RateLimitOptions {
            enabled: Some(true),
            window: 10,
            max: 1,
            ..RateLimitOptions::default()
        },
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::new(context, vec![endpoint("/ok", Method::GET)]);

    let first_ip = request_for_ip("192.0.2.1")?;
    assert_eq!(router.handle(first_ip)?.status(), StatusCode::OK);

    let first_ip_again = request_for_ip("192.0.2.1")?;
    assert_eq!(
        router.handle(first_ip_again)?.status(),
        StatusCode::TOO_MANY_REQUESTS
    );

    let second_ip = request_for_ip("192.0.2.2")?;
    assert_eq!(router.handle(second_ip)?.status(), StatusCode::OK);

    Ok(())
}

#[test]
fn rate_limiter_supports_custom_wildcard_rules() -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        rate_limit: RateLimitOptions {
            enabled: Some(true),
            custom_rules: vec![RateLimitPathRule {
                path: "/sign-in/*".to_owned(),
                rule: Some(RateLimitRule { window: 10, max: 2 }),
            }],
            ..RateLimitOptions::default()
        },
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::new(context, vec![endpoint("/sign-in/email", Method::POST)]);

    for attempt in 0..3 {
        let response = router.handle(
            Request::builder()
                .method(Method::POST)
                .uri("http://localhost:3000/api/auth/sign-in/email")
                .body(Vec::new())?,
        )?;
        if attempt < 2 {
            assert_eq!(response.status(), StatusCode::OK);
        } else {
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        }
    }

    Ok(())
}

#[test]
fn rate_limiter_can_disable_a_custom_path() -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        rate_limit: RateLimitOptions {
            enabled: Some(true),
            window: 10,
            max: 1,
            custom_rules: vec![RateLimitPathRule {
                path: "/get-session".to_owned(),
                rule: None,
            }],
            ..RateLimitOptions::default()
        },
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::new(context, vec![endpoint("/get-session", Method::GET)]);

    for _ in 0..5 {
        let response = router.handle(
            Request::builder()
                .method(Method::GET)
                .uri("http://localhost:3000/api/auth/get-session")
                .body(Vec::new())?,
        )?;
        assert_eq!(response.status(), StatusCode::OK);
    }

    Ok(())
}

#[test]
fn rate_limiter_supports_dynamic_request_aware_rules() -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        rate_limit: RateLimitOptions {
            enabled: Some(true),
            dynamic_rules: vec![DynamicRateLimitPathRule::new(
                "/ok",
                |request: &Request<Vec<u8>>,
                 current_rule: &RateLimitRule|
                 -> Result<Option<RateLimitRule>, OpenAuthError> {
                    if request.headers().get("x-strict-limit").is_some() {
                        return Ok(Some(RateLimitRule {
                            window: current_rule.window,
                            max: 1,
                        }));
                    }
                    Ok(Some(current_rule.clone()))
                },
            )],
            ..RateLimitOptions::default()
        },
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::new(context, vec![endpoint("/ok", Method::GET)]);

    let first = router.handle(
        Request::builder()
            .method(Method::GET)
            .uri("http://localhost:3000/api/auth/ok")
            .header("x-strict-limit", "1")
            .body(Vec::new())?,
    )?;
    assert_eq!(first.status(), StatusCode::OK);

    let second = router.handle(
        Request::builder()
            .method(Method::GET)
            .uri("http://localhost:3000/api/auth/ok")
            .header("x-strict-limit", "1")
            .body(Vec::new())?,
    )?;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);

    Ok(())
}

#[test]
fn disabled_paths_do_not_touch_rate_limit_storage() -> Result<(), Box<dyn std::error::Error>> {
    let storage = Arc::new(TestStorage::default());
    let context = create_auth_context(OpenAuthOptions {
        disabled_paths: vec!["/limited".to_owned()],
        rate_limit: RateLimitOptions {
            enabled: Some(true),
            window: 10,
            max: 1,
            custom_storage: Some(storage.clone()),
            ..RateLimitOptions::default()
        },
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::new(context, vec![endpoint("/limited", Method::GET)]);

    for _ in 0..2 {
        let response = router.handle(
            Request::builder()
                .method(Method::GET)
                .uri("http://localhost:3000/api/auth/limited")
                .body(Vec::new())?,
        )?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    assert_eq!(*storage.set_calls.lock().map_err(|_| "lock poisoned")?, 0);
    Ok(())
}

#[test]
fn production_requests_without_ip_are_not_rate_limited() -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        production: true,
        rate_limit: RateLimitOptions {
            enabled: Some(true),
            window: 10,
            max: 1,
            ..RateLimitOptions::default()
        },
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::new(context, vec![endpoint("/ok", Method::GET)]);

    for _ in 0..3 {
        let response = router.handle(
            Request::builder()
                .method(Method::GET)
                .uri("http://localhost:3000/api/auth/ok")
                .body(Vec::new())?,
        )?;
        assert_eq!(response.status(), StatusCode::OK);
    }

    Ok(())
}

fn request_for_ip(ip: &str) -> Result<ApiRequest, http::Error> {
    Request::builder()
        .method(Method::GET)
        .uri("http://localhost:3000/api/auth/ok")
        .header("x-forwarded-for", ip)
        .body(Vec::new())
}

#[derive(Debug, Default)]
struct TestStorage {
    records: Mutex<HashMap<String, RateLimitRecord>>,
    set_calls: Mutex<u64>,
}

impl RateLimitStorage for TestStorage {
    fn get(&self, key: &str) -> Result<Option<RateLimitRecord>, OpenAuthError> {
        Ok(self
            .records
            .lock()
            .map_err(|_| OpenAuthError::Api("test storage lock poisoned".to_owned()))?
            .get(key)
            .cloned())
    }

    fn set(
        &self,
        key: &str,
        value: RateLimitRecord,
        _ttl_seconds: u64,
        _update: bool,
    ) -> Result<(), OpenAuthError> {
        *self
            .set_calls
            .lock()
            .map_err(|_| OpenAuthError::Api("test storage lock poisoned".to_owned()))? += 1;
        self.records
            .lock()
            .map_err(|_| OpenAuthError::Api("test storage lock poisoned".to_owned()))?
            .insert(key.to_owned(), value);
        Ok(())
    }
}
