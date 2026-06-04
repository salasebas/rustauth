use http::{Method, Request, StatusCode};
use openauth_core::api::{response, ApiRequest, ApiResponse, AuthEndpoint, AuthRouter};
use openauth_core::context::create_auth_context;
use openauth_core::error::OpenAuthError;
use openauth_core::options::{
    AdvancedOptions, DynamicRateLimitPathRule, HybridRateLimitOptions, IpAddressOptions,
    MissingIpPolicy, OpenAuthOptions, RateLimitConsumeInput, RateLimitDecision, RateLimitFuture,
    RateLimitOptions, RateLimitPathRule, RateLimitRecord, RateLimitRule, RateLimitStorage,
    RateLimitStorageOption, RateLimitStore,
};
use openauth_core::rate_limit::{
    consume_rate_limit, consume_scoped_rate_limit, hash_rate_limit_scope,
    GovernorMemoryRateLimitStore, RequestClientIp,
};
use openauth_core::utils::ip::{create_rate_limit_key, create_rate_limit_key_with_suffix};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

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

#[tokio::test]
async fn rate_limiter_uses_special_sign_in_rule() -> Result<(), Box<dyn std::error::Error>> {
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
        let response = router
            .handle_async(
                Request::builder()
                    .method(Method::POST)
                    .uri("http://localhost:3000/api/auth/sign-in/email")
                    .body(Vec::new())?,
            )
            .await?;
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

#[tokio::test]
async fn rate_limiter_keys_by_normalized_path_without_query(
) -> Result<(), Box<dyn std::error::Error>> {
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
        let response = router
            .handle_async(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("http://localhost:3000/api/auth/ok?nonce={attempt}"))
                    .body(Vec::new())?,
            )
            .await?;
        if attempt < 2 {
            assert_eq!(response.status(), StatusCode::OK);
        } else {
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        }
    }

    Ok(())
}

#[tokio::test]
async fn memory_rate_limiter_ceil_retry_after_seconds() -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        rate_limit: RateLimitOptions {
            enabled: Some(true),
            window: 1,
            max: 2,
            ..RateLimitOptions::default()
        },
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::new(context, vec![endpoint("/ok", Method::GET)]);

    for _ in 0..2 {
        let response = router
            .handle_async(
                Request::builder()
                    .method(Method::GET)
                    .uri("http://localhost:3000/api/auth/ok")
                    .body(Vec::new())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
    }

    let denied = router
        .handle_async(
            Request::builder()
                .method(Method::GET)
                .uri("http://localhost:3000/api/auth/ok")
                .body(Vec::new())?,
        )
        .await?;

    assert_eq!(denied.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        denied
            .headers()
            .get("X-Retry-After")
            .ok_or("missing retry header")?,
        "1"
    );
    Ok(())
}

#[tokio::test]
async fn governor_memory_rate_limiter_reports_remaining_capacity(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = GovernorMemoryRateLimitStore::new();
    let rule = RateLimitRule { window: 10, max: 3 };
    let key = "127.0.0.1|/ok".to_owned();

    let first = store
        .consume(RateLimitConsumeInput {
            key: key.clone(),
            rule: rule.clone(),
            now_ms: 1_700_000_000_000,
        })
        .await?;
    assert!(first.permitted);
    assert_eq!(first.limit, 3);
    assert_eq!(first.remaining, 2);
    assert_eq!(first.retry_after, 0);

    let second = store
        .consume(RateLimitConsumeInput {
            key,
            rule,
            now_ms: 1_700_000_000_001,
        })
        .await?;
    assert!(second.permitted);
    assert_eq!(second.remaining, 1);
    assert_eq!(second.retry_after, 0);

    Ok(())
}

#[tokio::test]
async fn runtime_external_rate_limit_storage_without_store_returns_clear_error(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut context = create_auth_context(OpenAuthOptions {
        rate_limit: RateLimitOptions {
            enabled: Some(true),
            window: 10,
            max: 1,
            ..RateLimitOptions::default()
        },
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    context.rate_limit.storage = RateLimitStorageOption::Database;
    context.rate_limit.custom_store = None;

    let result = consume_rate_limit(
        &context,
        &Request::builder()
            .method(Method::GET)
            .uri("http://localhost:3000/api/auth/ok")
            .body(Vec::new())?,
    )
    .await;

    assert!(matches!(
        result,
        Err(OpenAuthError::InvalidConfig(message))
            if message.contains("database rate limit storage")
                && message.contains("RateLimitStore")
    ));
    Ok(())
}

#[tokio::test]
async fn rate_limiter_keeps_client_ips_separate() -> Result<(), Box<dyn std::error::Error>> {
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

    let first_ip = request_for_client_ip("192.0.2.1")?;
    assert_eq!(
        router.handle_async(first_ip).await?.status(),
        StatusCode::OK
    );

    let first_ip_again = request_for_client_ip("192.0.2.1")?;
    assert_eq!(
        router.handle_async(first_ip_again).await?.status(),
        StatusCode::TOO_MANY_REQUESTS
    );

    let second_ip = request_for_client_ip("192.0.2.2")?;
    assert_eq!(
        router.handle_async(second_ip).await?.status(),
        StatusCode::OK
    );

    Ok(())
}

#[tokio::test]
async fn rate_limiter_ignores_unconfigured_forwarded_headers(
) -> Result<(), Box<dyn std::error::Error>> {
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

    let first = request_for_client_ip_with_header("192.0.2.10", "203.0.113.1")?;
    assert_eq!(router.handle_async(first).await?.status(), StatusCode::OK);

    let second = request_for_client_ip_with_header("192.0.2.10", "203.0.113.2")?;
    assert_eq!(
        router.handle_async(second).await?.status(),
        StatusCode::TOO_MANY_REQUESTS
    );

    Ok(())
}

#[tokio::test]
async fn rate_limiter_uses_request_client_ip_extension() -> Result<(), Box<dyn std::error::Error>> {
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

    assert_eq!(
        router
            .handle_async(request_for_client_ip("192.0.2.20")?)
            .await?
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        router
            .handle_async(request_for_client_ip("192.0.2.20")?)
            .await?
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        router
            .handle_async(request_for_client_ip("192.0.2.21")?)
            .await?
            .status(),
        StatusCode::OK
    );

    Ok(())
}

#[tokio::test]
async fn rate_limiter_uses_explicit_forwarded_header_configuration(
) -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        production: true,
        advanced: AdvancedOptions::new()
            .ip_address(IpAddressOptions::new().headers(["x-forwarded-for"])),
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

    assert_eq!(
        router
            .handle_async(request_for_ip("192.0.2.30")?)
            .await?
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        router
            .handle_async(request_for_ip("192.0.2.30")?)
            .await?
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        router
            .handle_async(request_for_ip("192.0.2.31")?)
            .await?
            .status(),
        StatusCode::OK
    );

    Ok(())
}

#[tokio::test]
async fn rate_limiter_falls_back_to_client_ip_when_configured_header_is_invalid(
) -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        production: true,
        advanced: AdvancedOptions::new()
            .ip_address(IpAddressOptions::new().headers(["x-forwarded-for"])),
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

    let first = request_for_client_ip_with_header("192.0.2.40", "not an ip")?;
    assert_eq!(router.handle_async(first).await?.status(), StatusCode::OK);

    let second = request_for_client_ip_with_header("192.0.2.40", "still not an ip")?;
    assert_eq!(
        router.handle_async(second).await?.status(),
        StatusCode::TOO_MANY_REQUESTS
    );

    Ok(())
}

#[tokio::test]
async fn rate_limiter_supports_custom_wildcard_rules() -> Result<(), Box<dyn std::error::Error>> {
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
        let response = router
            .handle_async(
                Request::builder()
                    .method(Method::POST)
                    .uri("http://localhost:3000/api/auth/sign-in/email")
                    .body(Vec::new())?,
            )
            .await?;
        if attempt < 2 {
            assert_eq!(response.status(), StatusCode::OK);
        } else {
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        }
    }

    Ok(())
}

#[tokio::test]
async fn rate_limiter_can_disable_a_custom_path() -> Result<(), Box<dyn std::error::Error>> {
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
        let response = router
            .handle_async(
                Request::builder()
                    .method(Method::GET)
                    .uri("http://localhost:3000/api/auth/get-session")
                    .body(Vec::new())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
    }

    Ok(())
}

#[tokio::test]
async fn rate_limiter_supports_dynamic_request_aware_rules(
) -> Result<(), Box<dyn std::error::Error>> {
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

    let first = router
        .handle_async(
            Request::builder()
                .method(Method::GET)
                .uri("http://localhost:3000/api/auth/ok")
                .header("x-strict-limit", "1")
                .body(Vec::new())?,
        )
        .await?;
    assert_eq!(first.status(), StatusCode::OK);

    let second = router
        .handle_async(
            Request::builder()
                .method(Method::GET)
                .uri("http://localhost:3000/api/auth/ok")
                .header("x-strict-limit", "1")
                .body(Vec::new())?,
        )
        .await?;
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
fn production_requests_without_ip_are_denied_by_default() -> Result<(), Box<dyn std::error::Error>>
{
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

    // Fail closed: an enabled rate limit with an unresolvable client IP must
    // reject from the very first request, even on the sync handler path.
    for _ in 0..3 {
        let response = router.handle(
            Request::builder()
                .method(Method::GET)
                .uri("http://localhost:3000/api/auth/ok")
                .body(Vec::new())?,
        )?;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    Ok(())
}

#[tokio::test]
async fn production_sign_in_without_ip_cannot_bypass_special_limit(
) -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        production: true,
        rate_limit: RateLimitOptions {
            enabled: Some(true),
            window: 10,
            max: 100,
            ..RateLimitOptions::default()
        },
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::new(context, vec![endpoint("/sign-in/email", Method::POST)]);

    // Without RequestClientIp in production the default policy denies every
    // attempt, so the special /sign-in limit can never be bypassed.
    for _ in 0..5 {
        let response = router
            .handle_async(
                Request::builder()
                    .method(Method::POST)
                    .uri("http://localhost:3000/api/auth/sign-in/email")
                    .body(Vec::new())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    Ok(())
}

#[test]
fn production_requests_without_ip_allow_policy_skips_rate_limit(
) -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        production: true,
        rate_limit: RateLimitOptions {
            enabled: Some(true),
            window: 10,
            max: 1,
            missing_ip_policy: MissingIpPolicy::Allow,
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

#[tokio::test]
async fn production_sign_in_without_ip_shared_bucket_enforces_limit(
) -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        production: true,
        rate_limit: RateLimitOptions {
            enabled: Some(true),
            window: 10,
            max: 100,
            missing_ip_policy: MissingIpPolicy::SharedBucket,
            ..RateLimitOptions::default()
        },
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::new(context, vec![endpoint("/sign-in/email", Method::POST)]);

    // IP-less requests share one bucket and still honor the special /sign-in
    // limit (max 3) instead of bypassing it.
    for attempt in 0..4 {
        let response = router
            .handle_async(
                Request::builder()
                    .method(Method::POST)
                    .uri("http://localhost:3000/api/auth/sign-in/email")
                    .body(Vec::new())?,
            )
            .await?;
        if attempt < 3 {
            assert_eq!(response.status(), StatusCode::OK);
        } else {
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        }
    }

    Ok(())
}

#[test]
fn production_disabled_ip_tracking_skips_rate_limit() -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        production: true,
        advanced: AdvancedOptions::new()
            .ip_address(IpAddressOptions::new().disable_ip_tracking(true)),
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

    // Disabling IP tracking is an explicit opt-out: the fail-closed policy must
    // not turn it into a hard denial.
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

#[test]
fn sync_handler_returns_clear_error_when_rate_limit_must_consume(
) -> Result<(), Box<dyn std::error::Error>> {
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

    let error = match router.handle(
        Request::builder()
            .method(Method::GET)
            .uri("http://localhost:3000/api/auth/ok")
            .body(Vec::new())?,
    ) {
        Ok(response) => {
            return Err(format!("sync handler unexpectedly returned {}", response.status()).into());
        }
        Err(error) => error,
    };

    assert!(matches!(
        error,
        OpenAuthError::Api(message)
            if message == "async rate limit storage requires AuthRouter::handle_async"
    ));
    Ok(())
}

#[tokio::test]
async fn hybrid_local_denial_stops_before_global_store() -> Result<(), Box<dyn std::error::Error>> {
    let global = Arc::new(DecisionStore::permitted());
    let context = create_auth_context(OpenAuthOptions {
        rate_limit: RateLimitOptions {
            enabled: Some(true),
            window: 10,
            max: 1,
            custom_store: Some(global.clone()),
            hybrid: HybridRateLimitOptions {
                enabled: true,
                local_multiplier: 1,
            },
            ..RateLimitOptions::default()
        },
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::new(context, vec![endpoint("/ok", Method::GET)]);

    assert_eq!(
        router
            .handle_async(request_for_client_ip("192.0.2.10")?)
            .await?
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        router
            .handle_async(request_for_client_ip("192.0.2.10")?)
            .await?
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(global.calls(), 1);
    Ok(())
}

#[tokio::test]
async fn hybrid_returns_global_denial_when_local_permits() -> Result<(), Box<dyn std::error::Error>>
{
    let global = Arc::new(DecisionStore::denied(42));
    let context = create_auth_context(OpenAuthOptions {
        rate_limit: RateLimitOptions {
            enabled: Some(true),
            window: 10,
            max: 1,
            custom_store: Some(global.clone()),
            hybrid: HybridRateLimitOptions {
                enabled: true,
                local_multiplier: 10,
            },
            ..RateLimitOptions::default()
        },
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::new(context, vec![endpoint("/ok", Method::GET)]);

    let response = router
        .handle_async(request_for_client_ip("192.0.2.11")?)
        .await?;

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        response
            .headers()
            .get("X-Retry-After")
            .ok_or("missing retry header")?,
        "42"
    );
    assert_eq!(global.calls(), 1);
    Ok(())
}

#[tokio::test]
async fn hybrid_disabled_uses_distributed_store_directly() -> Result<(), Box<dyn std::error::Error>>
{
    let global = Arc::new(DecisionStore::denied(7));
    let context = create_auth_context(OpenAuthOptions {
        rate_limit: RateLimitOptions {
            enabled: Some(true),
            custom_store: Some(global.clone()),
            ..RateLimitOptions::default()
        },
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::new(context, vec![endpoint("/ok", Method::GET)]);

    let response = router
        .handle_async(request_for_client_ip("192.0.2.12")?)
        .await?;

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(global.calls(), 1);
    Ok(())
}

#[tokio::test]
async fn custom_store_decision_is_used_with_one_consume_call(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(DecisionStore::denied(13));
    let context = create_auth_context(OpenAuthOptions {
        rate_limit: RateLimitOptions {
            enabled: Some(true),
            custom_store: Some(store.clone()),
            ..RateLimitOptions::default()
        },
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::new(context, vec![endpoint("/ok", Method::GET)]);

    let response = router
        .handle_async(request_for_client_ip("192.0.2.13")?)
        .await?;

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        response
            .headers()
            .get("X-Retry-After")
            .ok_or("missing retry header")?,
        "13"
    );
    assert_eq!(store.calls(), 1);
    Ok(())
}

fn request_for_ip(ip: &str) -> Result<ApiRequest, http::Error> {
    Request::builder()
        .method(Method::GET)
        .uri("http://localhost:3000/api/auth/ok")
        .header("x-forwarded-for", ip)
        .body(Vec::new())
}

fn request_for_client_ip(ip: &str) -> Result<ApiRequest, Box<dyn std::error::Error>> {
    request_for_client_ip_with_header(ip, "198.51.100.1")
}

fn request_for_client_ip_with_header(
    client_ip: &str,
    forwarded_for: &str,
) -> Result<ApiRequest, Box<dyn std::error::Error>> {
    let mut request = Request::builder()
        .method(Method::GET)
        .uri("http://localhost:3000/api/auth/ok")
        .header("x-forwarded-for", forwarded_for)
        .body(Vec::new())?;
    request
        .extensions_mut()
        .insert(RequestClientIp(IpAddr::V4(client_ip.parse::<Ipv4Addr>()?)));
    Ok(request)
}

#[derive(Debug, Default)]
struct TestStorage {
    records: Mutex<HashMap<String, RateLimitRecord>>,
    set_calls: Mutex<u64>,
}

#[derive(Debug)]
struct DecisionStore {
    decision: RateLimitDecision,
    calls: AtomicUsize,
}

impl DecisionStore {
    fn permitted() -> Self {
        Self {
            decision: RateLimitDecision {
                permitted: true,
                retry_after: 0,
                limit: 1,
                remaining: 0,
                reset_after: 10,
            },
            calls: AtomicUsize::new(0),
        }
    }

    fn denied(retry_after: u64) -> Self {
        Self {
            decision: RateLimitDecision {
                permitted: false,
                retry_after,
                limit: 1,
                remaining: 0,
                reset_after: retry_after,
            },
            calls: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl RateLimitStore for DecisionStore {
    fn consume<'a>(&'a self, _input: RateLimitConsumeInput) -> RateLimitFuture<'a> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.decision.clone())
        })
    }
}

#[test]
fn hash_rate_limit_scope_is_stable_and_distinct() -> Result<(), Box<dyn std::error::Error>> {
    let secret = "secret-a-at-least-32-chars-long!!";
    let first = hash_rate_limit_scope(secret, "challenge-token-a")?;
    let second = hash_rate_limit_scope(secret, "challenge-token-a")?;
    let other = hash_rate_limit_scope(secret, "challenge-token-b")?;
    assert_eq!(first, second);
    assert_ne!(first, other);
    assert!(!first.contains("challenge-token"));
    Ok(())
}

#[test]
fn create_rate_limit_key_with_suffix_extends_ip_path_key() {
    let base = create_rate_limit_key("127.0.0.1", "/passkey/verify-authentication");
    let scoped = create_rate_limit_key_with_suffix(
        "127.0.0.1",
        "/passkey/verify-authentication",
        "challenge:deadbeef",
    );
    assert_eq!(scoped, format!("{base}|challenge:deadbeef"));
}

#[tokio::test]
async fn consume_scoped_rate_limit_uses_independent_buckets_per_scope(
) -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        rate_limit: RateLimitOptions {
            enabled: Some(true),
            window: 10,
            max: 100,
            ..RateLimitOptions::default()
        },
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let path = "/passkey/verify-authentication";
    let rule = RateLimitRule { window: 60, max: 2 };
    let request = || {
        Request::builder()
            .method(Method::POST)
            .uri("http://localhost:3000/api/auth/passkey/verify-authentication")
            .body(Vec::new())
    };

    for _ in 0..2 {
        assert!(consume_scoped_rate_limit(
            &context,
            &request()?,
            path,
            "challenge-a",
            rule.clone()
        )
        .await?
        .is_none());
    }
    assert!(
        consume_scoped_rate_limit(&context, &request()?, path, "challenge-a", rule.clone())
            .await?
            .is_some()
    );
    assert!(
        consume_scoped_rate_limit(&context, &request()?, path, "challenge-b", rule)
            .await?
            .is_none()
    );
    Ok(())
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
