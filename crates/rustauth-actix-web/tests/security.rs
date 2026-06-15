mod common;

use std::sync::Arc;

use actix_web::http::{header, Method, StatusCode};
use actix_web::test;
use common::*;
use rustauth::db::MemoryAdapter;
use rustauth::options::{AdvancedOptions, IpAddressOptions, RateLimitRule, RustAuthOptions};
use rustauth_actix_web::RustAuthActixWebOptions;

#[tokio::test]
async fn csrf_origin_checks_are_preserved_over_actix_web() -> Result<(), Box<dyn std::error::Error>>
{
    let auth = Arc::new(
        auth_with_adapter(
            MemoryAdapter::new(),
            RustAuthOptions::default().base_url("https://app.example.com/api/auth"),
        )
        .await?,
    );
    let app = mounted_app!(auth, RustAuthActixWebOptions::default());

    let rejected = test::call_service(
        &app,
        json_test_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"secret123"}"#,
            Some("better-auth.session_token=signed"),
        )
        .insert_header((header::ORIGIN, "https://evil.example.com"))
        .to_request(),
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::FORBIDDEN);
    let rejected_body = body_json(rejected).await?;
    assert_eq!(rejected_body["code"], "INVALID_ORIGIN");

    let allowed = test::call_service(
        &app,
        json_test_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"secret123"}"#,
            Some("better-auth.session_token=signed"),
        )
        .insert_header((header::ORIGIN, "https://app.example.com"))
        .to_request(),
    )
    .await;
    assert_ne!(allowed.status(), StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn core_rate_limit_runs_without_actix_middleware() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(
        auth_with_adapter(
            MemoryAdapter::new(),
            RustAuthOptions::default().rate_limit(
                rustauth::options::RateLimitOptions::new()
                    .enabled(true)
                    .custom_rule(
                        "/ok",
                        RateLimitRule {
                            window: time::Duration::seconds(60),
                            max: 1,
                        },
                    ),
            ),
        )
        .await?,
    );
    let app = mounted_app!(auth, RustAuthActixWebOptions::default());

    for attempt in 0..2 {
        let response = test::call_service(
            &app,
            test_request(Method::GET, "/api/auth/ok", "", None).to_request(),
        )
        .await;
        if attempt == 0 {
            assert_eq!(response.status(), StatusCode::OK);
        } else {
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            assert!(response.headers().contains_key("X-Retry-After"));
        }
    }
    Ok(())
}

#[tokio::test]
async fn actix_rate_limit_uses_peer_addr_without_ip_headers(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(
        auth_with_adapter(
            MemoryAdapter::new(),
            RustAuthOptions::default().production(true).rate_limit(
                rustauth::options::RateLimitOptions::new()
                    .enabled(true)
                    .custom_rule(
                        "/ok",
                        RateLimitRule {
                            window: time::Duration::seconds(60),
                            max: 1,
                        },
                    ),
            ),
        )
        .await?,
    );
    let app = mounted_app!(auth, RustAuthActixWebOptions::default());

    let first = test::call_service(
        &app,
        test_request_with_peer_addr(Method::GET, "/api/auth/ok", "", None, "192.0.2.50")?
            .to_request(),
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);

    let second = test::call_service(
        &app,
        test_request_with_peer_addr(Method::GET, "/api/auth/ok", "", None, "192.0.2.50")?
            .to_request(),
    )
    .await;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);

    Ok(())
}

#[tokio::test]
async fn actix_rate_limit_ignores_spoofed_forwarded_for_by_default(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(
        auth_with_adapter(
            MemoryAdapter::new(),
            RustAuthOptions::default().production(true).rate_limit(
                rustauth::options::RateLimitOptions::new()
                    .enabled(true)
                    .custom_rule(
                        "/ok",
                        RateLimitRule {
                            window: time::Duration::seconds(60),
                            max: 1,
                        },
                    ),
            ),
        )
        .await?,
    );
    let app = mounted_app!(auth, RustAuthActixWebOptions::default());

    let first = test::call_service(
        &app,
        test_request_with_peer_addr_and_forwarded_for(
            Method::GET,
            "/api/auth/ok",
            "",
            None,
            "192.0.2.60",
            "203.0.113.60",
        )?
        .to_request(),
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);

    let second = test::call_service(
        &app,
        test_request_with_peer_addr_and_forwarded_for(
            Method::GET,
            "/api/auth/ok",
            "",
            None,
            "192.0.2.60",
            "203.0.113.61",
        )?
        .to_request(),
    )
    .await;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);

    Ok(())
}

#[tokio::test]
async fn actix_rate_limit_uses_forwarded_for_when_proxy_headers_are_configured(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(
        auth_with_adapter(
            MemoryAdapter::new(),
            RustAuthOptions::default()
                .production(true)
                .advanced(
                    AdvancedOptions::new()
                        .ip_address(IpAddressOptions::new().headers(["x-forwarded-for"])),
                )
                .rate_limit(
                    rustauth::options::RateLimitOptions::new()
                        .enabled(true)
                        .custom_rule(
                            "/ok",
                            RateLimitRule {
                                window: time::Duration::seconds(60),
                                max: 1,
                            },
                        ),
                ),
        )
        .await?,
    );
    let app = mounted_app!(auth, RustAuthActixWebOptions::default());

    let first = test::call_service(
        &app,
        test_request_with_peer_addr_and_forwarded_for(
            Method::GET,
            "/api/auth/ok",
            "",
            None,
            "192.0.2.70",
            "203.0.113.70",
        )?
        .to_request(),
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);

    let second = test::call_service(
        &app,
        test_request_with_peer_addr_and_forwarded_for(
            Method::GET,
            "/api/auth/ok",
            "",
            None,
            "192.0.2.71",
            "203.0.113.70",
        )?
        .to_request(),
    )
    .await;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);

    Ok(())
}

#[tokio::test]
async fn actix_peer_addr_ip_can_be_disabled() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(
        auth_with_adapter(
            MemoryAdapter::new(),
            RustAuthOptions::default().production(true).rate_limit(
                rustauth::options::RateLimitOptions::new()
                    .enabled(true)
                    .custom_rule(
                        "/ok",
                        RateLimitRule {
                            window: time::Duration::seconds(60),
                            max: 1,
                        },
                    ),
            ),
        )
        .await?,
    );
    let app = mounted_app!(
        auth,
        RustAuthActixWebOptions::new().use_peer_addr_for_ip(false),
    );

    // peer_addr is present but ignored; without a trusted IP header production
    // rate limiting fails closed instead of silently bypassing the limit.
    let response = test::call_service(
        &app,
        test_request_with_peer_addr(Method::GET, "/api/auth/ok", "", None, "192.0.2.80")?
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

    Ok(())
}
