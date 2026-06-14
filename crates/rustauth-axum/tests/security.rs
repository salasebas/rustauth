mod common;

use axum::extract::ConnectInfo;
use axum::http::{header, Method, StatusCode};
use common::*;
use rustauth::db::MemoryAdapter;
use rustauth::options::{AdvancedOptions, IpAddressOptions, RateLimitRule, RustAuthOptions};
use rustauth_axum::{RustAuthAxumExt, RustAuthAxumOptions};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tower::ServiceExt;

#[tokio::test]
async fn csrf_origin_checks_are_preserved_over_axum() -> Result<(), Box<dyn std::error::Error>> {
    let app = auth_with_adapter(
        MemoryAdapter::new(),
        RustAuthOptions::default().base_url("https://app.example.com/api/auth"),
    )
    .await?
    .mount_at_base_path(RustAuthAxumOptions::default())?;

    let rejected = app
        .clone()
        .oneshot(
            json_request(
                Method::POST,
                "/api/auth/sign-in/email",
                r#"{"email":"ada@example.com","password":"secret123"}"#,
                Some("better-auth.session_token=signed"),
            )?
            .with_header(header::ORIGIN, "https://evil.example.com")?,
        )
        .await?;
    assert_eq!(rejected.status(), StatusCode::FORBIDDEN);
    let rejected_body = body_json(rejected).await?;
    assert_eq!(rejected_body["code"], "INVALID_ORIGIN");

    let allowed = app
        .oneshot(
            json_request(
                Method::POST,
                "/api/auth/sign-in/email",
                r#"{"email":"ada@example.com","password":"secret123"}"#,
                Some("better-auth.session_token=signed"),
            )?
            .with_header(header::ORIGIN, "https://app.example.com")?,
        )
        .await?;
    assert_ne!(allowed.status(), StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn core_rate_limit_runs_without_axum_middleware() -> Result<(), Box<dyn std::error::Error>> {
    let app = auth_with_adapter(
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
    .await?
    .mount_at_base_path(RustAuthAxumOptions::default())?;

    for attempt in 0..2 {
        let response = app
            .clone()
            .oneshot(request(Method::GET, "/api/auth/ok", "", None)?)
            .await?;
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
async fn axum_rate_limit_uses_connect_info_without_ip_headers(
) -> Result<(), Box<dyn std::error::Error>> {
    let app = auth_with_adapter(
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
    .await?
    .mount_at_base_path(RustAuthAxumOptions::default())?;

    let first = app
        .clone()
        .oneshot(request_with_connect_info(
            Method::GET,
            "/api/auth/ok",
            "192.0.2.50",
        )?)
        .await?;
    assert_eq!(first.status(), StatusCode::OK);

    let second = app
        .oneshot(request_with_connect_info(
            Method::GET,
            "/api/auth/ok",
            "192.0.2.50",
        )?)
        .await?;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);

    Ok(())
}

#[tokio::test]
async fn axum_rate_limit_ignores_spoofed_forwarded_for_by_default(
) -> Result<(), Box<dyn std::error::Error>> {
    let app = auth_with_adapter(
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
    .await?
    .mount_at_base_path(RustAuthAxumOptions::default())?;

    let first = app
        .clone()
        .oneshot(request_with_connect_info_and_forwarded_for(
            Method::GET,
            "/api/auth/ok",
            "192.0.2.60",
            "203.0.113.60",
        )?)
        .await?;
    assert_eq!(first.status(), StatusCode::OK);

    let second = app
        .oneshot(request_with_connect_info_and_forwarded_for(
            Method::GET,
            "/api/auth/ok",
            "192.0.2.60",
            "203.0.113.61",
        )?)
        .await?;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);

    Ok(())
}

#[tokio::test]
async fn axum_rate_limit_uses_forwarded_for_when_proxy_headers_are_configured(
) -> Result<(), Box<dyn std::error::Error>> {
    let app = auth_with_adapter(
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
    .await?
    .mount_at_base_path(RustAuthAxumOptions::default())?;

    let first = app
        .clone()
        .oneshot(request_with_connect_info_and_forwarded_for(
            Method::GET,
            "/api/auth/ok",
            "192.0.2.70",
            "203.0.113.70",
        )?)
        .await?;
    assert_eq!(first.status(), StatusCode::OK);

    let second = app
        .oneshot(request_with_connect_info_and_forwarded_for(
            Method::GET,
            "/api/auth/ok",
            "192.0.2.71",
            "203.0.113.70",
        )?)
        .await?;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);

    Ok(())
}

#[tokio::test]
async fn axum_connect_info_ip_can_be_disabled() -> Result<(), Box<dyn std::error::Error>> {
    let app = auth_with_adapter(
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
    .await?
    .mount_at_base_path(RustAuthAxumOptions::new().use_connect_info_for_ip(false))?;

    // ConnectInfo is present but ignored; without a trusted IP header production
    // rate limiting fails closed instead of silently bypassing the limit.
    let response = app
        .clone()
        .oneshot(request_with_connect_info(
            Method::GET,
            "/api/auth/ok",
            "192.0.2.80",
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

    Ok(())
}

fn request_with_connect_info(
    method: Method,
    path: &str,
    client_ip: &str,
) -> Result<axum::http::Request<axum::body::Body>, Box<dyn std::error::Error>> {
    let mut request = request(method, path, "", None)?;
    insert_connect_info(&mut request, client_ip)?;
    Ok(request)
}

fn request_with_connect_info_and_forwarded_for(
    method: Method,
    path: &str,
    client_ip: &str,
    forwarded_for: &'static str,
) -> Result<axum::http::Request<axum::body::Body>, Box<dyn std::error::Error>> {
    let mut request = request(method, path, "", None)?.with_header(
        header::HeaderName::from_static("x-forwarded-for"),
        forwarded_for,
    )?;
    insert_connect_info(&mut request, client_ip)?;
    Ok(request)
}

fn insert_connect_info(
    request: &mut axum::http::Request<axum::body::Body>,
    client_ip: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let ip = IpAddr::V4(client_ip.parse::<Ipv4Addr>()?);
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(ip, 12345)));
    Ok(())
}
