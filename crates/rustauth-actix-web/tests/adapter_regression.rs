mod common;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use actix_web::http::{header, Method, StatusCode};
use actix_web::test;
use actix_web::HttpMessage;
use actix_web::{App, HttpServer};
use common::*;
use rustauth::api::RequestBaseUrl;
use rustauth::auth::oauth::OAuthBaseUrlOverride;
use rustauth::db::MemoryAdapter;
use rustauth::error::RustAuthError;
use rustauth::options::{RateLimitRule, RustAuthOptions, TrustedOriginOptions};
use rustauth::plugin::{AuthPlugin, PluginRequestAction};
use rustauth::rate_limit::RequestClientIp;
use rustauth::RustAuth;
use rustauth_actix_web::{RustAuthActixWebExt, RustAuthActixWebOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::test]
async fn routes_accepts_stripped_paths_on_unmounted_router(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(auth_with_options(RustAuthOptions::default()).await?);
    let routes = auth.mount_routes(RustAuthActixWebOptions::default())?;
    let app = test::init_service(App::new().service(routes)).await;

    let response = test::call_service(
        &app,
        test_request(Method::GET, "/ok", "", None).to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_text(response).await?, "OK");
    Ok(())
}

#[tokio::test]
async fn disabled_paths_are_enforced_through_actix_router() -> Result<(), Box<dyn std::error::Error>>
{
    let auth = Arc::new(
        auth_with_options(
            RustAuthOptions::default()
                .base_url("http://localhost:3000/api/auth")
                .disabled_path("/sign-in/email"),
        )
        .await?,
    );
    let app = mounted_app!(auth, RustAuthActixWebOptions::default());

    let response = test::call_service(
        &app,
        json_test_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"secret123"}"#,
            None,
        )
        .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn on_request_plugin_can_short_circuit_before_core_handler(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin = AuthPlugin::new("request-guard").with_on_request(|_context, _request| {
        http::Response::builder()
            .status(http::StatusCode::ACCEPTED)
            .body(b"PLUGIN SHORT-CIRCUIT".to_vec())
            .map(PluginRequestAction::Respond)
            .map_err(|error| RustAuthError::Serialization {
                context: "building plugin short-circuit response",
                message: error.to_string(),
            })
    });
    let auth = Arc::new(
        auth_with_options(
            RustAuthOptions::default()
                .base_url("http://localhost:3000/api/auth")
                .plugin(plugin),
        )
        .await?,
    );
    let app = mounted_app!(auth, RustAuthActixWebOptions::default());

    let response = test::call_service(
        &app,
        test_request(Method::GET, "/api/auth/ok", "", None).to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(body_text(response).await?, "PLUGIN SHORT-CIRCUIT");
    Ok(())
}

#[tokio::test]
async fn on_request_plugin_runs_before_core_handler() -> Result<(), Box<dyn std::error::Error>> {
    let plugin = AuthPlugin::new("request-mutator")
        .with_on_request(|_context, mut request| {
            request
                .extensions_mut()
                .insert(rustauth::api::RequestBaseUrl(
                    "https://plugin.example.com/api/auth".to_owned(),
                ));
            Ok(PluginRequestAction::Continue(request))
        })
        .with_endpoint(custom_endpoint("/plugin/request-ext"));
    let auth = Arc::new(
        auth_with_options(
            RustAuthOptions::default()
                .base_url("http://localhost:3000/api/auth")
                .plugin(plugin),
        )
        .await?,
    );
    let app = mounted_app!(auth, RustAuthActixWebOptions::default());

    let response = test::call_service(
        &app,
        test_request(Method::GET, "/api/auth/plugin/request-ext", "", None).to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_text(response).await?, "CUSTOM");
    Ok(())
}

#[tokio::test]
async fn inbound_request_extensions_reach_core_handler() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(
        RustAuth::builder()
            .secret(SECRET)
            .async_endpoint(request_extension_endpoint("/request-ext"))
            .build()
            .await?,
    );
    let app = handle_app!(auth, RustAuthActixWebOptions::default());

    let request = test_request(Method::GET, "/api/auth/request-ext", "", None).to_request();
    request.extensions_mut().insert(RequestBaseUrl(
        "https://inbound.example.com/api/auth".to_owned(),
    ));

    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        body_text(response).await?,
        "request=https://inbound.example.com/api/auth"
    );
    Ok(())
}

#[tokio::test]
async fn handle_preserves_response_contract() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(
        RustAuth::builder()
            .secret(SECRET)
            .async_endpoint(response_contract_endpoint("/contract"))
            .build()
            .await?,
    );
    let app = handle_app!(auth, RustAuthActixWebOptions::default().body_limit(1024),);

    let response = test::call_service(
        &app,
        test_request(Method::GET, "/api/auth/contract", "", None).to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::CREATED);
    let cookies = response.headers().get_all(header::SET_COOKIE).count();
    assert_eq!(cookies, 2);
    Ok(())
}

#[tokio::test]
async fn pre_set_request_client_ip_is_not_overwritten_by_peer_addr(
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

    let pinned = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
    let first = test_request(Method::GET, "/api/auth/ok", "", None)
        .peer_addr(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 90)),
            12345,
        ))
        .to_request();
    first.extensions_mut().insert(RequestClientIp(pinned));

    let second = test_request(Method::GET, "/api/auth/ok", "", None)
        .peer_addr(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 91)),
            12345,
        ))
        .to_request();
    second.extensions_mut().insert(RequestClientIp(pinned));

    assert_eq!(
        test::call_service(&app, first).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        test::call_service(&app, second).await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    Ok(())
}

#[tokio::test]
async fn base_url_inference_skips_when_oauth_override_is_present(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(
        auth_with_adapter(
            MemoryAdapter::new(),
            RustAuthOptions::default()
                .trusted_origins(TrustedOriginOptions::Static(vec![
                    "https://configured.example.com".to_owned(),
                ]))
                .social_provider(FakeProvider::new("github")),
        )
        .await?,
    );
    let app = mounted_app!(
        auth,
        RustAuthActixWebOptions::new().infer_base_url_from_request(true),
    );

    let request = json_test_request(
        Method::POST,
        "/api/auth/sign-in/social",
        r#"{"provider":"github","callbackURL":"/dashboard"}"#,
        None,
    )
    .insert_header((header::HOST, "evil.example.com"))
    .to_request();
    request.extensions_mut().insert(OAuthBaseUrlOverride(
        "https://configured.example.com/api/auth".to_owned(),
    ));
    request
        .extensions_mut()
        .insert(rustauth::api::RequestBaseUrl(
            "https://configured.example.com/api/auth".to_owned(),
        ));

    let response = test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await?;
    let auth_url = body["url"].as_str().ok_or("missing auth url")?;
    assert_eq!(
        query_value(auth_url, "redirect_uri"),
        Some("https://configured.example.com/api/auth/callback/github".to_owned())
    );
    Ok(())
}

#[tokio::test]
async fn social_sign_in_infers_from_absolute_request_uri() -> Result<(), Box<dyn std::error::Error>>
{
    let auth = Arc::new(
        auth_with_adapter(
            MemoryAdapter::new(),
            RustAuthOptions::default()
                .trusted_origins(TrustedOriginOptions::Static(vec![
                    "https://app.example.com".to_owned(),
                ]))
                .social_provider(FakeProvider::new("github")),
        )
        .await?,
    );
    let app = mounted_app!(
        auth,
        RustAuthActixWebOptions::new().infer_base_url_from_request(true),
    );

    let response = test::call_service(
        &app,
        json_test_request(
            Method::POST,
            "https://app.example.com/api/auth/sign-in/social",
            r#"{"provider":"github","callbackURL":"/dashboard"}"#,
            None,
        )
        .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await?;
    let auth_url = body["url"].as_str().ok_or("missing auth url")?;
    assert_eq!(
        query_value(auth_url, "redirect_uri"),
        Some("https://app.example.com/api/auth/callback/github".to_owned())
    );
    Ok(())
}

#[allow(clippy::expect_used)]
#[tokio::test]
async fn tcp_listener_peer_addr_enables_rate_limit_without_manual_injection(
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

    let server = HttpServer::new(move || {
        App::new().service(
            auth.mount_at_base_path(RustAuthActixWebOptions::default())
                .expect("valid mount"),
        )
    })
    .bind(("127.0.0.1", 0))?;
    let addr = server.addrs()[0];
    let server = tokio::spawn(server.run());
    tokio::time::sleep(Duration::from_millis(50)).await;

    assert_eq!(raw_http_status(addr, "/api/auth/ok").await?, StatusCode::OK);
    assert_eq!(
        raw_http_status(addr, "/api/auth/ok").await?,
        StatusCode::TOO_MANY_REQUESTS
    );

    server.abort();
    Ok(())
}

async fn raw_http_status(
    addr: SocketAddr,
    path: &str,
) -> Result<StatusCode, Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(addr).await?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        addr.port()
    );
    stream.write_all(request.as_bytes()).await?;
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await?;
    let response = String::from_utf8_lossy(&buf[..n]);
    let status_line = response.lines().next().ok_or("missing status line")?;
    let code = status_line
        .split_whitespace()
        .nth(1)
        .ok_or("missing status code")?
        .parse::<u16>()?;
    Ok(StatusCode::from_u16(code)?)
}
