mod common;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use axum::extract::ConnectInfo;
use axum::http::{header, Method, StatusCode};
use common::*;
use rustauth::auth::oauth::OAuthBaseUrlOverride;
use rustauth::db::MemoryAdapter;
use rustauth::error::RustAuthError;
use rustauth::options::{RateLimitRule, RustAuthOptions, TrustedOriginOptions};
use rustauth::plugin::{AuthPlugin, PluginRequestAction};
use rustauth::rate_limit::RequestClientIp;
use rustauth::RustAuth;
use rustauth_axum::{handle, RustAuthAxumExt, RustAuthAxumOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tower::ServiceExt;

#[tokio::test]
async fn routes_accepts_stripped_paths_on_unmounted_router(
) -> Result<(), Box<dyn std::error::Error>> {
    let app = auth_with_options(RustAuthOptions::default())
        .await?
        .mount_routes(RustAuthAxumOptions::default())?;

    let response = app.oneshot(request(Method::GET, "/ok", "", None)?).await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_text(response).await?, "OK");
    Ok(())
}

#[tokio::test]
async fn disabled_paths_are_enforced_through_axum_router() -> Result<(), Box<dyn std::error::Error>>
{
    let app = auth_with_options(
        RustAuthOptions::default()
            .base_url("http://localhost:3000/api/auth")
            .disabled_path("/sign-in/email"),
    )
    .await?
    .mount_at_base_path(RustAuthAxumOptions::default())?;

    let response = app
        .oneshot(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn on_request_plugin_can_short_circuit_before_core_handler(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin = AuthPlugin::new("request-guard").with_on_request(|_context, _request| {
        axum::http::Response::builder()
            .status(StatusCode::ACCEPTED)
            .body(b"PLUGIN SHORT-CIRCUIT".to_vec())
            .map(PluginRequestAction::Respond)
            .map_err(|error: axum::http::Error| RustAuthError::Serialization {
                context: "building plugin short-circuit response",
                message: error.to_string(),
            })
    });
    let app = auth_with_options(
        RustAuthOptions::default()
            .base_url("http://localhost:3000/api/auth")
            .plugin(plugin),
    )
    .await?
    .mount_at_base_path(RustAuthAxumOptions::default())?;

    let response = app
        .oneshot(request(Method::GET, "/api/auth/ok", "", None)?)
        .await?;

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
                .insert(RequestExtensionMarker("plugin"));
            Ok(PluginRequestAction::Continue(request))
        })
        .with_endpoint(custom_endpoint("/plugin/request-ext"));
    let app = auth_with_options(
        RustAuthOptions::default()
            .base_url("http://localhost:3000/api/auth")
            .plugin(plugin),
    )
    .await?
    .mount_at_base_path(RustAuthAxumOptions::default())?;

    let response = app
        .oneshot(request(
            Method::GET,
            "/api/auth/plugin/request-ext",
            "",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_text(response).await?, "CUSTOM");
    Ok(())
}

#[tokio::test]
async fn inbound_request_extensions_reach_core_handler() -> Result<(), Box<dyn std::error::Error>> {
    let auth = RustAuth::builder()
        .secret(SECRET)
        .async_endpoint(request_extension_endpoint("/request-ext"))
        .build()
        .await?;

    let mut request = request(Method::GET, "/api/auth/request-ext", "", None)?;
    request
        .extensions_mut()
        .insert(RequestExtensionMarker("inbound"));

    let response = handle(&auth, RustAuthAxumOptions::default(), request).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_text(response).await?, "request=inbound");
    Ok(())
}

#[tokio::test]
async fn handle_preserves_response_contract() -> Result<(), Box<dyn std::error::Error>> {
    let auth = RustAuth::builder()
        .secret(SECRET)
        .async_endpoint(response_contract_endpoint("/contract"))
        .build()
        .await?;

    let response = rustauth_axum::handle(
        &auth,
        RustAuthAxumOptions::default().body_limit(1024),
        request(Method::GET, "/api/auth/contract", "", None)?,
    )
    .await;

    assert_eq!(response.status(), StatusCode::CREATED);
    let cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .count();
    assert_eq!(cookies, 2);
    Ok(())
}

#[tokio::test]
async fn pre_set_request_client_ip_is_not_overwritten_by_connect_info(
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

    let pinned = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
    let mut first = request(Method::GET, "/api/auth/ok", "", None)?;
    first.extensions_mut().insert(RequestClientIp(pinned));
    insert_connect_info(&mut first, "192.0.2.90")?;

    let mut second = request(Method::GET, "/api/auth/ok", "", None)?;
    second.extensions_mut().insert(RequestClientIp(pinned));
    insert_connect_info(&mut second, "192.0.2.91")?;

    assert_eq!(app.clone().oneshot(first).await?.status(), StatusCode::OK);
    assert_eq!(
        app.oneshot(second).await?.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    Ok(())
}

#[tokio::test]
async fn base_url_inference_skips_when_oauth_override_is_present(
) -> Result<(), Box<dyn std::error::Error>> {
    let app = auth_with_adapter(
        MemoryAdapter::new(),
        RustAuthOptions::default()
            .trusted_origins(TrustedOriginOptions::Static(vec![
                "https://configured.example.com".to_owned(),
            ]))
            .social_provider(FakeProvider::new("github")),
    )
    .await?
    .mount_at_base_path(RustAuthAxumOptions::new().infer_base_url_from_request(true))?;

    let mut request = json_request(
        Method::POST,
        "/api/auth/sign-in/social",
        r#"{"provider":"github","callbackURL":"/dashboard"}"#,
        None,
    )?;
    request.extensions_mut().insert(OAuthBaseUrlOverride(
        "https://configured.example.com/api/auth".to_owned(),
    ));
    request
        .extensions_mut()
        .insert(rustauth::api::RequestBaseUrl(
            "https://configured.example.com/api/auth".to_owned(),
        ));
    request.headers_mut().insert(
        header::HOST,
        header::HeaderValue::from_static("evil.example.com"),
    );

    let response = app.oneshot(request).await?;
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
    let app = auth_with_adapter(
        MemoryAdapter::new(),
        RustAuthOptions::default()
            .trusted_origins(TrustedOriginOptions::Static(vec![
                "https://app.example.com".to_owned(),
            ]))
            .social_provider(FakeProvider::new("github")),
    )
    .await?
    .mount_at_base_path(RustAuthAxumOptions::new().infer_base_url_from_request(true))?;

    let response = app
        .oneshot(json_request(
            Method::POST,
            "https://app.example.com/api/auth/sign-in/social",
            r#"{"provider":"github","callbackURL":"/dashboard"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await?;
    let auth_url = body["url"].as_str().ok_or("missing auth url")?;
    assert_eq!(
        query_value(auth_url, "redirect_uri"),
        Some("https://app.example.com/api/auth/callback/github".to_owned())
    );
    Ok(())
}

#[tokio::test]
async fn tcp_listener_connect_info_enables_rate_limit_without_manual_injection(
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

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let make_service = app.into_make_service_with_connect_info::<SocketAddr>();
    let server = tokio::spawn(async move {
        let result = axum::serve(listener, make_service).await;
        assert!(result.is_ok(), "test server should run: {result:?}");
    });
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
