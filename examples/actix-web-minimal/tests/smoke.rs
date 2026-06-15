use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use actix_web::http::{header, Method, StatusCode};
use actix_web::test::{self, TestRequest};
use actix_web::App;
use rustauth_actix_web::{RustAuthActixWebExt, RustAuthActixWebOptions};

const LOOPBACK_PEER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);

fn loopback_request(request: TestRequest) -> actix_http::Request {
    request.peer_addr(LOOPBACK_PEER).to_request()
}

macro_rules! mounted_app {
    () => {{
        let auth = rustauth_example_actix_web::build_auth()
            .await
            .expect("valid example auth config");
        let scope = auth
            .mount_at_base_path(RustAuthActixWebOptions::default())
            .expect("valid RustAuth Actix mount");
        test::init_service(App::new().service(scope)).await
    }};
}

#[tokio::test]
async fn ok_endpoint_responds() -> Result<(), Box<dyn std::error::Error>> {
    let app = mounted_app!();

    let response = test::call_service(
        &app,
        loopback_request(test::TestRequest::get().uri("/api/auth/ok")),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn email_sign_up_and_session_work() -> Result<(), Box<dyn std::error::Error>> {
    let app = mounted_app!();

    let sign_up = test::call_service(
        &app,
        loopback_request(
            test::TestRequest::post()
                .uri("/api/auth/sign-up/email")
                .insert_header((header::CONTENT_TYPE, "application/json"))
                .set_payload(
                    r#"{"name":"Test User","email":"actix@example.com","password":"password123456"}"#,
                ),
        ),
    )
    .await;
    assert_eq!(sign_up.status(), StatusCode::OK);

    let cookie = sign_up
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .ok_or("missing sign-up cookie")?;

    let get_session = test::call_service(
        &app,
        loopback_request(
            test::TestRequest::get()
                .uri("/api/auth/get-session")
                .insert_header((header::COOKIE, cookie)),
        ),
    )
    .await;
    assert_eq!(get_session.status(), StatusCode::OK);

    let body = test::read_body(get_session).await;
    let json: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(json["user"]["email"], "actix@example.com");

    let sign_in = test::call_service(
        &app,
        loopback_request(
            test::TestRequest::with_uri("/api/auth/sign-in/email")
                .method(Method::POST)
                .insert_header((header::CONTENT_TYPE, "application/json"))
                .set_payload(r#"{"email":"actix@example.com","password":"password123456"}"#),
        ),
    )
    .await;
    assert_eq!(sign_in.status(), StatusCode::OK);
    Ok(())
}
