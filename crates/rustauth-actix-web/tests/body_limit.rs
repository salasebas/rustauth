mod common;

use std::sync::Arc;

use actix_web::body::MessageBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::http::{Method, StatusCode};
use actix_web::middleware::{from_fn, Next};
use actix_web::test;
use actix_web::{App, Error};
use common::*;
use futures_util::StreamExt;
use rustauth::db::MemoryAdapter;
use rustauth::options::RustAuthOptions;
use rustauth_actix_web::{RustAuthActixWebExt, RustAuthActixWebOptions};

#[tokio::test]
async fn configurable_body_limit_rejects_oversized_requests(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(auth_with_options(RustAuthOptions::default()).await?);
    let app = mounted_app!(auth, RustAuthActixWebOptions::default().body_limit(8),);

    let response = test::call_service(
        &app,
        json_test_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com"}"#,
            None,
        )
        .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        response
            .headers()
            .get(actix_web::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    let body = body_json(response).await?;
    assert_eq!(body["code"], "PAYLOAD_TOO_LARGE");
    Ok(())
}

#[tokio::test]
async fn configurable_body_limit_allows_requests_within_limit(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(auth_with_options(RustAuthOptions::default()).await?);
    let app = mounted_app!(auth, RustAuthActixWebOptions::default().body_limit(1024),);

    let response = test::call_service(
        &app,
        json_test_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com"}"#,
            None,
        )
        .to_request(),
    )
    .await;

    assert_ne!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn body_consuming_middleware_before_auth_routes_returns_stable_json_error(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(auth_with_adapter(MemoryAdapter::new(), RustAuthOptions::default()).await?);
    let scope = auth.mount_at_base_path(RustAuthActixWebOptions::default())?;
    let app = test::init_service(
        App::new()
            .wrap(from_fn(drain_body_before_auth))
            .service(scope),
    )
    .await;

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

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = body_json(response).await?;
    assert_eq!(body["code"], "INVALID_REQUEST_BODY");
    Ok(())
}

async fn drain_body_before_auth(
    req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    let (http_req, mut payload) = req.into_parts();
    while payload.next().await.is_some() {}
    next.call(ServiceRequest::from_request(http_req)).await
}
