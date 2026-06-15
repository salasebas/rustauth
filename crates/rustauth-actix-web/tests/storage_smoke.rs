mod common;

use std::sync::Arc;

use actix_web::http::{Method, StatusCode};
use actix_web::test;
use common::*;
use rustauth::db::MemoryAdapter;
use rustauth::options::RustAuthOptions;
use rustauth_actix_web::RustAuthActixWebOptions;

#[tokio::test]
async fn memory_adapter_smoke_flow_runs_through_actix_web() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = MemoryAdapter::new();
    let auth = Arc::new(
        auth_with_adapter(
            adapter.clone(),
            RustAuthOptions::default().base_url("http://localhost:3000/api/auth"),
        )
        .await?,
    );
    let app = mounted_app!(auth, RustAuthActixWebOptions::default());

    let response = test::call_service(
        &app,
        json_test_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )
        .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(adapter.len("user").await, 1);
    assert_eq!(adapter.len("session").await, 1);
    Ok(())
}
