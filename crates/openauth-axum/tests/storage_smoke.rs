mod common;

use axum::http::{Method, StatusCode};
use common::*;
use openauth::{MemoryAdapter, OpenAuthOptions};
use openauth_axum::router;
use tower::ServiceExt;

#[tokio::test]
async fn memory_adapter_smoke_flow_runs_through_axum() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    let app = router(auth_with_adapter(
        adapter.clone(),
        OpenAuthOptions::default().base_url("http://localhost:3000/api/auth"),
    )?)?;

    let response = app
        .oneshot(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(adapter.len("user").await, 1);
    assert_eq!(adapter.len("session").await, 1);
    Ok(())
}
