mod common;

use std::sync::Arc;

use actix_web::http::{header, Method, StatusCode};
use actix_web::test;
use common::*;
use rustauth::RustAuth;
use rustauth_actix_web::RustAuthActixWebOptions;

#[tokio::test]
async fn borrowed_handle_preserves_response_status_headers_body_and_query(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(
        RustAuth::builder()
            .secret(SECRET)
            .async_endpoint(response_contract_endpoint("/contract"))
            .build()
            .await?,
    );
    let app = handle_app!(auth, RustAuthActixWebOptions::default());

    let response = test::call_service(
        &app,
        test_request(Method::GET, "/api/auth/contract?next=%2Fhome", "", None).to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(body_text(response).await?, "query=next=%2Fhome");
    Ok(())
}

#[tokio::test]
async fn actix_adapter_preserves_duplicate_response_headers(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(
        RustAuth::builder()
            .secret(SECRET)
            .async_endpoint(response_contract_endpoint("/contract"))
            .build()
            .await?,
    );
    let app = mounted_app!(auth, RustAuthActixWebOptions::default());

    let response = test::call_service(
        &app,
        test_request(Method::GET, "/api/auth/contract", "", None).to_request(),
    )
    .await;

    let cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .map(|value| value.to_str())
        .collect::<Result<Vec<_>, _>>()?;
    let test_headers = response
        .headers()
        .get_all("x-rustauth-test")
        .map(|value| value.to_str())
        .collect::<Result<Vec<_>, _>>()?;

    assert_eq!(cookies.len(), 2);
    assert!(cookies.iter().any(|value| value.starts_with("a=1;")));
    assert!(cookies.iter().any(|value| value.starts_with("b=2;")));
    assert_eq!(test_headers, vec!["one", "two"]);
    Ok(())
}

#[tokio::test]
async fn actix_adapter_preserves_empty_response_bodies() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(
        RustAuth::builder()
            .secret(SECRET)
            .async_endpoint(empty_response_endpoint("/empty"))
            .build()
            .await?,
    );
    let app = mounted_app!(auth, RustAuthActixWebOptions::default());

    let response = test::call_service(
        &app,
        test_request(Method::GET, "/api/auth/empty", "", None).to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(body_text(response).await?, "");
    Ok(())
}
