mod common;

use axum::http::{header, Method, StatusCode, Version};
use common::*;
use rustauth::RustAuth;
use rustauth_axum::{handle, RustAuthAxumExt, RustAuthAxumOptions};
use tower::ServiceExt;

#[tokio::test]
async fn borrowed_handle_preserves_response_status_version_headers_body_and_query(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = RustAuth::builder()
        .secret(SECRET)
        .async_endpoint(response_contract_endpoint("/contract"))
        .build()
        .await?;

    let response = handle(
        &auth,
        RustAuthAxumOptions::default(),
        request(Method::GET, "/api/auth/contract?next=%2Fhome", "", None)?,
    )
    .await;

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.version(), Version::HTTP_2);
    assert_eq!(body_text(response).await?, "query=next=%2Fhome");
    Ok(())
}

#[tokio::test]
async fn axum_adapter_preserves_duplicate_response_headers(
) -> Result<(), Box<dyn std::error::Error>> {
    let app = RustAuth::builder()
        .secret(SECRET)
        .async_endpoint(response_contract_endpoint("/contract"))
        .build()
        .await?
        .mount_at_base_path(RustAuthAxumOptions::default())?;

    let response = app
        .oneshot(request(Method::GET, "/api/auth/contract", "", None)?)
        .await?;

    let cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str())
        .collect::<Result<Vec<_>, _>>()?;
    let test_headers = response
        .headers()
        .get_all("x-rustauth-test")
        .iter()
        .map(|value| value.to_str())
        .collect::<Result<Vec<_>, _>>()?;

    assert_eq!(cookies.len(), 2);
    assert!(cookies.iter().any(|value| value.starts_with("a=1;")));
    assert!(cookies.iter().any(|value| value.starts_with("b=2;")));
    assert_eq!(test_headers, vec!["one", "two"]);
    Ok(())
}

#[tokio::test]
async fn axum_adapter_preserves_response_extensions() -> Result<(), Box<dyn std::error::Error>> {
    let app = RustAuth::builder()
        .secret(SECRET)
        .async_endpoint(response_contract_endpoint("/contract"))
        .build()
        .await?
        .mount_at_base_path(RustAuthAxumOptions::default())?;

    let response = app
        .oneshot(request(Method::GET, "/api/auth/contract", "", None)?)
        .await?;

    assert_eq!(
        response.extensions().get::<ResponseExtensionMarker>(),
        Some(&ResponseExtensionMarker("response-contract"))
    );
    Ok(())
}

#[tokio::test]
async fn axum_adapter_preserves_empty_response_bodies() -> Result<(), Box<dyn std::error::Error>> {
    let app = RustAuth::builder()
        .secret(SECRET)
        .async_endpoint(empty_response_endpoint("/empty"))
        .build()
        .await?
        .mount_at_base_path(RustAuthAxumOptions::default())?;

    let response = app
        .oneshot(request(Method::GET, "/api/auth/empty", "", None)?)
        .await?;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(body_text(response).await?, "");
    Ok(())
}
