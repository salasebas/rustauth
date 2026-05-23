mod common;

use axum::http::{header, Method, StatusCode, Version};
use common::*;
use openauth::OpenAuth;
use openauth_axum::{handle_ref, router};
use tower::ServiceExt;

#[tokio::test]
async fn borrowed_handle_preserves_response_status_version_headers_body_and_query(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = OpenAuth::builder()
        .secret(SECRET)
        .async_endpoint(response_contract_endpoint("/contract"))
        .build()?;

    let response = handle_ref(
        &auth,
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
    let app = router(
        OpenAuth::builder()
            .secret(SECRET)
            .async_endpoint(response_contract_endpoint("/contract"))
            .build()?,
    )?;

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
        .get_all("x-openauth-test")
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
async fn axum_adapter_preserves_empty_response_bodies() -> Result<(), Box<dyn std::error::Error>> {
    let app = router(
        OpenAuth::builder()
            .secret(SECRET)
            .async_endpoint(empty_response_endpoint("/empty"))
            .build()?,
    )?;

    let response = app
        .oneshot(request(Method::GET, "/api/auth/empty", "", None)?)
        .await?;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(body_text(response).await?, "");
    Ok(())
}
