use http::StatusCode;
use openauth_scim::errors::{ScimError, SCIM_ERROR_SCHEMA};

#[test]
fn scim_error_serializes_rfc7644_body() {
    let error = ScimError::new(StatusCode::BAD_REQUEST, "Invalid SCIM filter")
        .with_scim_type("invalidFilter");
    let body = error.body();

    assert_eq!(body.schemas, vec![SCIM_ERROR_SCHEMA.to_owned()]);
    assert_eq!(body.status, "400");
    assert_eq!(body.detail.as_deref(), Some("Invalid SCIM filter"));
    assert_eq!(body.scim_type.as_deref(), Some("invalidFilter"));
}

#[test]
fn scim_error_response_uses_scim_json_content_type() -> Result<(), Box<dyn std::error::Error>> {
    let response = ScimError::unauthorized("SCIM token is required").into_response()?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get(http::header::CONTENT_TYPE),
        Some(&http::HeaderValue::from_static("application/scim+json"))
    );

    Ok(())
}
