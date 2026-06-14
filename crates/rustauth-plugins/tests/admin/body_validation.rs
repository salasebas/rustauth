use http::{header, Method, Request, StatusCode};

use super::{fixture, json_body, Fixture};

/// POST endpoints that now validate their request body before reaching the
/// handler. Each previously let malformed input surface as an internal handler
/// error instead of a structured 400/415 response (OPE-69).
const BODY_ENDPOINTS: &[&str] = &[
    "/admin/set-role",
    "/admin/list-user-sessions",
    "/admin/has-permission",
];

fn raw_request(
    path: &str,
    content_type: Option<&str>,
    body: &str,
) -> Result<Request<Vec<u8>>, Box<dyn std::error::Error>> {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(format!("http://localhost:3000/api/auth{path}"));
    if let Some(content_type) = content_type {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }
    Ok(builder.body(body.as_bytes().to_vec())?)
}

#[tokio::test]
async fn malformed_json_returns_structured_400() -> Result<(), Box<dyn std::error::Error>> {
    let Fixture { router, .. } = fixture()?;
    for path in BODY_ENDPOINTS {
        let response = router
            .handle_async(raw_request(path, Some("application/json"), "{not valid")?)
            .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
        assert_eq!(
            json_body(response)?["code"],
            "INVALID_REQUEST_BODY",
            "{path}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn missing_content_type_returns_415() -> Result<(), Box<dyn std::error::Error>> {
    let Fixture { router, .. } = fixture()?;
    for path in BODY_ENDPOINTS {
        let response = router.handle_async(raw_request(path, None, "{}")?).await?;
        assert_eq!(
            response.status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "{path}"
        );
        assert_eq!(
            json_body(response)?["code"],
            "UNSUPPORTED_MEDIA_TYPE",
            "{path}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn unsupported_content_type_returns_415() -> Result<(), Box<dyn std::error::Error>> {
    let Fixture { router, .. } = fixture()?;
    for path in BODY_ENDPOINTS {
        let response = router
            .handle_async(raw_request(path, Some("text/plain"), "userId=abc")?)
            .await?;
        assert_eq!(
            response.status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "{path}"
        );
        assert_eq!(
            json_body(response)?["code"],
            "UNSUPPORTED_MEDIA_TYPE",
            "{path}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn missing_required_field_returns_structured_400() -> Result<(), Box<dyn std::error::Error>> {
    let Fixture { router, .. } = fixture()?;

    // `userId` is required by the published schema for both endpoints.
    for (path, body) in [
        ("/admin/set-role", r#"{ "role": "admin" }"#),
        ("/admin/list-user-sessions", "{}"),
    ] {
        let response = router
            .handle_async(raw_request(path, Some("application/json"), body)?)
            .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
        assert_eq!(
            json_body(response)?["code"],
            "INVALID_REQUEST_BODY",
            "{path}"
        );
    }

    // has-permission keeps `permissions` optional at the schema layer (the
    // handler still rejects an empty set) so the legacy `permission` alias keeps
    // working; an absent permission set returns a structured 400, never a 500.
    let response = router
        .handle_async(raw_request(
            "/admin/has-permission",
            Some("application/json"),
            "{}",
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}
