use super::*;

#[tokio::test]
async fn error_route_renders_sanitized_html() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let router = router(adapter)?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/error?error=%3Cscript%3E&error_description=%3Cb%3Ebad%3C%2Fb%3E",
            "",
            None,
        )?)
        .await?;
    let body = std::str::from_utf8(response.body())?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/html; charset=utf-8")
    );
    assert!(body.contains("UNKNOWN"));
    assert!(body.contains("&lt;b&gt;bad&lt;/b&gt;"));
    assert!(!body.contains("<script>"));
    Ok(())
}
