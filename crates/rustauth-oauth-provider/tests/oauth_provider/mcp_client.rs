use super::common::*;

use http::Response;
use rustauth_oauth_provider::mcp::client::{McpAuthClient, McpAuthClientOptions};

#[test]
fn mcp_client_helpers_build_standard_responses() -> Result<(), Box<dyn std::error::Error>> {
    let client = McpAuthClient::new(McpAuthClientOptions {
        auth_url: "https://auth.example/api/auth/".to_owned(),
        resource: Some("https://resource.example".to_owned()),
        ..McpAuthClientOptions::default()
    });

    assert_eq!(
        client.www_authenticate(),
        "Bearer resource_metadata=\"https://resource.example/.well-known/oauth-protected-resource\""
    );

    let unauthorized = client.unauthorized_response()?;
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        unauthorized.headers()[header::WWW_AUTHENTICATE],
        client.www_authenticate()
    );
    assert_eq!(
        unauthorized.headers()["Access-Control-Expose-Headers"],
        "WWW-Authenticate"
    );
    assert_eq!(
        json_body(unauthorized)?["error"]["message"],
        "Unauthorized: Authentication required"
    );

    let cors = client.cors_preflight_response()?;
    assert_eq!(cors.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        cors.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        "https://auth.example"
    );

    let metadata = client.protected_resource_metadata("https://server.example/mcp");
    assert_eq!(metadata["resource"], "https://resource.example");
    assert_eq!(
        metadata["authorization_servers"],
        json!(["https://auth.example/api/auth"])
    );
    Ok(())
}

#[tokio::test]
async fn mcp_client_handler_short_circuits_options_and_missing_bearer(
) -> Result<(), Box<dyn std::error::Error>> {
    let client = McpAuthClient::new(McpAuthClientOptions {
        auth_url: "https://auth.example/api/auth".to_owned(),
        ..McpAuthClientOptions::default()
    });

    let options = client
        .handle_request(
            Request::builder()
                .method(Method::OPTIONS)
                .uri("https://server.example/mcp")
                .body(Vec::new())?,
            |_request, _session| async { Response::builder().status(StatusCode::OK).body(vec![]) },
        )
        .await?;
    assert_eq!(options.status(), StatusCode::NO_CONTENT);

    let missing = client
        .handle_request(
            Request::builder()
                .method(Method::POST)
                .uri("https://server.example/mcp")
                .body(Vec::new())?,
            |_request, _session| async { Response::builder().status(StatusCode::OK).body(vec![]) },
        )
        .await?;
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}
