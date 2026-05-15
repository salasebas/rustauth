use std::sync::Arc;

use http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use openauth_core::api::{create_auth_endpoint, response, AuthEndpointOptions};
use openauth_core::cookies::sign_cookie_value;
use openauth_core::error::OpenAuthError;
use openauth_core::plugin::AuthPlugin;
use serde_json::Value;

use super::common::{
    assert_exposes_header, auth_token_header, bearer_request, exposed_auth_token_count,
    json_request, percent_encode_component, router, router_with_plugins, seed_user_and_session,
    sign_up_and_tokens, TestAdapter,
};

#[tokio::test]
async fn bearer_scheme_is_case_insensitive_and_allows_extra_whitespace(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let router = router(adapter, openauth_plugins::bearer::bearer())?;
    let tokens = sign_up_and_tokens(&router).await?;

    for scheme in ["bearer", "BEARER", "BeArEr", "Bearer "] {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("{scheme}  {}", tokens.signed))?,
        );
        let response = router
            .handle_async(json_request(
                Method::GET,
                "/api/auth/get-session",
                "",
                None,
                headers,
            )?)
            .await?;
        let body: Value = serde_json::from_slice(response.body())?;
        assert_eq!(body["session"]["token"], tokens.raw);
    }
    Ok(())
}

#[tokio::test]
async fn signed_bearer_token_may_be_percent_encoded() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let router = router(adapter, openauth_plugins::bearer::bearer())?;
    let tokens = sign_up_and_tokens(&router).await?;
    let encoded = percent_encode_component(&tokens.signed);

    let response = router
        .handle_async(bearer_request(
            Method::GET,
            "/api/auth/get-session",
            &encoded,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["session"]["token"], tokens.raw);
    Ok(())
}

#[tokio::test]
async fn invalid_bearer_token_does_not_override_valid_cookie(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let router = router(adapter, openauth_plugins::bearer::bearer())?;
    let tokens = sign_up_and_tokens(&router).await?;
    let cookie = format!("better-auth.session_token={}", tokens.signed);

    let response = router
        .handle_async(bearer_request(
            Method::GET,
            "/api/auth/get-session",
            "invalid.token",
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["session"]["token"], tokens.raw);
    Ok(())
}

#[tokio::test]
async fn missing_malformed_and_empty_bearer_headers_are_ignored(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    seed_user_and_session(&adapter).await;
    let router = router(adapter, openauth_plugins::bearer::bearer())?;

    for value in [None, Some("Basic token_1"), Some("Bearer    ")] {
        let mut headers = HeaderMap::new();
        if let Some(value) = value {
            headers.insert(header::AUTHORIZATION, HeaderValue::from_static(value));
        }
        let response = router
            .handle_async(json_request(
                Method::GET,
                "/api/auth/get-session",
                "",
                None,
                headers,
            )?)
            .await?;
        let body: Value = serde_json::from_slice(response.body())?;
        assert!(body.is_null());
    }
    Ok(())
}

#[tokio::test]
async fn existing_exposed_headers_are_preserved_when_auth_token_is_added(
) -> Result<(), Box<dyn std::error::Error>> {
    let response = issue_cookie_response("x-existing", false).await?;

    assert!(auth_token_header(&response).is_some());
    assert_exposes_header(&response, "x-existing")?;
    assert_exposes_header(&response, "set-auth-token")?;
    Ok(())
}

#[tokio::test]
async fn existing_auth_token_exposure_is_not_duplicated() -> Result<(), Box<dyn std::error::Error>>
{
    let response = issue_cookie_response("x-existing, set-auth-token", false).await?;

    assert_eq!(exposed_auth_token_count(&response)?, 1);
    Ok(())
}

#[tokio::test]
async fn session_cookie_is_found_when_multiple_set_cookie_headers_exist(
) -> Result<(), Box<dyn std::error::Error>> {
    let response = issue_cookie_response("", true).await?;

    assert_eq!(
        auth_token_header(&response).as_deref(),
        Some("issued.token")
    );
    Ok(())
}

async fn issue_cookie_response(
    exposed_headers: &'static str,
    include_other_cookie_first: bool,
) -> Result<http::Response<Vec<u8>>, Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let router = router_with_plugins(
        adapter,
        vec![
            openauth_plugins::bearer::bearer(),
            issue_cookie_plugin(exposed_headers, include_other_cookie_first),
        ],
    )?;
    Ok(router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/issue-cookie",
            "",
            None,
            HeaderMap::new(),
        )?)
        .await?)
}

fn issue_cookie_plugin(
    exposed_headers: &'static str,
    include_other_cookie_first: bool,
) -> AuthPlugin {
    let endpoint = create_auth_endpoint(
        "/issue-cookie",
        Method::GET,
        AuthEndpointOptions::default(),
        move |context, _request| {
            Box::pin(async move {
                let mut response = response(StatusCode::OK, b"OK".to_vec())?;
                if include_other_cookie_first {
                    response.headers_mut().append(
                        header::SET_COOKIE,
                        HeaderValue::from_static("unrelated=value; Path=/"),
                    );
                }
                let token = if include_other_cookie_first {
                    "issued.token".to_owned()
                } else {
                    sign_cookie_value("issued_token", &context.secret)?
                };
                let cookie = format!(
                    "{}={token}; Path=/",
                    context.auth_cookies.session_token.name
                );
                let cookie = HeaderValue::from_str(&cookie)
                    .map_err(|error| OpenAuthError::Api(error.to_string()))?;
                response.headers_mut().append(header::SET_COOKIE, cookie);
                if !exposed_headers.is_empty() {
                    response.headers_mut().insert(
                        header::ACCESS_CONTROL_EXPOSE_HEADERS,
                        HeaderValue::from_static(exposed_headers),
                    );
                }
                Ok(response)
            })
        },
    );
    AuthPlugin::new("issuer").with_endpoint(endpoint)
}
