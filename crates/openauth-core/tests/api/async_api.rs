use http::{Method, Request, StatusCode};
use openauth_core::api::{response, ApiRequest, AsyncAuthEndpoint, AuthEndpoint, AuthRouter};
use openauth_core::context::{create_auth_context, AuthContext};
use openauth_core::error::OpenAuthError;
use openauth_core::options::OpenAuthOptions;

fn sync_endpoint() -> AuthEndpoint {
    AuthEndpoint {
        path: "/sync".to_owned(),
        method: Method::GET,
        handler: |_context: &AuthContext, _request: ApiRequest| {
            response(StatusCode::OK, b"SYNC".to_vec())
        },
    }
}

fn async_endpoint(path: &str) -> AsyncAuthEndpoint {
    AsyncAuthEndpoint::new(
        path.to_owned(),
        Method::GET,
        |_context: &AuthContext, _request: ApiRequest| {
            Box::pin(async move { response(StatusCode::OK, b"ASYNC".to_vec()) })
        },
    )
}

#[tokio::test]
async fn handle_async_runs_async_endpoint() -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router =
        AuthRouter::with_async_endpoints(context, Vec::new(), vec![async_endpoint("/async")])?;

    let response = router
        .handle_async(
            Request::builder()
                .method(Method::GET)
                .uri("http://localhost:3000/api/auth/async")
                .body(Vec::new())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.body(), b"ASYNC");
    Ok(())
}

#[tokio::test]
async fn handle_async_can_run_existing_sync_endpoints() -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::with_async_endpoints(context, vec![sync_endpoint()], Vec::new())?;

    let response = router
        .handle_async(
            Request::builder()
                .method(Method::GET)
                .uri("http://localhost:3000/api/auth/sync")
                .body(Vec::new())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.body(), b"SYNC");
    Ok(())
}

#[test]
fn sync_handle_rejects_async_only_endpoint() -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router =
        AuthRouter::with_async_endpoints(context, Vec::new(), vec![async_endpoint("/async")])?;

    let error = match router.handle(
        Request::builder()
            .method(Method::GET)
            .uri("http://localhost:3000/api/auth/async")
            .body(Vec::new())?,
    ) {
        Ok(_) => return Err("sync handle unexpectedly accepted async endpoint".into()),
        Err(error) => error,
    };

    assert_eq!(
        error,
        OpenAuthError::Api("async endpoint requires AuthRouter::handle_async".to_owned())
    );
    Ok(())
}

#[test]
fn async_endpoint_conflicts_with_sync_endpoint() -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;

    let result = AuthRouter::with_async_endpoints(
        context,
        vec![AuthEndpoint {
            path: "/same".to_owned(),
            method: Method::GET,
            handler: |_context: &AuthContext, _request: ApiRequest| {
                response(StatusCode::OK, Vec::new())
            },
        }],
        vec![async_endpoint("/same")],
    );

    assert!(result.is_err());
    Ok(())
}
