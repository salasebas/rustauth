mod common;

use axum::http::{Method, StatusCode};
use axum::Router;
use common::*;
use openauth::{
    AuthPlugin, DeleteUserOptions, MemoryAdapter, OpenAuth, OpenAuthOptions, UserOptions,
};
use openauth_axum::{router, OpenAuthAxumError, OpenAuthAxumExt};
use tower::ServiceExt;

#[tokio::test]
async fn ok_route_is_mounted_under_default_base_path() -> Result<(), Box<dyn std::error::Error>> {
    let app = router(auth_with_options(OpenAuthOptions::default())?)?;

    let response = app
        .oneshot(request(Method::GET, "/api/auth/ok", "", None)?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_text(response).await?, "OK");
    Ok(())
}

#[tokio::test]
async fn custom_base_path_mounts_all_auth_routes() -> Result<(), Box<dyn std::error::Error>> {
    let app = OpenAuth::builder()
        .secret(SECRET)
        .base_path("/auth")
        .build()?
        .into_router()?;

    let response = app
        .oneshot(request(Method::GET, "/auth/ok", "", None)?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn root_base_path_mounts_auth_routes_at_root() -> Result<(), Box<dyn std::error::Error>> {
    let app = OpenAuth::builder()
        .secret(SECRET)
        .base_path("/")
        .build()?
        .into_router()?;

    let response = app.oneshot(request(Method::GET, "/ok", "", None)?).await?;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn trailing_slash_base_path_is_mounted_without_panicking(
) -> Result<(), Box<dyn std::error::Error>> {
    let app = OpenAuth::builder()
        .secret(SECRET)
        .base_path("/api/auth/")
        .build()?
        .into_router()?;

    let response = app
        .oneshot(request(Method::GET, "/api/auth/ok", "", None)?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn invalid_base_paths_are_rejected_before_mounting() -> Result<(), Box<dyn std::error::Error>>
{
    for base_path in ["api/auth", "", "/api/{auth}", "/api/*auth", "/api/auth?x=1"] {
        let result = OpenAuth::builder()
            .secret(SECRET)
            .base_path(base_path)
            .build()?
            .into_router();
        let Err(error) = result else {
            return Err(std::io::Error::other(format!("{base_path} should be rejected")).into());
        };
        assert!(
            matches!(error, OpenAuthAxumError::InvalidBasePath(_)),
            "{base_path} should produce InvalidBasePath"
        );
    }
    Ok(())
}

#[tokio::test]
async fn non_auth_paths_and_wrong_methods_return_not_found(
) -> Result<(), Box<dyn std::error::Error>> {
    let app = router(auth_with_options(OpenAuthOptions::default())?)?;

    let outside = app
        .clone()
        .oneshot(request(Method::GET, "/api/authentication/ok", "", None)?)
        .await?;
    assert_eq!(outside.status(), StatusCode::NOT_FOUND);

    let wrong_method = app
        .clone()
        .oneshot(request(Method::POST, "/api/auth/ok", "{}", None)?)
        .await?;
    assert_eq!(wrong_method.status(), StatusCode::NOT_FOUND);

    let head = app
        .clone()
        .oneshot(request(Method::HEAD, "/api/auth/ok", "", None)?)
        .await?;
    assert_eq!(head.status(), StatusCode::NOT_FOUND);

    let options = app
        .oneshot(request(Method::OPTIONS, "/api/auth/ok", "", None)?)
        .await?;
    assert_eq!(options.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn into_routes_can_be_nested_manually() -> Result<(), Box<dyn std::error::Error>> {
    let auth = auth_with_options(OpenAuthOptions::default())?;
    let app = Router::new().nest("/api/auth", auth.into_routes());

    let response = app
        .oneshot(request(Method::GET, "/api/auth/ok", "", None)?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_text(response).await?, "OK");
    Ok(())
}

#[tokio::test]
async fn extra_async_endpoint_is_reachable_through_catch_all(
) -> Result<(), Box<dyn std::error::Error>> {
    let app = router(auth_with_async_endpoint(custom_endpoint("/plugin/custom"))?)?;

    let response = app
        .oneshot(request(Method::GET, "/api/auth/plugin/custom", "", None)?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_text(response).await?, "CUSTOM");
    Ok(())
}

#[tokio::test]
async fn plugin_endpoint_is_reachable_through_catch_all() -> Result<(), Box<dyn std::error::Error>>
{
    let plugin = AuthPlugin::new("route-plugin").with_endpoint(custom_endpoint("/plugin/hello"));
    let app = router(auth_with_options(
        OpenAuthOptions::default().plugin(plugin),
    )?)?;

    let response = app
        .oneshot(request(Method::GET, "/api/auth/plugin/hello", "", None)?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_text(response).await?, "CUSTOM");
    Ok(())
}

#[tokio::test]
async fn every_core_auth_route_is_mounted_through_axum() -> Result<(), Box<dyn std::error::Error>> {
    let app = router(auth_with_adapter(
        MemoryAdapter::new(),
        OpenAuthOptions::default()
            .base_url("http://localhost:3000/api/auth")
            .user(UserOptions::default().delete_user(DeleteUserOptions::default().enabled(true)))
            .social_provider(FakeProvider::new("github")),
    )?)?;

    for case in core_route_cases() {
        let response = app
            .clone()
            .oneshot(request(
                case.method.clone(),
                case.path,
                case.body,
                case.cookie,
            )?)
            .await?;
        assert_ne!(
            response.status(),
            StatusCode::NOT_FOUND,
            "{} {} should be mounted",
            case.method,
            case.path
        );
    }
    Ok(())
}

struct RouteCase {
    method: Method,
    path: &'static str,
    body: &'static str,
    cookie: Option<&'static str>,
}

fn core_route_cases() -> Vec<RouteCase> {
    vec![
        RouteCase::post("/api/auth/sign-up/email", "{}"),
        RouteCase::post("/api/auth/sign-in/email", "{}"),
        RouteCase::post("/api/auth/sign-in/social", "{}"),
        RouteCase::post("/api/auth/sign-in/oauth2", "{}"),
        RouteCase::get("/api/auth/callback/github?state=missing"),
        RouteCase::post("/api/auth/callback/github", "{}"),
        RouteCase::post("/api/auth/link-social", "{}"),
        RouteCase::get("/api/auth/error?error=invalid_request"),
        RouteCase::get("/api/auth/get-session"),
        RouteCase::post("/api/auth/get-session", "{}"),
        RouteCase::get("/api/auth/list-sessions"),
        RouteCase::post("/api/auth/update-session", "{}"),
        RouteCase::post("/api/auth/revoke-session", "{}"),
        RouteCase::post("/api/auth/revoke-sessions", "{}"),
        RouteCase::post("/api/auth/revoke-other-sessions", "{}"),
        RouteCase::get("/api/auth/list-accounts"),
        RouteCase::post("/api/auth/unlink-account", "{}"),
        RouteCase::post("/api/auth/get-access-token", "{}"),
        RouteCase::post("/api/auth/refresh-token", "{}"),
        RouteCase::get("/api/auth/account-info"),
        RouteCase::post("/api/auth/update-user", "{}"),
        RouteCase::post("/api/auth/change-email", "{}"),
        RouteCase::post("/api/auth/send-verification-email", "{}"),
        RouteCase::get("/api/auth/verify-email?token=missing"),
        RouteCase::post("/api/auth/delete-user", "{}"),
        RouteCase::get("/api/auth/delete-user/callback?token=missing"),
        RouteCase::post("/api/auth/change-password", "{}"),
        RouteCase::post("/api/auth/set-password", "{}"),
        RouteCase::post("/api/auth/verify-password", "{}"),
        RouteCase::post("/api/auth/request-password-reset", "{}"),
        RouteCase::get("/api/auth/reset-password/missing?callbackURL=/reset"),
        RouteCase::post("/api/auth/reset-password", "{}"),
        RouteCase::post_with_cookie("/api/auth/sign-out", "{}", "x=1"),
    ]
}

impl RouteCase {
    fn get(path: &'static str) -> Self {
        Self {
            method: Method::GET,
            path,
            body: "",
            cookie: None,
        }
    }

    fn post(path: &'static str, body: &'static str) -> Self {
        Self {
            method: Method::POST,
            path,
            body,
            cookie: None,
        }
    }

    fn post_with_cookie(path: &'static str, body: &'static str, cookie: &'static str) -> Self {
        Self {
            method: Method::POST,
            path,
            body,
            cookie: Some(cookie),
        }
    }
}
