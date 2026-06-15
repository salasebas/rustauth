mod common;

use std::sync::Arc;

use common::*;

use actix_web::http::Method;
use actix_web::http::StatusCode;
use actix_web::test;
use actix_web::{web, App};
use rustauth::db::MemoryAdapter;
use rustauth::options::{AdvancedOptions, DeleteUserOptions, RustAuthOptions, UserOptions};
use rustauth::plugin::AuthPlugin;
use rustauth::RustAuth;
use rustauth_actix_web::{RustAuthActixWebError, RustAuthActixWebExt, RustAuthActixWebOptions};

#[tokio::test]
async fn ok_route_is_mounted_under_default_base_path() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(auth_with_options(RustAuthOptions::default()).await?);
    let app = mounted_app!(auth, RustAuthActixWebOptions::default());

    let response = test::call_service(
        &app,
        test_request(Method::GET, "/api/auth/ok", "", None).to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_text(response).await?, "OK");
    Ok(())
}

#[tokio::test]
async fn default_base_path_accepts_trailing_slash_root() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(auth_with_options(RustAuthOptions::default()).await?);
    let app = mounted_app!(auth, RustAuthActixWebOptions::default());

    let root_without_slash = test::call_service(
        &app,
        test_request(Method::GET, "/api/auth", "", None).to_request(),
    )
    .await;
    assert_eq!(root_without_slash.status(), StatusCode::NOT_FOUND);

    let root_with_slash = test::call_service(
        &app,
        test_request(Method::GET, "/api/auth/", "", None).to_request(),
    )
    .await;
    assert_eq!(root_with_slash.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn skip_trailing_slashes_reaches_core_routes_over_actix(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(
        auth_with_options(
            RustAuthOptions::default().advanced(AdvancedOptions::new().skip_trailing_slashes(true)),
        )
        .await?,
    );
    let app = mounted_app!(auth, RustAuthActixWebOptions::default());

    let response = test::call_service(
        &app,
        test_request(Method::GET, "/api/auth/ok/", "", None).to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_text(response).await?, "OK");
    Ok(())
}

#[tokio::test]
async fn custom_base_path_mounts_all_auth_routes() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(
        RustAuth::builder()
            .secret(SECRET)
            .base_path("/auth")
            .build()
            .await?,
    );
    let app = mounted_app!(auth, RustAuthActixWebOptions::default());

    let response = test::call_service(
        &app,
        test_request(Method::GET, "/auth/ok", "", None).to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn root_base_path_mounts_auth_routes_at_root() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(
        RustAuth::builder()
            .secret(SECRET)
            .base_path("/")
            .build()
            .await?,
    );
    let app = mounted_app!(auth, RustAuthActixWebOptions::default());

    let response = test::call_service(
        &app,
        test_request(Method::GET, "/ok", "", None).to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn empty_base_path_mounts_auth_routes_at_root() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(
        RustAuth::builder()
            .secret(SECRET)
            .base_path("")
            .build()
            .await?,
    );
    let app = mounted_app!(auth, RustAuthActixWebOptions::default());

    let response = test::call_service(
        &app,
        test_request(Method::GET, "/ok", "", None).to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn trailing_slash_base_path_is_mounted_without_panicking(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(
        RustAuth::builder()
            .secret(SECRET)
            .base_path("/api/auth/")
            .build()
            .await?,
    );
    let app = mounted_app!(auth, RustAuthActixWebOptions::default());

    let response = test::call_service(
        &app,
        test_request(Method::GET, "/api/auth/ok", "", None).to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn invalid_base_paths_are_rejected_before_mounting() -> Result<(), Box<dyn std::error::Error>>
{
    for base_path in [
        "api/auth",
        "/api/{auth}",
        "/api/*auth",
        "/api/auth?x=1",
        "/api/auth#x",
    ] {
        let auth = Arc::new(
            RustAuth::builder()
                .secret(SECRET)
                .base_path(base_path)
                .build()
                .await?,
        );
        let result = auth.mount_at_base_path(RustAuthActixWebOptions::default());
        let Err(error) = result else {
            return Err(std::io::Error::other(format!("{base_path} should be rejected")).into());
        };
        assert!(
            matches!(error, RustAuthActixWebError::InvalidBasePath(_)),
            "{base_path} should produce InvalidBasePath"
        );
    }
    Ok(())
}

#[tokio::test]
async fn invalid_base_url_is_rejected_before_mounting() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(
        RustAuth::builder()
            .secret(SECRET)
            .base_path("/api/auth")
            .base_url("not-a-url")
            .build()
            .await?,
    );
    let result = auth.mount_at_base_path(RustAuthActixWebOptions::default());

    let Err(error) = result else {
        return Err(std::io::Error::other("invalid base_url should be rejected").into());
    };
    assert!(matches!(error, RustAuthActixWebError::InvalidBaseUrl(_)));
    Ok(())
}

#[tokio::test]
async fn inconsistent_base_url_path_is_rejected_before_mounting(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(
        RustAuth::builder()
            .secret(SECRET)
            .base_path("/api/auth")
            .base_url("http://localhost:3000/wrong")
            .build()
            .await?,
    );
    let result = auth.mount_at_base_path(RustAuthActixWebOptions::default());

    let Err(error) = result else {
        return Err(std::io::Error::other("mismatched base_url should be rejected").into());
    };
    assert!(matches!(
        error,
        RustAuthActixWebError::InconsistentBaseUrlPath { .. }
    ));
    Ok(())
}

#[tokio::test]
async fn non_auth_paths_and_wrong_methods_return_not_found(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(auth_with_options(RustAuthOptions::default()).await?);
    let app = mounted_app!(auth, RustAuthActixWebOptions::default());

    let outside = test::call_service(
        &app,
        test_request(Method::GET, "/api/authentication/ok", "", None).to_request(),
    )
    .await;
    assert_eq!(outside.status(), StatusCode::NOT_FOUND);

    let wrong_method = test::call_service(
        &app,
        test_request(Method::POST, "/api/auth/ok", "{}", None).to_request(),
    )
    .await;
    assert_eq!(wrong_method.status(), StatusCode::NOT_FOUND);

    let head = test::call_service(
        &app,
        test_request(Method::HEAD, "/api/auth/ok", "", None).to_request(),
    )
    .await;
    assert_eq!(head.status(), StatusCode::NOT_FOUND);

    let options = test::call_service(
        &app,
        test_request(Method::OPTIONS, "/api/auth/ok", "", None).to_request(),
    )
    .await;
    assert_eq!(options.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn mount_routes_can_be_nested_without_consuming_auth(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(auth_with_options(RustAuthOptions::default()).await?);
    let routes = auth.mount_routes(RustAuthActixWebOptions::default())?;
    let app = test::init_service(App::new().service(web::scope("/api/auth").service(routes))).await;

    let response = test::call_service(
        &app,
        test_request(Method::GET, "/api/auth/ok", "", None).to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_text(response).await?, "OK");
    assert!(!auth.endpoint_registry().is_empty());
    Ok(())
}

#[tokio::test]
async fn mount_routes_can_be_nested_manually_on_owned_auth(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = auth_with_options(RustAuthOptions::default()).await?;
    let routes = auth.mount_routes(RustAuthActixWebOptions::default())?;
    let app = test::init_service(App::new().service(web::scope("/api/auth").service(routes))).await;

    let response = test::call_service(
        &app,
        test_request(Method::GET, "/api/auth/ok", "", None).to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_text(response).await?, "OK");
    Ok(())
}

#[tokio::test]
async fn extra_async_endpoint_is_reachable_through_catch_all(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = Arc::new(auth_with_async_endpoint(custom_endpoint("/plugin/custom")).await?);
    let app = mounted_app!(auth, RustAuthActixWebOptions::default());

    let response = test::call_service(
        &app,
        test_request(Method::GET, "/api/auth/plugin/custom", "", None).to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_text(response).await?, "CUSTOM");
    Ok(())
}

#[tokio::test]
async fn plugin_endpoint_is_reachable_through_catch_all() -> Result<(), Box<dyn std::error::Error>>
{
    let plugin = AuthPlugin::new("route-plugin").with_endpoint(custom_endpoint("/plugin/hello"));
    let auth = Arc::new(auth_with_options(RustAuthOptions::default().plugin(plugin)).await?);
    let app = mounted_app!(auth, RustAuthActixWebOptions::default());

    let response = test::call_service(
        &app,
        test_request(Method::GET, "/api/auth/plugin/hello", "", None).to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_text(response).await?, "CUSTOM");
    Ok(())
}

#[tokio::test]
async fn every_core_auth_route_is_mounted_through_actix() -> Result<(), Box<dyn std::error::Error>>
{
    let auth = Arc::new(
        auth_with_adapter(
            MemoryAdapter::new(),
            RustAuthOptions::default()
                .base_url("http://localhost:3000/api/auth")
                .user(
                    UserOptions::default().delete_user(DeleteUserOptions::default().enabled(true)),
                )
                .social_provider(FakeProvider::new("github")),
        )
        .await?,
    );
    let cases = auth
        .endpoint_registry()
        .into_iter()
        .map(RouteCase::from_endpoint)
        .collect::<Vec<_>>();
    let app = mounted_app!(Arc::clone(&auth), RustAuthActixWebOptions::default());

    for case in cases {
        let response = test::call_service(
            &app,
            test_request(
                actix_method(&case.method)?,
                &case.path,
                case.body,
                case.cookie,
            )
            .to_request(),
        )
        .await;
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
    method: http::Method,
    path: String,
    body: &'static str,
    cookie: Option<&'static str>,
}

impl RouteCase {
    fn from_endpoint(endpoint: rustauth::api::EndpointInfo) -> Self {
        let path = materialize_route_path(&endpoint.path);
        let path = match endpoint.path.as_str() {
            "/callback/:id" => format!("{path}?state=missing"),
            "/error" => format!("{path}?error=invalid_request"),
            "/reset-password/:token" => format!("{path}?callbackURL=/reset"),
            "/verify-email" | "/delete-user/callback" => format!("{path}?token=missing"),
            _ => path,
        };
        let body = if endpoint.method == http::Method::POST {
            "{}"
        } else {
            ""
        };
        let cookie = (endpoint.path == "/sign-out").then_some("x=1");

        Self {
            method: endpoint.method,
            path,
            body,
            cookie,
        }
    }
}

fn materialize_route_path(path: &str) -> String {
    let path = path.replace(":id", "github").replace(":token", "missing");
    format!("/api/auth{path}")
}
