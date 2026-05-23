use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::Request;
use axum::response::IntoResponse;
use axum::routing::any;
use axum::Router;
use openauth::{OpenAuth, OpenAuthError};

use crate::error::{internal_error_response, OpenAuthAxumError};
use crate::request::to_api_request;
use crate::response::from_api_response;
use crate::OpenAuthAxumOptions;

#[derive(Clone)]
struct OpenAuthAxumState {
    auth: Arc<OpenAuth>,
    options: OpenAuthAxumOptions,
}

/// Convenience extension methods for mounting OpenAuth into Axum.
pub trait OpenAuthAxumExt {
    /// Mount OpenAuth at `OpenAuthOptions.base_path`, defaulting to `/api/auth`.
    fn into_router(self) -> Result<Router, OpenAuthAxumError>;

    /// Mount OpenAuth with adapter-specific options.
    fn into_router_with_options(
        self,
        options: OpenAuthAxumOptions,
    ) -> Result<Router, OpenAuthAxumError>;

    /// Return unmounted OpenAuth routes for callers that want to nest manually.
    fn into_routes(self) -> Router;

    /// Return unmounted OpenAuth routes with adapter-specific options.
    fn into_routes_with_options(self, options: OpenAuthAxumOptions) -> Router;
}

impl OpenAuthAxumExt for OpenAuth {
    fn into_router(self) -> Result<Router, OpenAuthAxumError> {
        router(self)
    }

    fn into_router_with_options(
        self,
        options: OpenAuthAxumOptions,
    ) -> Result<Router, OpenAuthAxumError> {
        router_with_options(self, options)
    }

    fn into_routes(self) -> Router {
        routes(self)
    }

    fn into_routes_with_options(self, options: OpenAuthAxumOptions) -> Router {
        routes_with_options(self, options)
    }
}

/// Mount OpenAuth at `auth.context().base_path`.
pub fn router(auth: OpenAuth) -> Result<Router, OpenAuthAxumError> {
    router_with_options(auth, OpenAuthAxumOptions::default())
}

/// Mount OpenAuth at `auth.context().base_path` with adapter-specific options.
pub fn router_with_options(
    auth: OpenAuth,
    options: OpenAuthAxumOptions,
) -> Result<Router, OpenAuthAxumError> {
    let base_path = normalize_base_path(&auth.context().base_path)?;
    if base_path == "/" {
        return Ok(routes_with_options(auth, options));
    }
    Ok(Router::new().nest(&base_path, routes_with_options(auth, options)))
}

/// Build unmounted OpenAuth catch-all routes.
///
/// Use this when composing with an existing Axum router manually. The returned
/// router should be nested at the same path as `OpenAuthOptions.base_path`.
pub fn routes(auth: OpenAuth) -> Router {
    routes_with_options(auth, OpenAuthAxumOptions::default())
}

/// Build unmounted OpenAuth catch-all routes with adapter-specific options.
pub fn routes_with_options(auth: OpenAuth, options: OpenAuthAxumOptions) -> Router {
    routes_from_shared(Arc::new(auth), options)
}

fn routes_from_shared(auth: Arc<OpenAuth>, options: OpenAuthAxumOptions) -> Router {
    Router::new()
        .route("/", any(route_handler))
        .route("/{*path}", any(route_handler))
        .with_state(OpenAuthAxumState { auth, options })
}

/// Handle a single Axum request through OpenAuth.
pub async fn handle(auth: OpenAuth, request: Request<Body>) -> axum::response::Response {
    handle_ref(&auth, request).await
}

/// Handle a single Axum request through OpenAuth with adapter-specific options.
pub async fn handle_with_options(
    auth: OpenAuth,
    options: OpenAuthAxumOptions,
    request: Request<Body>,
) -> axum::response::Response {
    handle_ref_with_options(&auth, options, request).await
}

/// Handle a single Axum request through a borrowed OpenAuth instance.
pub async fn handle_ref(auth: &OpenAuth, request: Request<Body>) -> axum::response::Response {
    handle_ref_with_options(auth, OpenAuthAxumOptions::default(), request).await
}

/// Handle a single Axum request through a borrowed OpenAuth instance with options.
pub async fn handle_ref_with_options(
    auth: &OpenAuth,
    options: OpenAuthAxumOptions,
    request: Request<Body>,
) -> axum::response::Response {
    match to_api_request(request, options).await {
        Ok(request) => match auth.handler_async(request).await {
            Ok(response) => from_api_response(response),
            Err(error) => {
                log_internal_error(auth, &error);
                internal_error_response()
            }
        },
        Err(response) => response,
    }
}

async fn route_handler(
    State(state): State<OpenAuthAxumState>,
    request: Request<Body>,
) -> impl IntoResponse {
    handle_ref_with_options(state.auth.as_ref(), state.options, request).await
}

fn normalize_base_path(base_path: &str) -> Result<String, OpenAuthAxumError> {
    if !is_valid_base_path(base_path) {
        return Err(OpenAuthAxumError::InvalidBasePath(base_path.to_owned()));
    }

    let trimmed = base_path.trim_end_matches('/');
    if trimmed.is_empty() {
        Ok("/".to_owned())
    } else {
        Ok(trimmed.to_owned())
    }
}

fn is_valid_base_path(base_path: &str) -> bool {
    !base_path.is_empty()
        && base_path.starts_with('/')
        && !base_path.contains('?')
        && !base_path.contains('#')
        && !base_path.contains('{')
        && !base_path.contains('}')
        && !base_path.contains('*')
}

fn log_internal_error(auth: &OpenAuth, error: &OpenAuthError) {
    let message = error.to_string();
    auth.context()
        .logger
        .error("OpenAuth Axum handler failed", &[message.as_str()]);
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "test-secret-123456789012345678901234";

    #[test]
    fn normalize_base_path_trims_trailing_slashes_except_root() -> Result<(), OpenAuthAxumError> {
        assert_eq!(normalize_base_path("/")?, "/");
        assert_eq!(normalize_base_path("/api/auth/")?, "/api/auth");
        assert_eq!(normalize_base_path("/api/auth///")?, "/api/auth");
        Ok(())
    }

    #[test]
    fn normalize_base_path_rejects_axum_pattern_syntax_and_non_absolute_paths() {
        for base_path in ["", "api/auth", "/api/{auth}", "/api/*auth", "/api/auth?x=1"] {
            assert!(matches!(
                normalize_base_path(base_path),
                Err(OpenAuthAxumError::InvalidBasePath(_))
            ));
        }
    }

    #[test]
    fn axum_state_clones_only_the_shared_auth_pointer() -> Result<(), OpenAuthError> {
        let auth = Arc::new(OpenAuth::builder().secret(SECRET).build()?);
        let state = OpenAuthAxumState {
            auth: Arc::clone(&auth),
            options: OpenAuthAxumOptions::default(),
        };

        let cloned = state.clone();

        assert_eq!(Arc::strong_count(&auth), 3);
        drop(cloned);
        assert_eq!(Arc::strong_count(&auth), 2);
        Ok(())
    }
}
