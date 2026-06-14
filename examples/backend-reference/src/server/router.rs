//! Axum router: RustAuth public API + reference introspection routes.

use axum::routing::get;
use axum::Router;

use rustauth::api::EndpointInfo;
use rustauth::RustAuth;
use rustauth_axum::{RustAuthAxumExt, RustAuthAxumOptions};
use rustauth_core::env::allows_development_defaults;

use crate::auth::AuthStack;
use crate::config::AppConfig;
use crate::error::AppResult;
use crate::server::introspection;

#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub auth: std::sync::Arc<RustAuth>,
    pub endpoints: Vec<EndpointInfo>,
    pub openapi: serde_json::Value,
}

/// Build the HTTP application from a fully initialized [`AuthStack`].
pub fn build_router(stack: AuthStack) -> AppResult<Router> {
    let AuthStack { auth, config } = stack;
    let expose_reference_routes = allows_development_defaults(auth.options());
    let auth_base_path = config.auth_base_path.clone();
    let endpoints = auth.endpoint_registry();
    let openapi = auth.openapi_schema();
    let auth_routes = auth.mount_routes(RustAuthAxumOptions::default())?;

    let state = AppState {
        config,
        auth,
        endpoints,
        openapi,
    };

    let reference = Router::new()
        .route("/health", get(introspection::health))
        .route("/reference/runtime", get(introspection::runtime))
        .route("/reference/endpoints", get(introspection::endpoints))
        .route("/reference/groups", get(introspection::endpoint_groups))
        .route("/reference/openapi.json", get(introspection::openapi))
        .route("/reference/plugins", get(introspection::plugins))
        .route("/reference/access", get(introspection::access))
        .route(
            "/reference/social-patterns",
            get(introspection::social_patterns),
        )
        .with_state(state);

    let mut app = Router::new().nest(&auth_base_path, auth_routes);
    if expose_reference_routes {
        app = app.merge(reference);
    }
    Ok(app)
}
