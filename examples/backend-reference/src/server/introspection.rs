//! Read-only routes that expose runtime metadata and the full public API catalog.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;

use rustauth_core::env::allows_development_defaults;

use crate::auth::access::{example_access_control, member_role, owner_role};
use crate::auth::{enabled_plugin_ids, SOCIAL_SETUP_PATTERNS};
use crate::catalog::{endpoint_views, group_endpoints};
use crate::server::router::AppState;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: String,
}

#[derive(Serialize)]
pub struct RuntimeResponse {
    pub rustauth_version: String,
    pub auth_base_path: String,
    pub base_url: String,
    pub database_url_redacted: String,
    pub development: bool,
    pub trusted_origins: Vec<String>,
    pub enabled_plugins: &'static [&'static str],
    pub endpoint_count: usize,
}

pub async fn health() -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok",
        version: rustauth::VERSION.to_owned(),
    })
}

pub async fn runtime(State(state): State<AppState>) -> impl IntoResponse {
    Json(RuntimeResponse {
        rustauth_version: rustauth::VERSION.to_owned(),
        auth_base_path: state.config.auth_base_path.clone(),
        base_url: state.config.base_url.clone(),
        database_url_redacted: redact_database_url(&state.config.database_url),
        development: allows_development_defaults(state.auth.options()),
        trusted_origins: state.config.trusted_origins.clone(),
        enabled_plugins: enabled_plugin_ids(),
        endpoint_count: state.endpoints.len(),
    })
}

pub async fn endpoints(State(state): State<AppState>) -> impl IntoResponse {
    Json(endpoint_views(&state.endpoints))
}

pub async fn endpoint_groups(State(state): State<AppState>) -> impl IntoResponse {
    Json(group_endpoints(&state.endpoints))
}

pub async fn openapi(State(state): State<AppState>) -> impl IntoResponse {
    (StatusCode::OK, Json(state.openapi.clone()))
}

pub async fn access() -> impl IntoResponse {
    let control = match example_access_control() {
        Ok(control) => control,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": error.to_string() })),
            )
                .into_response();
        }
    };
    let owner_statements = owner_role(&control)
        .map(|role| role.statements().len())
        .map_err(|error| error.to_string());
    let member_statements = member_role(&control)
        .map(|role| role.statements().len())
        .map_err(|error| error.to_string());

    Json(AccessResponse {
        description: "App-layer RBAC via rustauth_plugins::access (not an HTTP plugin)",
        statements: &[
            (
                "organization",
                &["create", "read", "update", "delete", "invite"],
            ),
            ("billing", &["read", "manage"]),
            ("api_key", &["create", "read", "revoke"]),
        ],
        example_roles: ExampleRoles {
            owner_resource_count: owner_statements,
            member_resource_count: member_statements,
        },
    })
    .into_response()
}

pub async fn plugins() -> impl IntoResponse {
    Json(PluginsResponse {
        enabled: enabled_plugin_ids(),
        notes: &[
            "access: helper library for roles/statements (no HTTP routes) — see /reference/access",
            "captcha: protects /reference/captcha-protected only in this demo",
            "generic-oauth: POST /sign-in/oauth2, GET /oauth2/callback/:providerId, POST /oauth2/link (catalog social uses /sign-in/social, /callback/:id, /link-social)",
            "plugins use *_with constructors where the public API exposes options",
        ],
    })
}

pub async fn social_patterns() -> impl IntoResponse {
    Json(SocialPatternsResponse {
        patterns: SOCIAL_SETUP_PATTERNS,
        credential_env: "{PROVIDER}_CLIENT_ID and {PROVIDER}_CLIENT_SECRET (stub values in dev)",
    })
}

#[derive(Serialize)]
struct SocialPatternsResponse {
    patterns: &'static [&'static str],
    credential_env: &'static str,
}

#[derive(Serialize)]
struct PluginsResponse {
    enabled: &'static [&'static str],
    notes: &'static [&'static str],
}

#[derive(Serialize)]
struct AccessResponse {
    description: &'static str,
    statements: &'static [(&'static str, &'static [&'static str])],
    example_roles: ExampleRoles,
}

#[derive(Serialize)]
struct ExampleRoles {
    owner_resource_count: Result<usize, String>,
    member_resource_count: Result<usize, String>,
}

fn redact_database_url(url: &str) -> String {
    if let Some(at) = url.find('@') {
        if let Some(scheme_end) = url.find("://") {
            let scheme = &url[..scheme_end + 3];
            let host = &url[at + 1..];
            return format!("{scheme}***:***@{host}");
        }
    }
    url.to_owned()
}
