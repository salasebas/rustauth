use http::{Method, StatusCode};
use openauth_core::api::{create_auth_endpoint, AsyncAuthEndpoint, AuthEndpointOptions};
use openauth_core::context::AuthContext;
use serde_json::{json, Value};

use super::shared::{json_response, with_cors};
use super::ResolvedMcpOptions;

pub fn authorization_server_endpoint(options: ResolvedMcpOptions) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/.well-known/oauth-authorization-server",
        Method::GET,
        AuthEndpointOptions::new().operation_id("getMcpOAuthConfig"),
        move |context, _request| {
            let options = options.clone();
            Box::pin(async move {
                let metadata = authorization_server_metadata(context, &options);
                with_cors(json_response(StatusCode::OK, &metadata)?)
            })
        },
    )
}

pub fn protected_resource_endpoint(options: ResolvedMcpOptions) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/.well-known/oauth-protected-resource",
        Method::GET,
        AuthEndpointOptions::new().operation_id("getMcpProtectedResource"),
        move |context, _request| {
            let options = options.clone();
            Box::pin(async move {
                let metadata = protected_resource_metadata(context, &options);
                with_cors(json_response(StatusCode::OK, &metadata)?)
            })
        },
    )
}

fn authorization_server_metadata(context: &AuthContext, options: &ResolvedMcpOptions) -> Value {
    let issuer = context.base_url.clone();
    let base = auth_base_url(context);
    let mut metadata = json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{base}/mcp/authorize"),
        "token_endpoint": format!("{base}/mcp/token"),
        "userinfo_endpoint": format!("{base}/mcp/userinfo"),
        "jwks_uri": format!("{base}/mcp/jwks"),
        "registration_endpoint": format!("{base}/mcp/register"),
        "scopes_supported": options.scopes,
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "acr_values_supported": [
            "urn:mace:incommon:iap:silver",
            "urn:mace:incommon:iap:bronze",
        ],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["HS256", "none"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
            "none",
        ],
        "code_challenge_methods_supported": ["S256"],
        "claims_supported": [
            "sub",
            "iss",
            "aud",
            "exp",
            "nbf",
            "iat",
            "jti",
            "email",
            "email_verified",
            "name",
        ],
    });
    merge_metadata(&mut metadata, &options.metadata.authorization_server);
    metadata
}

fn protected_resource_metadata(context: &AuthContext, options: &ResolvedMcpOptions) -> Value {
    let origin = origin_from_base_url(&context.base_url);
    let base = auth_base_url(context);
    let mut metadata = json!({
        "resource": options.resource.clone().unwrap_or_else(|| origin.clone()),
        "authorization_servers": [origin],
        "jwks_uri": format!("{base}/mcp/jwks"),
        "scopes_supported": options.scopes,
        "bearer_methods_supported": ["header"],
        "resource_signing_alg_values_supported": ["HS256", "none"],
    });
    merge_metadata(&mut metadata, &options.metadata.protected_resource);
    metadata
}

fn merge_metadata(metadata: &mut Value, overrides: &serde_json::Map<String, Value>) {
    let Some(object) = metadata.as_object_mut() else {
        return;
    };
    for (key, value) in overrides {
        object.insert(key.clone(), value.clone());
    }
}

fn auth_base_url(context: &AuthContext) -> String {
    format!(
        "{}{}",
        context.base_url.trim_end_matches('/'),
        context.base_path.trim_end_matches('/')
    )
}

fn origin_from_base_url(base_url: &str) -> String {
    url::Url::parse(base_url)
        .ok()
        .and_then(|url| {
            let scheme = url.scheme();
            let host = url.host_str()?;
            let port = url
                .port()
                .map(|port| format!(":{port}"))
                .unwrap_or_default();
            Some(format!("{scheme}://{host}{port}"))
        })
        .unwrap_or_else(|| base_url.trim_end_matches('/').to_owned())
}
