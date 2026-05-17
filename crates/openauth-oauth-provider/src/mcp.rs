use http::{header, HeaderMap, StatusCode};
use openauth_core::context::AuthContext;
use openauth_core::db::DbAdapter;
use openauth_core::error::OpenAuthError;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::options::ResolvedOAuthProviderOptions;
use crate::token::validate_access_token;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpBearerToken {
    pub active: bool,
    pub subject: Option<String>,
    pub client_id: Option<String>,
    pub scopes: Vec<String>,
}

pub fn authorization_server_metadata(
    context: &AuthContext,
    options: &ResolvedOAuthProviderOptions,
) -> Value {
    json!({
        "issuer": context.base_url,
        "authorization_endpoint": format!("{}/oauth2/authorize", context.base_url),
        "token_endpoint": format!("{}/oauth2/token", context.base_url),
        "registration_endpoint": format!("{}/oauth2/register", context.base_url),
        "introspection_endpoint": format!("{}/oauth2/introspect", context.base_url),
        "revocation_endpoint": format!("{}/oauth2/revoke", context.base_url),
        "scopes_supported": options.scopes,
        "response_types_supported": ["code"],
        "grant_types_supported": options
            .grant_types
            .iter()
            .map(|grant| grant.as_str())
            .collect::<Vec<_>>(),
        "code_challenge_methods_supported": ["S256"],
    })
}

pub fn protected_resource_metadata(
    context: &AuthContext,
    options: &ResolvedOAuthProviderOptions,
    resource: &str,
) -> Result<Value, OpenAuthError> {
    let parsed =
        url::Url::parse(resource).map_err(|error| OpenAuthError::Api(error.to_string()))?;
    Ok(json!({
        "resource": parsed.as_str(),
        "authorization_servers": [context.base_url.as_str()],
        "scopes_supported": options.scopes,
        "bearer_methods_supported": ["header"],
    }))
}

pub async fn validate_bearer_token(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    authorization: Option<&str>,
) -> Result<Option<McpBearerToken>, OpenAuthError> {
    let Some(token) = authorization.and_then(parse_bearer_token) else {
        return Ok(None);
    };
    let Some(validated) = validate_access_token(context, adapter, options, token).await? else {
        return Ok(None);
    };
    if !validated.active {
        return Ok(None);
    }
    let subject = validated
        .claims
        .get("sub")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or(validated.user_id);
    Ok(Some(McpBearerToken {
        active: true,
        subject,
        client_id: validated.client_id,
        scopes: validated.scopes,
    }))
}

fn parse_bearer_token(authorization: &str) -> Option<&str> {
    let value = authorization.trim();
    value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty())
}

/// Build a `WWW-Authenticate` value for MCP protected resource metadata.
pub fn www_authenticate_for_resources<I, S>(resources: I) -> Result<String, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    resources
        .into_iter()
        .map(|resource| {
            let resource = resource.as_ref();
            let url = url::Url::parse(resource)
                .map_err(|_| format!("missing resource_metadata mapping for {resource}"))?;
            let path = url.path().trim_end_matches('/');
            Ok(format!(
                "Bearer resource_metadata=\"{}://{}{}{}{}\"",
                url.scheme(),
                url.host_str().unwrap_or_default(),
                url.port()
                    .map(|port| format!(":{port}"))
                    .unwrap_or_default(),
                "/.well-known/oauth-protected-resource",
                path
            ))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|values| values.join(", "))
}

/// Attach MCP authentication challenge headers to a response builder.
pub fn unauthorized_response_headers(resource_metadata: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Ok(value) = header::HeaderValue::from_str(resource_metadata) {
        headers.insert(header::WWW_AUTHENTICATE, value);
    }
    headers
}

/// Status returned for missing or invalid bearer tokens in MCP handlers.
pub const MCP_UNAUTHORIZED: StatusCode = StatusCode::UNAUTHORIZED;
