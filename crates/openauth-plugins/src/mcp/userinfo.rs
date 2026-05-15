use http::{header, Method, StatusCode};
use openauth_core::api::{create_auth_endpoint, AsyncAuthEndpoint, AuthEndpointOptions};
use openauth_core::db::{DbValue, FindOne, Where};
use serde_json::{json, Value};
use time::OffsetDateTime;

use super::claims::user_claims;
use super::shared::{
    adapter, find_user, json_response, oauth_error, optional_timestamp, required_string,
    OAUTH_TOKEN_MODEL,
};
use super::McpAdditionalIdTokenClaims;

pub fn userinfo_endpoint(
    additional_claims: Option<McpAdditionalIdTokenClaims>,
) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/mcp/userinfo",
        Method::GET,
        AuthEndpointOptions::new().operation_id("mcpUserInfo"),
        move |context, request| {
            let additional_claims = additional_claims.clone();
            Box::pin(async move {
                let Some(token) = request
                    .headers()
                    .get(header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.strip_prefix("Bearer "))
                    .map(str::to_owned)
                else {
                    return oauth_error(
                        StatusCode::UNAUTHORIZED,
                        "invalid_request",
                        "authorization header not found",
                    );
                };
                let adapter = adapter(context)?;
                let Some(record) = adapter
                    .find_one(
                        FindOne::new(OAUTH_TOKEN_MODEL)
                            .where_clause(Where::new("accessToken", DbValue::String(token))),
                    )
                    .await?
                else {
                    return oauth_error(
                        StatusCode::UNAUTHORIZED,
                        "invalid_token",
                        "invalid access token",
                    );
                };
                if optional_timestamp(&record, "accessTokenExpiresAt")?
                    .is_some_and(|expires_at| expires_at <= OffsetDateTime::now_utc())
                {
                    return oauth_error(
                        StatusCode::UNAUTHORIZED,
                        "invalid_token",
                        "The Access Token expired",
                    );
                }
                let user_id = required_string(&record, "userId")?;
                let Some(user) = find_user(adapter.as_ref(), &user_id).await? else {
                    return oauth_error(
                        StatusCode::UNAUTHORIZED,
                        "invalid_token",
                        "user not found",
                    );
                };
                let scopes = required_string(&record, "scopes")?
                    .split_whitespace()
                    .map(str::to_owned)
                    .collect::<Vec<_>>();
                let mut claims = user_claims(&user, &scopes);
                if let Some(callback) = additional_claims {
                    for (key, value) in callback(&user, &scopes)? {
                        claims.insert(key, value);
                    }
                }
                json_response(StatusCode::OK, &Value::Object(claims))
            })
        },
    )
}

pub fn jwks_endpoint() -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/mcp/jwks",
        Method::GET,
        AuthEndpointOptions::new().operation_id("mcpJwks"),
        move |_context, _request| {
            Box::pin(async move {
                let mut response = json_response(StatusCode::OK, &json!({ "keys": [] }))?;
                response.headers_mut().insert(
                    header::CACHE_CONTROL,
                    http::HeaderValue::from_static("no-store"),
                );
                Ok(response)
            })
        },
    )
}
