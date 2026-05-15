use http::{header, Method, StatusCode};
use openauth_core::api::{create_auth_endpoint, AsyncAuthEndpoint, AuthEndpointOptions};
use openauth_core::db::{DbValue, FindOne, Where};
use serde_json::Value;
use time::OffsetDateTime;

use super::shared::{
    adapter, json_response, optional_timestamp, record_to_json, OAUTH_TOKEN_MODEL,
};

pub fn get_session_endpoint() -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/mcp/get-session",
        Method::GET,
        AuthEndpointOptions::new().operation_id("getMcpSession"),
        move |context, request| {
            Box::pin(async move {
                let Some(access_token) = request
                    .headers()
                    .get(header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.strip_prefix("Bearer "))
                    .map(str::to_owned)
                else {
                    let mut response = json_response(StatusCode::OK, &Value::Null)?;
                    response.headers_mut().insert(
                        header::WWW_AUTHENTICATE,
                        http::HeaderValue::from_static("Bearer"),
                    );
                    return Ok(response);
                };
                let adapter = adapter(context)?;
                let Some(record) = adapter
                    .find_one(
                        FindOne::new(OAUTH_TOKEN_MODEL)
                            .where_clause(Where::new("accessToken", DbValue::String(access_token))),
                    )
                    .await?
                else {
                    return json_response(StatusCode::OK, &Value::Null);
                };
                if optional_timestamp(&record, "accessTokenExpiresAt")?
                    .is_some_and(|expires_at| expires_at <= OffsetDateTime::now_utc())
                {
                    return json_response(StatusCode::OK, &Value::Null);
                }
                json_response(StatusCode::OK, &record_to_json(&record)?)
            })
        },
    )
}
