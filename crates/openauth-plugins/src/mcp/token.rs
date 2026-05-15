use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use http::{header, Method, StatusCode};
use openauth_core::api::{
    create_auth_endpoint, parse_request_body, AsyncAuthEndpoint, AuthEndpointOptions,
};
use openauth_core::crypto::jwt::sign_jwt;
use openauth_core::db::{Create, DbValue, Delete, FindOne, Where};
use serde::Serialize;
use serde_json::{json, Value};
use subtle::ConstantTimeEq;
use time::{Duration, OffsetDateTime};

use super::claims::user_claims;
use super::shared::{
    adapter, find_client, find_user, oauth_error, optional_timestamp, pkce_s256, random_token,
    required_string, string_field, with_cors, OAUTH_TOKEN_MODEL,
};
use super::{McpAdditionalIdTokenClaims, ResolvedMcpOptions};

#[derive(Debug, Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct VerificationCodeValue {
    #[serde(rename = "clientId")]
    client_id: String,
    #[serde(rename = "redirectURI")]
    redirect_uri: String,
    scope: Vec<String>,
    #[serde(rename = "userId")]
    user_id: String,
    #[serde(rename = "authTime")]
    auth_time: Option<i64>,
    #[serde(rename = "codeChallenge")]
    code_challenge: Option<String>,
    #[serde(rename = "codeChallengeMethod")]
    code_challenge_method: Option<String>,
    nonce: Option<String>,
}

pub fn token_endpoint(
    options: ResolvedMcpOptions,
    additional_id_token_claims: Option<McpAdditionalIdTokenClaims>,
) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/mcp/token",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("mcpOAuthToken")
            .allowed_media_types(["application/json", "application/x-www-form-urlencoded"]),
        move |context, request| {
            let options = options.clone();
            let additional_id_token_claims = additional_id_token_claims.clone();
            Box::pin(async move {
                let adapter = adapter(context)?;
                let body: Value = parse_request_body(&request)?;
                let mut client_id = string_field(&body, "client_id");
                let mut client_secret = string_field(&body, "client_secret");
                if client_id.is_none() && client_secret.is_none() {
                    if let Some((id, secret)) = basic_credentials(&request) {
                        client_id = Some(id);
                        client_secret = Some(secret);
                    }
                }
                let grant_type = string_field(&body, "grant_type");
                let token_result = match grant_type.as_deref() {
                    Some("refresh_token") => {
                        refresh_token(adapter.as_ref(), &options, client_id, &body).await
                    }
                    Some("authorization_code") => {
                        authorization_code(
                            adapter.as_ref(),
                            context,
                            &options,
                            client_id,
                            client_secret,
                            &body,
                            additional_id_token_claims.as_ref(),
                        )
                        .await
                    }
                    Some(_) => {
                        return oauth_error(
                            StatusCode::BAD_REQUEST,
                            "unsupported_grant_type",
                            "grant_type must be 'authorization_code'",
                        )
                    }
                    None => {
                        return oauth_error(
                            StatusCode::BAD_REQUEST,
                            "invalid_request",
                            "grant_type is required",
                        )
                    }
                };
                let response = match token_result {
                    Ok(response) => response,
                    Err(error) => return token_error_response(error),
                };
                let mut response = super::shared::json_response(StatusCode::OK, &response)?;
                response.headers_mut().insert(
                    header::CACHE_CONTROL,
                    http::HeaderValue::from_static("no-store"),
                );
                response
                    .headers_mut()
                    .insert(header::PRAGMA, http::HeaderValue::from_static("no-cache"));
                with_cors(response)
            })
        },
    )
}

async fn refresh_token(
    adapter: &dyn openauth_core::db::DbAdapter,
    options: &ResolvedMcpOptions,
    client_id: Option<String>,
    body: &Value,
) -> Result<TokenResponse, openauth_core::error::OpenAuthError> {
    let Some(refresh_token) = string_field(body, "refresh_token") else {
        return Err(openauth_core::error::OpenAuthError::Api(
            "refresh_token is required".to_owned(),
        ));
    };
    let Some(token) = adapter
        .find_one(
            FindOne::new(OAUTH_TOKEN_MODEL)
                .where_clause(Where::new("refreshToken", DbValue::String(refresh_token))),
        )
        .await?
    else {
        return Err(openauth_core::error::OpenAuthError::Api(
            "invalid refresh token".to_owned(),
        ));
    };
    let token_client_id = required_string(&token, "clientId")?;
    if client_id.as_deref() != Some(token_client_id.as_str()) {
        return Err(openauth_core::error::OpenAuthError::Api(
            "invalid client_id".to_owned(),
        ));
    }
    let expires_at = optional_timestamp(&token, "refreshTokenExpiresAt")?;
    if expires_at.is_some_and(|expires_at| expires_at <= OffsetDateTime::now_utc()) {
        return Err(openauth_core::error::OpenAuthError::Api(
            "refresh token expired".to_owned(),
        ));
    }
    let access_token = random_token();
    let refresh_token = random_token();
    let now = OffsetDateTime::now_utc();
    let scopes = required_string(&token, "scopes")?;
    adapter
        .create(
            Create::new(OAUTH_TOKEN_MODEL)
                .data("accessToken", DbValue::String(access_token.clone()))
                .data("refreshToken", DbValue::String(refresh_token.clone()))
                .data(
                    "accessTokenExpiresAt",
                    DbValue::Timestamp(
                        now + Duration::seconds(options.access_token_expires_in as i64),
                    ),
                )
                .data(
                    "refreshTokenExpiresAt",
                    DbValue::Timestamp(
                        now + Duration::seconds(options.refresh_token_expires_in as i64),
                    ),
                )
                .data("clientId", DbValue::String(token_client_id))
                .data(
                    "userId",
                    token.get("userId").cloned().unwrap_or(DbValue::Null),
                )
                .data("scopes", DbValue::String(scopes.clone()))
                .data("createdAt", DbValue::Timestamp(now))
                .data("updatedAt", DbValue::Timestamp(now)),
        )
        .await?;
    Ok(TokenResponse {
        access_token,
        token_type: "bearer".to_owned(),
        expires_in: options.access_token_expires_in,
        refresh_token: Some(refresh_token),
        scope: scopes,
        id_token: None,
    })
}

async fn authorization_code(
    adapter: &dyn openauth_core::db::DbAdapter,
    context: &openauth_core::context::AuthContext,
    options: &ResolvedMcpOptions,
    client_id: Option<String>,
    client_secret: Option<String>,
    body: &Value,
    additional_id_token_claims: Option<&McpAdditionalIdTokenClaims>,
) -> Result<TokenResponse, openauth_core::error::OpenAuthError> {
    let Some(code) = string_field(body, "code") else {
        return Err(openauth_core::error::OpenAuthError::Api(
            "code is required".to_owned(),
        ));
    };
    let Some(verification) = adapter
        .find_one(
            FindOne::new("verification")
                .where_clause(Where::new("identifier", DbValue::String(code.clone()))),
        )
        .await?
    else {
        return Err(openauth_core::error::OpenAuthError::Api(
            "invalid code".to_owned(),
        ));
    };
    adapter
        .delete(
            Delete::new("verification")
                .where_clause(Where::new("identifier", DbValue::String(code))),
        )
        .await?;
    if optional_timestamp(&verification, "expires_at")?
        .is_some_and(|expires_at| expires_at <= OffsetDateTime::now_utc())
    {
        return Err(openauth_core::error::OpenAuthError::Api(
            "code expired".to_owned(),
        ));
    }
    let Some(client_id) = client_id else {
        return Err(openauth_core::error::OpenAuthError::Api(
            "client_id is required".to_owned(),
        ));
    };
    let Some(redirect_uri) = string_field(body, "redirect_uri") else {
        return Err(openauth_core::error::OpenAuthError::Api(
            "redirect_uri is required".to_owned(),
        ));
    };
    let Some(client) = find_client(adapter, &client_id).await? else {
        return Err(openauth_core::error::OpenAuthError::Api(
            "invalid client_id".to_owned(),
        ));
    };
    if client.disabled {
        return Err(openauth_core::error::OpenAuthError::Api(
            "client is disabled".to_owned(),
        ));
    }
    let value = required_string(&verification, "value")?;
    let value: VerificationCodeValue = serde_json::from_str(&value)
        .map_err(|error| openauth_core::error::OpenAuthError::Api(error.to_string()))?;
    if client.client_type == "public" {
        if value.code_challenge.is_none() {
            return Err(openauth_core::error::OpenAuthError::Api(
                "code challenge is required for public clients".to_owned(),
            ));
        }
        if string_field(body, "code_verifier").is_none() {
            return Err(openauth_core::error::OpenAuthError::Api(
                "code verifier is required for public clients".to_owned(),
            ));
        }
    } else if !client_secret_matches(client.client_secret.as_deref(), client_secret.as_deref()) {
        return Err(openauth_core::error::OpenAuthError::Api(
            "invalid client_secret".to_owned(),
        ));
    }

    if value.client_id != client_id {
        return Err(openauth_core::error::OpenAuthError::Api(
            "invalid client_id".to_owned(),
        ));
    }
    if value.redirect_uri != redirect_uri {
        return Err(openauth_core::error::OpenAuthError::Api(
            "invalid redirect_uri".to_owned(),
        ));
    }
    validate_pkce(&value, string_field(body, "code_verifier"))?;

    let access_token = random_token();
    let refresh_token = random_token();
    let now = OffsetDateTime::now_utc();
    let scopes = value.scope.join(" ");
    adapter
        .create(
            Create::new(OAUTH_TOKEN_MODEL)
                .data("accessToken", DbValue::String(access_token.clone()))
                .data("refreshToken", DbValue::String(refresh_token.clone()))
                .data(
                    "accessTokenExpiresAt",
                    DbValue::Timestamp(
                        now + Duration::seconds(options.access_token_expires_in as i64),
                    ),
                )
                .data(
                    "refreshTokenExpiresAt",
                    DbValue::Timestamp(
                        now + Duration::seconds(options.refresh_token_expires_in as i64),
                    ),
                )
                .data("clientId", DbValue::String(client_id.clone()))
                .data("userId", DbValue::String(value.user_id.clone()))
                .data("scopes", DbValue::String(scopes.clone()))
                .data("createdAt", DbValue::Timestamp(now))
                .data("updatedAt", DbValue::Timestamp(now)),
        )
        .await?;
    let id_token = if value.scope.iter().any(|scope| scope == "openid") {
        let Some(user) = find_user(adapter, &value.user_id).await? else {
            return Err(openauth_core::error::OpenAuthError::Api(
                "user not found".to_owned(),
            ));
        };
        let mut claims = serde_json::Map::new();
        claims.insert("sub".to_owned(), json!(value.user_id));
        claims.insert("aud".to_owned(), json!(client_id));
        claims.insert("nonce".to_owned(), json!(value.nonce));
        claims.insert("acr".to_owned(), json!("urn:mace:incommon:iap:silver"));
        claims.insert("auth_time".to_owned(), json!(value.auth_time));
        for (key, claim) in user_claims(&user, &value.scope) {
            if key != "sub" {
                claims.insert(key, claim);
            }
        }
        if let Some(callback) = additional_id_token_claims {
            for (key, value) in callback(&user, &value.scope)? {
                claims.insert(key, value);
            }
        }
        Some(sign_jwt(
            &Value::Object(claims),
            &context.secret,
            options.access_token_expires_in as i64,
        )?)
    } else {
        None
    };
    Ok(TokenResponse {
        access_token,
        token_type: "Bearer".to_owned(),
        expires_in: options.access_token_expires_in,
        refresh_token: value
            .scope
            .iter()
            .any(|scope| scope == "offline_access")
            .then_some(refresh_token),
        scope: scopes,
        id_token,
    })
}

fn client_secret_matches(expected: Option<&str>, provided: Option<&str>) -> bool {
    let Some(expected) = expected else {
        return provided.is_none();
    };
    let Some(provided) = provided else {
        return false;
    };
    expected.len() == provided.len() && expected.as_bytes().ct_eq(provided.as_bytes()).into()
}

fn validate_pkce(
    value: &VerificationCodeValue,
    code_verifier: Option<String>,
) -> Result<(), openauth_core::error::OpenAuthError> {
    let Some(challenge) = &value.code_challenge else {
        return Ok(());
    };
    let Some(verifier) = code_verifier else {
        return Err(openauth_core::error::OpenAuthError::Api(
            "code verifier is missing".to_owned(),
        ));
    };
    let method = value
        .code_challenge_method
        .as_deref()
        .unwrap_or("plain")
        .to_ascii_lowercase();
    let candidate = if method == "plain" {
        verifier
    } else {
        pkce_s256(&verifier)
    };
    if &candidate != challenge {
        return Err(openauth_core::error::OpenAuthError::Api(
            "code verification failed".to_owned(),
        ));
    }
    Ok(())
}

fn basic_credentials(request: &openauth_core::api::ApiRequest) -> Option<(String, String)> {
    let value = request
        .headers()
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let encoded = value.strip_prefix("Basic ")?;
    let decoded = STANDARD.decode(encoded).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (id, secret) = decoded.split_once(':')?;
    (!id.is_empty() && !secret.is_empty()).then(|| (id.to_owned(), secret.to_owned()))
}

fn token_error_response(
    error: openauth_core::error::OpenAuthError,
) -> Result<openauth_core::api::ApiResponse, openauth_core::error::OpenAuthError> {
    let openauth_core::error::OpenAuthError::Api(message) = error else {
        return Err(error);
    };
    let (status, code) = if message.contains("invalid client")
        || message.contains("invalid code")
        || message.contains("expired")
        || message.contains("verification failed")
    {
        (StatusCode::UNAUTHORIZED, "invalid_grant")
    } else if message.contains("client_secret") {
        (StatusCode::UNAUTHORIZED, "invalid_client")
    } else if message.contains("unsupported") {
        (StatusCode::BAD_REQUEST, "unsupported_grant_type")
    } else {
        (StatusCode::BAD_REQUEST, "invalid_request")
    };
    oauth_error(status, code, &message)
}
