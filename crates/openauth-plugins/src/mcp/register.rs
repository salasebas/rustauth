use http::{header, Method, StatusCode};
use openauth_core::api::{
    create_auth_endpoint, parse_request_body, AsyncAuthEndpoint, AuthEndpointOptions,
};
use openauth_core::db::{Create, DbValue};
use serde_json::{json, Value};
use time::OffsetDateTime;

use super::shared::{
    adapter, current_session, json_response, oauth_error, random_token, with_cors,
};
use super::{
    McpClientIdGenerator, McpClientSecretGenerator, ResolvedMcpOptions, TokenEndpointAuthMethod,
};

pub fn register_endpoint(
    _options: ResolvedMcpOptions,
    client_id_generator: Option<McpClientIdGenerator>,
    client_secret_generator: Option<McpClientSecretGenerator>,
) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/mcp/register",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("registerMcpClient")
            .allowed_media_types(["application/json"]),
        move |context, request| {
            let client_id_generator = client_id_generator.clone();
            let client_secret_generator = client_secret_generator.clone();
            Box::pin(async move {
                let adapter = adapter(context)?;
                let body: Value = parse_request_body(&request)?;
                let grant_types = string_array(&body, "grant_types")
                    .unwrap_or_else(|| vec!["authorization_code".to_owned()]);
                let response_types = string_array(&body, "response_types")
                    .unwrap_or_else(|| vec!["code".to_owned()]);
                let redirect_uris = string_array(&body, "redirect_uris").unwrap_or_default();
                if let Some(invalid) = redirect_uris
                    .iter()
                    .find(|redirect_uri| !is_valid_redirect_uri(redirect_uri))
                {
                    return oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_redirect_uri",
                        &format!("Invalid redirect URI: {invalid}"),
                    );
                }
                if let Some(invalid) = grant_types.iter().find(|grant| !is_allowed_grant(grant)) {
                    return oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_client_metadata",
                        &format!("Unsupported grant type: {invalid}"),
                    );
                }
                if let Some(invalid) = response_types
                    .iter()
                    .find(|response| !is_allowed_response_type(response))
                {
                    return oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_client_metadata",
                        &format!("Unsupported response type: {invalid}"),
                    );
                }
                if let Some(method) = string_value(&body, "token_endpoint_auth_method") {
                    if token_endpoint_auth_method(&method).is_none() {
                        return oauth_error(
                            StatusCode::BAD_REQUEST,
                            "invalid_client_metadata",
                            &format!("Unsupported token endpoint auth method: {method}"),
                        );
                    }
                }

                if requires_redirect_uri(&grant_types) && redirect_uris.is_empty() {
                    return oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_redirect_uri",
                        "Redirect URIs are required for authorization_code and implicit grant types",
                    );
                }
                if grant_types
                    .iter()
                    .any(|grant| grant == "authorization_code")
                    && !response_types.iter().any(|response| response == "code")
                {
                    return oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_client_metadata",
                        "When 'authorization_code' grant type is used, 'code' response type must be included",
                    );
                }
                if grant_types.iter().any(|grant| grant == "implicit")
                    && !response_types.iter().any(|response| response == "token")
                {
                    return oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_client_metadata",
                        "When 'implicit' grant type is used, 'token' response type must be included",
                    );
                }

                let session = current_session(adapter.as_ref(), context, &request).await?;
                let auth_method = auth_method(&body);
                let client_type = if auth_method == TokenEndpointAuthMethod::None {
                    "public"
                } else {
                    "web"
                };
                let client_id = client_id_generator
                    .as_ref()
                    .map(|generator| generator())
                    .unwrap_or_else(random_token);
                let client_secret = (client_type != "public").then(|| {
                    client_secret_generator
                        .as_ref()
                        .map(|generator| generator())
                        .unwrap_or_else(random_token)
                });
                let now = OffsetDateTime::now_utc();

                adapter
                    .create(
                        Create::new("oauthApplication")
                            .data(
                                "name",
                                DbValue::String(
                                    string_value(&body, "client_name")
                                        .unwrap_or_else(|| client_id.clone()),
                                ),
                            )
                            .data("icon", nullable_string(&body, "logo_uri"))
                            .data("metadata", metadata_string(&body))
                            .data("clientId", DbValue::String(client_id.clone()))
                            .data(
                                "clientSecret",
                                client_secret
                                    .clone()
                                    .map(DbValue::String)
                                    .unwrap_or(DbValue::Null),
                            )
                            .data("redirectUrls", DbValue::String(redirect_uris.join(",")))
                            .data("type", DbValue::String(client_type.to_owned()))
                            .data(
                                "authenticationScheme",
                                DbValue::String(auth_method.as_str().to_owned()),
                            )
                            .data("disabled", DbValue::Boolean(false))
                            .data(
                                "userId",
                                session
                                    .map(|session| DbValue::String(session.user_id))
                                    .unwrap_or(DbValue::Null),
                            )
                            .data("createdAt", DbValue::Timestamp(now))
                            .data("updatedAt", DbValue::Timestamp(now)),
                    )
                    .await?;

                let mut response = json!({
                    "client_id": client_id,
                    "client_id_issued_at": now.unix_timestamp(),
                    "redirect_uris": redirect_uris,
                    "token_endpoint_auth_method": auth_method.as_str(),
                    "grant_types": grant_types,
                    "response_types": response_types,
                    "client_name": string_value(&body, "client_name"),
                    "client_uri": string_value(&body, "client_uri"),
                    "logo_uri": string_value(&body, "logo_uri"),
                    "scope": string_value(&body, "scope"),
                    "contacts": string_array(&body, "contacts"),
                    "tos_uri": string_value(&body, "tos_uri"),
                    "policy_uri": string_value(&body, "policy_uri"),
                    "jwks_uri": string_value(&body, "jwks_uri"),
                    "jwks": body.get("jwks").cloned(),
                    "software_id": string_value(&body, "software_id"),
                    "software_version": string_value(&body, "software_version"),
                    "software_statement": string_value(&body, "software_statement"),
                    "metadata": body.get("metadata").cloned(),
                });
                if let Some(secret) = client_secret {
                    response["client_secret"] = Value::String(secret);
                    response["client_secret_expires_at"] = json!(0);
                }
                let mut response = json_response(StatusCode::CREATED, &response)?;
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

fn requires_redirect_uri(grant_types: &[String]) -> bool {
    grant_types.is_empty()
        || grant_types
            .iter()
            .any(|grant| grant == "authorization_code" || grant == "implicit")
}

fn auth_method(body: &Value) -> TokenEndpointAuthMethod {
    string_value(body, "token_endpoint_auth_method")
        .and_then(|method| token_endpoint_auth_method(&method))
        .unwrap_or(TokenEndpointAuthMethod::ClientSecretBasic)
}

fn token_endpoint_auth_method(method: &str) -> Option<TokenEndpointAuthMethod> {
    match method {
        "none" => Some(TokenEndpointAuthMethod::None),
        "client_secret_basic" => Some(TokenEndpointAuthMethod::ClientSecretBasic),
        "client_secret_post" => Some(TokenEndpointAuthMethod::ClientSecretPost),
        _ => None,
    }
}

fn is_allowed_grant(grant: &str) -> bool {
    matches!(
        grant,
        "authorization_code"
            | "implicit"
            | "password"
            | "client_credentials"
            | "refresh_token"
            | "urn:ietf:params:oauth:grant-type:jwt-bearer"
            | "urn:ietf:params:oauth:grant-type:saml2-bearer"
    )
}

fn is_allowed_response_type(response_type: &str) -> bool {
    matches!(response_type, "code" | "token")
}

fn is_valid_redirect_uri(redirect_uri: &str) -> bool {
    if redirect_uri.trim().is_empty() {
        return false;
    }
    let Ok(url) = url::Url::parse(redirect_uri) else {
        return false;
    };
    if url.has_authority() && url.fragment().is_none() {
        match url.scheme() {
            "https" => true,
            "http" => url
                .host_str()
                .is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "::1")),
            _ => false,
        }
    } else {
        false
    }
}

fn string_value(body: &Value, field: &str) -> Option<String> {
    body.get(field).and_then(Value::as_str).map(str::to_owned)
}

fn nullable_string(body: &Value, field: &str) -> DbValue {
    string_value(body, field)
        .map(DbValue::String)
        .unwrap_or(DbValue::Null)
}

fn metadata_string(body: &Value) -> DbValue {
    body.get("metadata")
        .map(|metadata| DbValue::String(metadata.to_string()))
        .unwrap_or(DbValue::Null)
}

fn string_array(body: &Value, field: &str) -> Option<Vec<String>> {
    body.get(field)?.as_array().map(|values| {
        values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect()
    })
}
