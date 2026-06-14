use super::*;

pub(super) fn introspect_endpoint(options: Arc<ResolvedOAuthProviderOptions>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/oauth2/introspect",
        Method::POST,
        AuthEndpointOptions::new()
            .allowed_media_types(["application/x-www-form-urlencoded", "application/json"]),
        move |context, request| {
            let options = Arc::clone(&options);
            async move {
                let Some(adapter) = context.adapter() else {
                    return error_response(OAuthProviderError::invalid_request(
                        "database adapter required",
                    ));
                };
                let body: serde_json::Value = parse_body(&request)?;
                if let Some(response) = authenticate_endpoint_client(
                    &context,
                    adapter.as_ref(),
                    &options,
                    &request,
                    &body,
                )
                .await?
                {
                    return Ok(response);
                }
                let Some(token) = body.get("token").and_then(|value| value.as_str()) else {
                    return error_response(OAuthProviderError::invalid_request(
                        "token is required",
                    ));
                };
                let token_type_hint = body.get("token_type_hint").and_then(|value| value.as_str());
                match introspect_token_with_hint(
                    &context,
                    adapter.as_ref(),
                    &options,
                    token,
                    token_type_hint,
                )
                .await
                {
                    Ok(body) => json_response(StatusCode::OK, &body),
                    Err(error) => {
                        client_auth_failure_response(error).or_else(oauth_runtime_error_response)
                    }
                }
            }
        },
    )
}

pub(super) fn revoke_endpoint(options: Arc<ResolvedOAuthProviderOptions>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/oauth2/revoke",
        Method::POST,
        AuthEndpointOptions::new()
            .allowed_media_types(["application/x-www-form-urlencoded", "application/json"]),
        move |context, request| {
            let options = Arc::clone(&options);
            async move {
                let Some(adapter) = context.adapter() else {
                    return error_response(OAuthProviderError::invalid_request(
                        "database adapter required",
                    ));
                };
                let body: serde_json::Value = parse_body(&request)?;
                if let Some(response) = authenticate_endpoint_client(
                    &context,
                    adapter.as_ref(),
                    &options,
                    &request,
                    &body,
                )
                .await?
                {
                    return Ok(response);
                }
                let Some(token) = body.get("token").and_then(|value| value.as_str()) else {
                    return error_response(OAuthProviderError::invalid_request(
                        "token is required",
                    ));
                };
                let token_type_hint = body.get("token_type_hint").and_then(|value| value.as_str());
                match revoke_token_with_hint(adapter.as_ref(), &options, token, token_type_hint)
                    .await
                {
                    Ok(()) => empty_success_response(),
                    Err(error) => {
                        client_auth_failure_response(error).or_else(oauth_runtime_error_response)
                    }
                }
            }
        },
    )
}

async fn authenticate_endpoint_client(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    request: &ApiRequest,
    body: &serde_json::Value,
) -> Result<Option<ApiResponse>, RustAuthError> {
    let (client_id, client_secret) = match request_client_auth(request, body) {
        Ok(credentials) => credentials,
        Err(error) => return error_response(error).map(Some),
    };
    let Some(client_id) = client_id else {
        return Ok(Some(error_response(OAuthProviderError::unauthorized(
            "client authentication required",
        ))?));
    };
    match validate_client_credentials(
        context,
        adapter,
        options,
        &client_id,
        client_secret.as_deref(),
        &[],
    )
    .await
    {
        Ok(_) => Ok(None),
        Err(error) => client_auth_failure_response(error).map(Some),
    }
}

fn request_client_auth(
    request: &ApiRequest,
    body: &serde_json::Value,
) -> Result<(Option<String>, Option<String>), OAuthProviderError> {
    let mut client_id = body
        .get("client_id")
        .and_then(|value| value.as_str())
        .map(str::to_owned);
    let mut client_secret = body
        .get("client_secret")
        .and_then(|value| value.as_str())
        .map(str::to_owned);
    if let Some((basic_id, basic_secret)) = basic_credentials(request)? {
        client_id = Some(basic_id);
        client_secret = Some(basic_secret);
    }
    Ok((client_id, client_secret))
}

fn client_auth_failure_response(error: RustAuthError) -> Result<ApiResponse, RustAuthError> {
    let RustAuthError::Api(message) = error else {
        return Err(error);
    };
    let Some(description) = message.strip_prefix("invalid_client: ") else {
        return Err(RustAuthError::Api(message));
    };
    error_response(OAuthProviderError::unauthorized(description.to_owned()))
}

pub(super) fn token_grant_error_response(
    error: RustAuthError,
) -> Result<ApiResponse, RustAuthError> {
    client_auth_failure_response(error)
        .or_else(oauth_validation_error_response)
        .or_else(oauth_runtime_error_response)
}

fn oauth_runtime_error_response(error: RustAuthError) -> Result<ApiResponse, RustAuthError> {
    let RustAuthError::Api(message) = error else {
        return Err(error);
    };
    let Some((code, description)) = message.split_once(": ") else {
        return Err(RustAuthError::Api(message));
    };
    error_response(match code {
        "invalid_request" => OAuthProviderError::invalid_request(description.to_owned()),
        "invalid_scope" => OAuthProviderError::invalid_scope(description.to_owned()),
        "invalid_grant" => OAuthProviderError::new(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            description.to_owned(),
        ),
        "invalid_token" => OAuthProviderError::new(
            StatusCode::BAD_REQUEST,
            "invalid_token",
            description.to_owned(),
        ),
        "invalid_user" => OAuthProviderError::new(
            StatusCode::BAD_REQUEST,
            "invalid_user",
            description.to_owned(),
        ),
        _ => return Err(RustAuthError::Api(message)),
    })
}
