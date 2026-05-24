use super::*;

pub(super) fn token_endpoint(options: Arc<ResolvedOAuthProviderOptions>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/oauth2/token",
        Method::POST,
        AuthEndpointOptions::new()
            .allowed_media_types(["application/x-www-form-urlencoded", "application/json"]),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                let Some(adapter) = context.adapter() else {
                    return error_response(OAuthProviderError::invalid_request(
                        "database adapter required",
                    ));
                };
                let mut body: TokenRequest = match parse_body(&request) {
                    Ok(body) => body,
                    Err(error) => {
                        return error_response(OAuthProviderError::invalid_request(
                            error.to_string(),
                        ));
                    }
                };
                match basic_credentials(&request) {
                    Ok(Some((client_id, client_secret))) => {
                        body.client_id = Some(client_id);
                        body.client_secret = Some(client_secret);
                    }
                    Ok(None) => {}
                    Err(error) => return error_response(error),
                }
                match body.grant_type.as_deref() {
                    Some("client_credentials") => {
                        if !options.grant_types.contains(&GrantType::ClientCredentials) {
                            return error_response(OAuthProviderError::new(
                                StatusCode::BAD_REQUEST,
                                "unsupported_grant_type",
                                "unsupported grant_type client_credentials",
                            ));
                        }
                        let Some(client_id) = body.client_id.as_deref() else {
                            return error_response(OAuthProviderError::invalid_client(
                                "missing client",
                            ));
                        };
                        let requested_scopes = split_scope(body.scope.as_deref());
                        let resource = match validate_resource(
                            context,
                            &options,
                            body.resource.clone(),
                            &requested_scopes,
                        ) {
                            Ok(resource) => resource,
                            Err(error) => return error_response(error),
                        };
                        let response = match create_client_credentials_token(
                            context,
                            adapter.as_ref(),
                            &options,
                            client_id,
                            body.client_secret.as_deref(),
                            requested_scopes,
                            resource,
                        )
                        .await
                        {
                            Ok(response) => response,
                            Err(error) => return token_grant_error_response(error),
                        };
                        json_response(StatusCode::OK, &response)
                    }
                    Some("authorization_code") => {
                        if !options.grant_types.contains(&GrantType::AuthorizationCode) {
                            return error_response(OAuthProviderError::new(
                                StatusCode::BAD_REQUEST,
                                "unsupported_grant_type",
                                "unsupported grant_type authorization_code",
                            ));
                        }
                        let Some(client_id) = body.client_id.as_deref() else {
                            return error_response(OAuthProviderError::invalid_client(
                                "missing client",
                            ));
                        };
                        let Some(code) = body.code.as_deref() else {
                            return error_response(OAuthProviderError::invalid_request(
                                "code is required",
                            ));
                        };
                        let identifier = store_token(&options, code, "authorization_code").await?;
                        let store = DbVerificationStore::new(adapter.as_ref());
                        let Some(verification) = store.find_verification(&identifier).await? else {
                            return error_response(OAuthProviderError::new(
                                StatusCode::UNAUTHORIZED,
                                "invalid_verification",
                                "Invalid code",
                            ));
                        };
                        store.delete_verification(&identifier).await?;
                        let code_value: AuthorizationCodeValue =
                            serde_json::from_str(&verification.value)
                                .map_err(|error| OpenAuthError::Api(error.to_string()))?;
                        if code_value.redirect_uri.as_deref() != body.redirect_uri.as_deref() {
                            return error_response(OAuthProviderError::invalid_request(
                                "redirect_uri mismatch",
                            ));
                        }
                        if let Some(challenge) = code_value.code_challenge.as_deref() {
                            let Some(verifier) = body.code_verifier.as_deref() else {
                                return error_response(OAuthProviderError::invalid_request(
                                    "code_verifier is required",
                                ));
                            };
                            if code_value.code_challenge_method.as_deref() != Some("S256")
                                || crate::utils::sha256_base64url(verifier) != challenge
                            {
                                return error_response(OAuthProviderError::new(
                                    StatusCode::UNAUTHORIZED,
                                    "invalid_grant",
                                    "invalid code_verifier",
                                ));
                            }
                        } else if body.code_verifier.is_some() {
                            return error_response(OAuthProviderError::invalid_request(
                                "code_verifier provided but PKCE was not used in authorization",
                            ));
                        }
                        let resource = match validate_resource(
                            context,
                            &options,
                            body.resource.clone(),
                            &code_value.scopes,
                        ) {
                            Ok(resource) => resource,
                            Err(error) => return error_response(error),
                        };
                        let response = match create_authorization_code_token(
                            context,
                            adapter.as_ref(),
                            &options,
                            client_id,
                            body.client_secret.as_deref(),
                            code_value,
                            resource,
                        )
                        .await
                        {
                            Ok(response) => response,
                            Err(error) => return token_grant_error_response(error),
                        };
                        json_response(StatusCode::OK, &response)
                    }
                    Some("refresh_token") => {
                        if !options.grant_types.contains(&GrantType::RefreshToken) {
                            return error_response(OAuthProviderError::new(
                                StatusCode::BAD_REQUEST,
                                "unsupported_grant_type",
                                "unsupported grant_type refresh_token",
                            ));
                        }
                        let Some(client_id) = body.client_id.as_deref() else {
                            return error_response(OAuthProviderError::invalid_client(
                                "missing client",
                            ));
                        };
                        let Some(refresh_token) = body.refresh_token.as_deref() else {
                            return error_response(OAuthProviderError::invalid_request(
                                "refresh_token is required",
                            ));
                        };
                        let requested_scopes = split_scope(body.scope.as_deref());
                        let resource = match validate_resource(
                            context,
                            &options,
                            body.resource.clone(),
                            &requested_scopes,
                        ) {
                            Ok(resource) => resource,
                            Err(error) => return error_response(error),
                        };
                        let response = match create_refresh_token_grant(
                            context,
                            adapter.as_ref(),
                            &options,
                            RefreshTokenGrantInput {
                                client_id,
                                client_secret: body.client_secret.as_deref(),
                                refresh_token,
                                requested_scopes,
                                resource,
                            },
                        )
                        .await
                        {
                            Ok(response) => response,
                            Err(error) => return token_grant_error_response(error),
                        };
                        json_response(StatusCode::OK, &response)
                    }
                    Some(grant_type) => error_response(OAuthProviderError::new(
                        StatusCode::BAD_REQUEST,
                        "unsupported_grant_type",
                        format!("unsupported grant_type {grant_type}"),
                    )),
                    None => error_response(OAuthProviderError::new(
                        StatusCode::BAD_REQUEST,
                        "unsupported_grant_type",
                        "unsupported grant_type",
                    )),
                }
            })
        },
    )
}

fn validate_resource(
    context: &openauth_core::context::AuthContext,
    options: &ResolvedOAuthProviderOptions,
    resources: Vec<String>,
    scopes: &[String],
) -> Result<Vec<String>, OAuthProviderError> {
    if resources.is_empty() {
        return Ok(Vec::new());
    }
    let mut valid = if options.valid_audiences.is_empty() {
        vec![context.base_url.clone()]
    } else {
        options.valid_audiences.clone()
    };
    if scopes.iter().any(|scope| scope == "openid") {
        valid.push(format!("{}/oauth2/userinfo", context.base_url));
    }
    for resource in &resources {
        if !valid.iter().any(|audience| audience == resource) {
            return Err(OAuthProviderError::invalid_request(
                "requested resource invalid",
            ));
        }
    }
    Ok(resources)
}

pub(super) fn validate_requested_scopes(
    client: &crate::models::SchemaClient,
    options: &ResolvedOAuthProviderOptions,
    scopes: &[String],
) -> Result<(), OAuthProviderError> {
    let allowed_scopes = client.scopes.as_ref().unwrap_or(&options.scopes);
    for scope in scopes {
        if !allowed_scopes.iter().any(|allowed| allowed == scope) {
            return Err(OAuthProviderError::invalid_scope(format!(
                "requested scope {scope} is not allowed for this client"
            )));
        }
    }
    Ok(())
}
