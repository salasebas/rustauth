use super::*;

pub(super) async fn create_id_token(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    client: &SchemaClient,
    input: IdTokenInput<'_>,
) -> Result<Option<String>, RustAuthError> {
    if !input.scopes.iter().any(|scope| scope == "openid") {
        return Ok(None);
    }
    if options.disable_jwt_plugin && client.client_secret.is_none() {
        return Ok(None);
    }
    let Some(user) = find_user(adapter, input.user_id).await? else {
        return Err(OAuthProviderError::invalid_request("user not found").into());
    };
    let iat = now();
    let exp = iat + Duration::seconds(options.id_token_expires_in as i64);
    let mut claims = user_normal_claims(&user, input.scopes);
    if let Some(resolver) = &options.custom_id_token_claims {
        claims.extend(
            resolver
                .resolve(CustomIdTokenClaimsInput {
                    user: user.clone(),
                    scopes: input.scopes.to_vec(),
                    metadata: client.metadata.clone(),
                })
                .await?,
        );
    }
    claims.insert(
        "sub".to_owned(),
        Value::String(resolve_subject_identifier(input.user_id, client, options)?),
    );
    claims.insert("iss".to_owned(), Value::String(context.base_url.clone()));
    claims.insert("aud".to_owned(), Value::String(client.client_id.clone()));
    claims.insert("iat".to_owned(), Value::Number(iat.unix_timestamp().into()));
    claims.insert("exp".to_owned(), Value::Number(exp.unix_timestamp().into()));
    claims.insert(
        "acr".to_owned(),
        Value::String("urn:mace:incommon:iap:bronze".to_owned()),
    );
    if let Some(nonce) = input.nonce {
        claims.insert("nonce".to_owned(), Value::String(nonce.to_owned()));
    }
    if client.enable_end_session == Some(true) {
        if let Some(session_id) = input.session_id {
            claims.insert("sid".to_owned(), Value::String(session_id.to_owned()));
        }
    }
    if let Some(auth_time) = input.auth_time {
        claims.insert(
            "auth_time".to_owned(),
            Value::Number(auth_time.unix_timestamp().into()),
        );
    }

    if options.disable_jwt_plugin {
        let stored_secret = client.client_secret.as_deref().ok_or_else(|| {
            RustAuthError::Api("client_secret is required for HS256 id_token".to_owned())
        })?;
        let secret = symmetric_decrypt(context.secret.as_str(), stored_secret)?;
        return hs256_jwt::sign_jwt(&claims, &secret, options.id_token_expires_in as i64).map(Some);
    }

    rustauth_plugins::jwt::sign_jwt(context, claims, Some(resolved_jwt_options(context)))
        .await
        .map(Some)
}

pub(crate) fn user_normal_claims(user: &User, scopes: &[String]) -> Map<String, Value> {
    let mut claims = Map::new();
    if scopes.iter().any(|scope| scope == "profile") {
        claims.insert("name".to_owned(), Value::String(user.name.clone()));
        if let Some(image) = &user.image {
            claims.insert("picture".to_owned(), Value::String(image.clone()));
        }
        let names = user
            .name
            .split_whitespace()
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        if names.len() > 1 {
            claims.insert(
                "given_name".to_owned(),
                Value::String(names[..names.len() - 1].join(" ")),
            );
            claims.insert(
                "family_name".to_owned(),
                Value::String(names[names.len() - 1].to_owned()),
            );
        }
    }
    if scopes.iter().any(|scope| scope == "email") {
        claims.insert("email".to_owned(), Value::String(user.email.clone()));
        claims.insert(
            "email_verified".to_owned(),
            Value::Bool(user.email_verified),
        );
    }
    claims
}

pub(super) async fn find_user(
    adapter: &dyn DbAdapter,
    user_id: &str,
) -> Result<Option<User>, RustAuthError> {
    adapter
        .find_one(find_by_string("user", "id", user_id))
        .await?
        .map(user_from_record)
        .transpose()
}

pub(crate) fn resolve_subject_identifier(
    user_id: &str,
    client: &SchemaClient,
    options: &ResolvedOAuthProviderOptions,
) -> Result<String, RustAuthError> {
    let Some(secret) = options.pairwise_secret.as_deref() else {
        return Ok(user_id.to_owned());
    };
    if client.subject_type.as_deref() != Some("pairwise") {
        return Ok(user_id.to_owned());
    }
    let sector = sector_identifier(client)?;
    hmac_sha256_base64url(&format!("{sector}.{user_id}"), secret)
}

pub(crate) async fn validate_id_token_hint(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    token: &str,
    client_id_hint: Option<&str>,
) -> Result<ValidatedIdTokenHint, OAuthProviderError> {
    let unverified = unverified_jwt_claims(token).ok_or_else(|| {
        OAuthProviderError::new(
            http::StatusCode::UNAUTHORIZED,
            "invalid_token",
            "invalid id token",
        )
    })?;
    let client_id = client_id_hint
        .map(str::to_owned)
        .or_else(|| client_id_from_audience(&unverified))
        .ok_or_else(|| OAuthProviderError::invalid_request("id token missing audience"))?;
    let Some(client) = get_client_cached(adapter, options, &client_id)
        .await
        .map_err(|error| OAuthProviderError::invalid_request(error.to_string()))?
    else {
        return Err(OAuthProviderError::invalid_client("client doesn't exist"));
    };
    if client.disabled == Some(true) {
        return Err(OAuthProviderError::invalid_client("client is disabled"));
    }
    if client.enable_end_session != Some(true) {
        return Err(OAuthProviderError::unauthorized("client unable to logout"));
    }

    let claims = if options.disable_jwt_plugin {
        let stored_secret = client
            .client_secret
            .as_deref()
            .ok_or_else(|| OAuthProviderError::invalid_client("missing required credentials"))?;
        let secret = symmetric_decrypt(context.secret.as_str(), stored_secret).map_err(|_| {
            OAuthProviderError::new(
                http::StatusCode::UNAUTHORIZED,
                "invalid_token",
                "invalid id token",
            )
        })?;
        let value: Value = hs256_jwt::verify_jwt(token, &secret)
            .map_err(|_| {
                OAuthProviderError::new(
                    http::StatusCode::UNAUTHORIZED,
                    "invalid_token",
                    "invalid id token",
                )
            })?
            .ok_or_else(|| {
                OAuthProviderError::new(
                    http::StatusCode::UNAUTHORIZED,
                    "invalid_token",
                    "invalid id token",
                )
            })?;
        match value {
            Value::Object(claims) => claims,
            _ => return Err(OAuthProviderError::invalid_request("missing payload")),
        }
    } else {
        let mut jwt_options = resolved_jwt_options(context);
        jwt_options.jwt.audience = Some(vec![client_id.clone()]);
        rustauth_plugins::jwt::verify_jwt_with_options(
            context,
            token,
            &jwt_options,
            Some(&context.base_url),
        )
        .await
        .map_err(|_| {
            OAuthProviderError::new(
                http::StatusCode::UNAUTHORIZED,
                "invalid_token",
                "invalid id token",
            )
        })?
        .ok_or_else(|| {
            OAuthProviderError::new(
                http::StatusCode::UNAUTHORIZED,
                "invalid_token",
                "invalid id token",
            )
        })?
    };

    if claims.get("iss").and_then(Value::as_str) != Some(context.base_url.as_str()) {
        return Err(OAuthProviderError::invalid_request("invalid issuer"));
    }
    let audiences = audiences_from_claims(&claims)
        .ok_or_else(|| OAuthProviderError::invalid_request("id token missing audience"))?;
    if !audiences.iter().any(|audience| audience == &client_id) {
        return Err(OAuthProviderError::invalid_request("audience mismatch"));
    }
    let session_id = claims
        .get("sid")
        .and_then(Value::as_str)
        .ok_or_else(|| OAuthProviderError::invalid_request("id token missing session"))?
        .to_owned();

    Ok(ValidatedIdTokenHint { client, session_id })
}

fn sector_identifier(client: &SchemaClient) -> Result<String, RustAuthError> {
    let uri = client
        .redirect_uris
        .first()
        .ok_or_else(|| RustAuthError::Api("client has no redirect URIs".to_owned()))?;
    let url = url::Url::parse(uri).map_err(|error| RustAuthError::Api(error.to_string()))?;
    let host = url
        .host_str()
        .ok_or_else(|| RustAuthError::Api("redirect URI has no host".to_owned()))?;
    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    })
}
