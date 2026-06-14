use super::*;

pub(crate) async fn validate_access_token(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    token: &str,
) -> Result<Option<ValidatedAccessToken>, RustAuthError> {
    let stored = store_token(options, token, "access_token").await?;
    if let Some(record) = adapter
        .find_one(find_by_string(OAUTH_ACCESS_TOKEN_MODEL, "token", &stored))
        .await?
    {
        let active = timestamp(&record, "expires_at").is_some_and(|expires| expires > now());
        let client_id = string(&record, "client_id");
        let user_id = string(&record, "user_id");
        let scopes = string_array(&record, "scopes").unwrap_or_default();
        let sub = match (&client_id, &user_id) {
            (Some(client_id), Some(user_id)) => {
                match get_client_cached(adapter, options, client_id).await? {
                    Some(client) => Some(resolve_subject_identifier(user_id, &client, options)?),
                    None => Some(user_id.clone()),
                }
            }
            _ => user_id.clone(),
        };
        let mut claims = json!({
        "active": active,
        "token_type": "access_token",
        "client_id": client_id,
        "sub": sub,
        "sid": string(&record, "session_id"),
        "exp": timestamp(&record, "expires_at").map(OffsetDateTime::unix_timestamp),
        "iat": timestamp(&record, "created_at").map(OffsetDateTime::unix_timestamp),
        "scope": join_scope(&scopes),
        });
        if let Some(resolver) = &options.custom_access_token_claims {
            if let Value::Object(map) = &mut claims {
                let client = match client_id.as_deref() {
                    Some(client_id) => get_client_cached(adapter, options, client_id).await?,
                    None => None,
                };
                let user = match user_id.as_deref() {
                    Some(user_id) => find_user(adapter, user_id).await?,
                    None => None,
                };
                map.extend(
                    resolver
                        .resolve(CustomAccessTokenClaimsInput {
                            user,
                            reference_id: string(&record, "reference_id"),
                            scopes: scopes.clone(),
                            resource: Vec::new(),
                            metadata: client.and_then(|client| client.metadata),
                        })
                        .await?,
                );
            }
        }
        return Ok(Some(ValidatedAccessToken {
            active,
            user_id,
            client_id: client_id.clone(),
            scopes: scopes.clone(),
            claims,
        }));
    }
    if !options.disable_jwt_plugin {
        if let Some(unverified) = unverified_jwt_claims(token) {
            let mut jwt_options = resolved_jwt_options(context);
            jwt_options.jwt.audience = audiences_from_claims(&unverified);
            if let Some(claims) = rustauth_plugins::jwt::verify_jwt_with_options(
                context,
                token,
                &jwt_options,
                Some(&context.base_url),
            )
            .await?
            {
                let scopes = claims
                    .get("scope")
                    .and_then(Value::as_str)
                    .map(|scope| {
                        scope
                            .split_whitespace()
                            .map(str::to_owned)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let user_id = claims.get("sub").and_then(Value::as_str).map(str::to_owned);
                let client_id = claims.get("azp").and_then(Value::as_str).map(str::to_owned);
                let mut response = Value::Object(claims);
                if let Value::Object(map) = &mut response {
                    map.insert("active".to_owned(), Value::Bool(true));
                    map.insert(
                        "token_type".to_owned(),
                        Value::String("access_token".to_owned()),
                    );
                    if let Some(client_id) = &client_id {
                        map.insert("client_id".to_owned(), Value::String(client_id.clone()));
                    }
                }
                return Ok(Some(ValidatedAccessToken {
                    active: true,
                    claims: response,
                    user_id,
                    client_id,
                    scopes,
                }));
            }
        }
    }
    Ok(None)
}

pub async fn introspect_token_with_hint(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    token: &str,
    token_type_hint: Option<&str>,
) -> Result<serde_json::Value, RustAuthError> {
    match token_type_hint {
        Some("access_token") => {
            return Ok(validate_access_token(context, adapter, options, token)
                .await?
                .map(|validated| validated.claims)
                .unwrap_or_else(|| serde_json::json!({ "active": false })));
        }
        Some("refresh_token") => {
            return introspect_refresh_token(adapter, options, token).await;
        }
        Some(_) => {
            return Err(OAuthProviderError::invalid_request("unsupported token_type_hint").into());
        }
        None => {}
    }
    if let Some(validated) = validate_access_token(context, adapter, options, token).await? {
        return Ok(validated.claims);
    }
    introspect_refresh_token(adapter, options, token).await
}

async fn introspect_refresh_token(
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    token: &str,
) -> Result<serde_json::Value, RustAuthError> {
    if let Some(stored) = stored_refresh_token_for_lookup(options, token).await? {
        if let Some(record) = adapter
            .find_one(find_by_string(OAUTH_REFRESH_TOKEN_MODEL, "token", &stored))
            .await?
        {
            let active = timestamp(&record, "revoked").is_none()
                && timestamp(&record, "expires_at").is_some_and(|expires| expires > now());
            return Ok(serde_json::json!({
                "active": active,
                "token_type": "refresh_token",
                "client_id": string(&record, "client_id"),
                "sub": string(&record, "user_id"),
                "sid": string(&record, "session_id"),
                "exp": timestamp(&record, "expires_at").map(OffsetDateTime::unix_timestamp),
                "iat": timestamp(&record, "created_at").map(OffsetDateTime::unix_timestamp),
                "scope": string_array(&record, "scopes").map(|scopes| scopes.join(" ")),
            }));
        }
    }
    Ok(serde_json::json!({ "active": false }))
}

async fn stored_refresh_token_for_lookup(
    options: &ResolvedOAuthProviderOptions,
    token: &str,
) -> Result<Option<String>, RustAuthError> {
    if options
        .prefixes
        .refresh_token
        .as_deref()
        .is_some_and(|prefix| !token.starts_with(prefix))
    {
        return Ok(None);
    }
    let decoded = decode_refresh_token(options, token).await?;
    store_token(options, &decoded.token, "refresh_token")
        .await
        .map(Some)
}

pub(super) fn unverified_jwt_claims(token: &str) -> Option<Map<String, Value>> {
    let payload = token.split('.').nth(1)?;
    let payload = URL_SAFE_NO_PAD.decode(payload).ok()?;
    match serde_json::from_slice::<Value>(&payload).ok()? {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

pub(super) fn audiences_from_claims(claims: &Map<String, Value>) -> Option<Vec<String>> {
    match claims.get("aud") {
        Some(Value::String(audience)) => Some(vec![audience.clone()]),
        Some(Value::Array(audiences)) => Some(
            audiences
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect(),
        ),
        _ => None,
    }
}

pub(super) fn client_id_from_audience(claims: &Map<String, Value>) -> Option<String> {
    audiences_from_claims(claims).and_then(|audiences| audiences.into_iter().next())
}

pub async fn revoke_token_with_hint(
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    token: &str,
    token_type_hint: Option<&str>,
) -> Result<(), RustAuthError> {
    match token_type_hint {
        Some("access_token") => {
            if revoke_access_token(adapter, options, token).await? {
                return Ok(());
            }
            if refresh_token_exists(adapter, options, token).await? {
                return Err(OAuthProviderError::new(
                    http::StatusCode::BAD_REQUEST,
                    "invalid_token",
                    "token_type_hint does not match token",
                )
                .into());
            }
            return Ok(());
        }
        Some("refresh_token") => {
            if revoke_refresh_token(adapter, options, token).await? {
                return Ok(());
            }
            if access_token_exists(adapter, options, token).await? {
                return Err(OAuthProviderError::new(
                    http::StatusCode::BAD_REQUEST,
                    "invalid_token",
                    "token_type_hint does not match token",
                )
                .into());
            }
            return Ok(());
        }
        Some(_) => {
            return Err(OAuthProviderError::invalid_request("unsupported token_type_hint").into());
        }
        None => {}
    }
    revoke_access_token(adapter, options, token).await?;
    revoke_refresh_token(adapter, options, token).await?;
    Ok(())
}

async fn access_token_exists(
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    token: &str,
) -> Result<bool, RustAuthError> {
    let stored = store_token(options, token, "access_token").await?;
    Ok(adapter
        .find_one(find_by_string(OAUTH_ACCESS_TOKEN_MODEL, "token", &stored))
        .await?
        .is_some())
}

async fn revoke_access_token(
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    token: &str,
) -> Result<bool, RustAuthError> {
    let existed = access_token_exists(adapter, options, token).await?;
    if existed {
        let stored = store_token(options, token, "access_token").await?;
        adapter
            .delete(delete_by_string(OAUTH_ACCESS_TOKEN_MODEL, "token", &stored))
            .await?;
    }
    Ok(existed)
}

async fn refresh_token_exists(
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    token: &str,
) -> Result<bool, RustAuthError> {
    let Some(stored_refresh_token) = stored_refresh_token_for_lookup(options, token).await? else {
        return Ok(false);
    };
    Ok(adapter
        .find_one(find_by_string(
            OAUTH_REFRESH_TOKEN_MODEL,
            "token",
            &stored_refresh_token,
        ))
        .await?
        .is_some())
}

async fn revoke_refresh_token(
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    token: &str,
) -> Result<bool, RustAuthError> {
    if let Some(stored_refresh_token) = stored_refresh_token_for_lookup(options, token).await? {
        if adapter
            .find_one(find_by_string(
                OAUTH_REFRESH_TOKEN_MODEL,
                "token",
                &stored_refresh_token,
            ))
            .await?
            .is_none()
        {
            return Ok(false);
        }
        let mut revoke = DbRecord::new();
        revoke.insert("revoked".to_owned(), DbValue::Timestamp(now()));
        adapter
            .update(update_by_string(
                OAUTH_REFRESH_TOKEN_MODEL,
                "token",
                &stored_refresh_token,
                revoke,
            ))
            .await?;
        return Ok(true);
    }
    Ok(false)
}
