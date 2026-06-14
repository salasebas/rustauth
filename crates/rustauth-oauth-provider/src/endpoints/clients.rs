use super::*;

pub(super) fn register_endpoint(options: Arc<ResolvedOAuthProviderOptions>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/oauth2/register",
        Method::POST,
        AuthEndpointOptions::new().allowed_media_types(["application/json"]),
        move |context, request| {
            let options = Arc::clone(&options);
            async move {
                let Some(adapter) = context.adapter() else {
                    return error_response(OAuthProviderError::invalid_request(
                        "database adapter required",
                    ));
                };
                let body: OAuthClient = parse_body(&request)?;
                let user_id = current_session(&context, adapter.as_ref(), &request)
                    .await?
                    .map(|(session, user, _)| (session, user));
                let client = match create_oauth_client(
                    &context,
                    adapter.as_ref(),
                    &options,
                    body,
                    CreateOAuthClientInput {
                        is_register: true,
                        user: user_id.as_ref().map(|(_, user)| user.clone()),
                        session: user_id.as_ref().map(|(session, _)| session.clone()),
                    },
                )
                .await
                {
                    Ok(client) => client,
                    Err(error) => return oauth_validation_error_response(error),
                };
                no_store_json_response(StatusCode::CREATED, &client)
            }
        },
    )
}

pub(super) fn create_client_endpoint(
    path: &'static str,
    options: Arc<ResolvedOAuthProviderOptions>,
) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        path,
        Method::POST,
        AuthEndpointOptions::new().allowed_media_types(["application/json"]),
        move |context, request| {
            let options = Arc::clone(&options);
            async move {
                let Some(adapter) = context.adapter() else {
                    return error_response(OAuthProviderError::invalid_request(
                        "database adapter required",
                    ));
                };
                let body: OAuthClient = parse_body(&request)?;
                let current = current_session(&context, adapter.as_ref(), &request).await?;
                let Some((session, user, _)) = current else {
                    return error_response(OAuthProviderError::new(
                        StatusCode::UNAUTHORIZED,
                        "unauthorized",
                        "Unauthorized",
                    ));
                };
                if !has_client_privileges(&options, ClientPrivilegeAction::Create, &user, &session)
                    .await?
                {
                    return client_privileges_error_response();
                }
                let client = match create_oauth_client(
                    &context,
                    adapter.as_ref(),
                    &options,
                    body,
                    CreateOAuthClientInput {
                        is_register: false,
                        user: Some(user),
                        session: Some(session),
                    },
                )
                .await
                {
                    Ok(client) => client,
                    Err(error) => return oauth_validation_error_response(error),
                };
                json_response(StatusCode::CREATED, &client)
            }
        },
    )
}

pub(super) fn get_client_endpoint(options: Arc<ResolvedOAuthProviderOptions>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/oauth2/get-client",
        Method::GET,
        AuthEndpointOptions::new(),
        move |context, request| {
            let options = Arc::clone(&options);
            async move {
                let Some(adapter) = context.adapter() else {
                    return error_response(OAuthProviderError::invalid_request(
                        "database adapter required",
                    ));
                };
                let Some((session, user, _)) =
                    current_session(&context, adapter.as_ref(), &request).await?
                else {
                    return error_response(OAuthProviderError::new(
                        StatusCode::UNAUTHORIZED,
                        "unauthorized",
                        "Unauthorized",
                    ));
                };
                let Some(client_id) = query_param(&request, "client_id") else {
                    return error_response(OAuthProviderError::invalid_client(
                        "client_id is required",
                    ));
                };
                if !has_client_privileges(&options, ClientPrivilegeAction::Read, &user, &session)
                    .await?
                {
                    return client_privileges_error_response();
                }
                let Some(client) =
                    get_client_cached(adapter.as_ref(), &options, &client_id).await?
                else {
                    return error_response(OAuthProviderError::new(
                        StatusCode::NOT_FOUND,
                        "not_found",
                        "client not found",
                    ));
                };
                if !is_client_owner(&client, &user, &session, &options).await? {
                    return client_owner_error_response();
                }
                let mut response = schema_to_oauth(&client);
                response.client_secret = None;
                json_response(StatusCode::OK, &response)
            }
        },
    )
}

async fn is_client_owner(
    client: &crate::models::SchemaClient,
    user: &User,
    session: &Session,
    options: &ResolvedOAuthProviderOptions,
) -> Result<bool, RustAuthError> {
    if client.user_id.as_deref() == Some(user.id.as_str()) {
        return Ok(true);
    }
    if let (Some(client_reference_id), Some(resolver)) = (
        client.reference_id.as_deref(),
        options.client_reference.as_ref(),
    ) {
        return resolver
            .resolve(ClientReferenceInput {
                user: Some(user.clone()),
                session: Some(session.clone()),
            })
            .await
            .map(|reference_id| reference_id.as_deref() == Some(client_reference_id));
    }
    Ok(false)
}

async fn has_client_privileges(
    options: &ResolvedOAuthProviderOptions,
    action: ClientPrivilegeAction,
    user: &User,
    session: &Session,
) -> Result<bool, RustAuthError> {
    let Some(resolver) = &options.client_privileges else {
        return Ok(true);
    };
    resolver
        .resolve(ClientPrivilegesInput {
            action,
            user: Some(user.clone()),
            session: Some(session.clone()),
        })
        .await
}

fn client_privileges_error_response() -> Result<ApiResponse, RustAuthError> {
    error_response(OAuthProviderError::access_denied(
        "client action is not allowed",
    ))
}

fn is_trusted_client(options: &ResolvedOAuthProviderOptions, client_id: &str) -> bool {
    options.cached_trusted_clients.contains(client_id)
}

fn trusted_client_error_response() -> Result<ApiResponse, RustAuthError> {
    error_response(OAuthProviderError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "invalid_client",
        "trusted clients must be updated manually",
    ))
}

fn client_owner_error_response() -> Result<ApiResponse, RustAuthError> {
    error_response(OAuthProviderError::access_denied(
        "client belongs to another user",
    ))
}

pub(super) fn public_client_endpoint(
    path: &'static str,
    options: Arc<ResolvedOAuthProviderOptions>,
) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        path,
        Method::GET,
        AuthEndpointOptions::new(),
        move |context, request| {
            let options = Arc::clone(&options);
            async move {
                let Some(adapter) = context.adapter() else {
                    return error_response(OAuthProviderError::invalid_request(
                        "database adapter required",
                    ));
                };
                let Some(client_id) = query_param(&request, "client_id") else {
                    return error_response(OAuthProviderError::invalid_client(
                        "client_id is required",
                    ));
                };
                let Some(client) =
                    get_client_cached(adapter.as_ref(), &options, &client_id).await?
                else {
                    return error_response(OAuthProviderError::new(
                        StatusCode::NOT_FOUND,
                        "not_found",
                        "client not found",
                    ));
                };
                if client.disabled == Some(true) {
                    return error_response(OAuthProviderError::new(
                        StatusCode::NOT_FOUND,
                        "not_found",
                        "client not found",
                    ));
                }
                let response = json!({
                    "client_id": client.client_id,
                    "client_name": client.name,
                    "client_uri": client.uri,
                    "logo_uri": client.icon,
                    "contacts": client.contacts,
                    "tos_uri": client.tos,
                    "policy_uri": client.policy,
                });
                json_response(StatusCode::OK, &response)
            }
        },
    )
}

pub(super) fn public_client_prelogin_endpoint(
    options: Arc<ResolvedOAuthProviderOptions>,
) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/oauth2/public-client-prelogin",
        Method::POST,
        AuthEndpointOptions::new().allowed_media_types(["application/json"]),
        move |context, request| {
            let options = Arc::clone(&options);
            async move {
                let mut request = request;
                let body: serde_json::Value = parse_body(&request)?;
                if !options.allow_public_client_prelogin {
                    return error_response(OAuthProviderError::invalid_request(
                        "public client prelogin is disabled",
                    ));
                }
                let oauth_query = body
                    .get("oauth_query")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default();
                if !verify_oauth_query(oauth_query, context.secret.as_str())? {
                    return error_response(OAuthProviderError::new(
                        StatusCode::UNAUTHORIZED,
                        "invalid_signature",
                        "invalid oauth_query signature",
                    ));
                }
                let client_id = body
                    .get("client_id")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default();
                let uri = format!("{}?client_id={}", request.uri().path(), client_id);
                *request.uri_mut() = uri.parse().map_err(|error: http::uri::InvalidUri| {
                    RustAuthError::Api(error.to_string())
                })?;
                (public_client_endpoint("/oauth2/public-client-prelogin", options).handler)(
                    &context, request,
                )
                .await
            }
        },
    )
}

fn verify_oauth_query(oauth_query: &str, secret: &str) -> Result<bool, RustAuthError> {
    let mut signature = None;
    let mut expires_at = None;
    let mut unsigned = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in url::form_urlencoded::parse(oauth_query.as_bytes()) {
        if key == "sig" {
            signature = Some(value.into_owned());
            continue;
        }
        if key == "exp" {
            expires_at = value.parse::<i64>().ok();
        }
        unsigned.append_pair(&key, &value);
    }
    let Some(signature) = signature else {
        return Ok(false);
    };
    let Some(expires_at) = expires_at else {
        return Ok(false);
    };
    if expires_at < OffsetDateTime::now_utc().unix_timestamp() {
        return Ok(false);
    }
    let expected = hmac_sha256_base64(&unsigned.finish(), secret)?;
    Ok(constant_time_equal(signature, expected))
}

pub(super) fn get_clients_endpoint(
    options: Arc<ResolvedOAuthProviderOptions>,
) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/oauth2/get-clients",
        Method::GET,
        AuthEndpointOptions::new(),
        move |context, request| {
            let options = Arc::clone(&options);
            async move {
                let Some(adapter) = context.adapter() else {
                    return error_response(OAuthProviderError::invalid_request(
                        "database adapter required",
                    ));
                };
                let Some((session, user, _)) =
                    current_session(&context, adapter.as_ref(), &request).await?
                else {
                    return error_response(OAuthProviderError::new(
                        StatusCode::UNAUTHORIZED,
                        "unauthorized",
                        "Unauthorized",
                    ));
                };
                if !has_client_privileges(&options, ClientPrivilegeAction::List, &user, &session)
                    .await?
                {
                    return client_privileges_error_response();
                }
                let reference_id = match &options.client_reference {
                    Some(resolver) => {
                        resolver
                            .resolve(ClientReferenceInput {
                                user: Some(user.clone()),
                                session: Some(session),
                            })
                            .await?
                    }
                    None => None,
                };
                let (field, value) = match reference_id {
                    Some(reference_id) => ("reference_id", reference_id),
                    None => ("user_id", user.id),
                };
                let clients = adapter
                    .find_many(find_many_by_string(OAUTH_CLIENT_MODEL, field, &value))
                    .await?
                    .into_iter()
                    .map(crate::client::schema_client_from_record)
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .map(|client| {
                        let mut client = schema_to_oauth(&client);
                        client.client_secret = None;
                        client
                    })
                    .collect::<Vec<_>>();
                json_response(StatusCode::OK, &clients)
            }
        },
    )
}

#[derive(Debug, Deserialize)]
struct UpdateClientBody {
    client_id: String,
    update: OAuthClient,
}

pub(super) fn update_client_endpoint(
    path: &'static str,
    options: Arc<ResolvedOAuthProviderOptions>,
) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        path,
        Method::POST,
        AuthEndpointOptions::new().allowed_media_types(["application/json"]),
        move |context, request| {
            let options = Arc::clone(&options);
            async move {
                let Some(adapter) = context.adapter() else {
                    return error_response(OAuthProviderError::invalid_request(
                        "database adapter required",
                    ));
                };
                let Some((session, user, _)) =
                    current_session(&context, adapter.as_ref(), &request).await?
                else {
                    return error_response(OAuthProviderError::new(
                        StatusCode::UNAUTHORIZED,
                        "unauthorized",
                        "Unauthorized",
                    ));
                };
                let body: UpdateClientBody = parse_body(&request)?;
                if is_trusted_client(&options, &body.client_id) {
                    return trusted_client_error_response();
                }
                if !has_client_privileges(&options, ClientPrivilegeAction::Update, &user, &session)
                    .await?
                {
                    return client_privileges_error_response();
                }
                let Some(existing) =
                    get_client_cached(adapter.as_ref(), &options, &body.client_id).await?
                else {
                    return error_response(OAuthProviderError::new(
                        StatusCode::NOT_FOUND,
                        "not_found",
                        "client not found",
                    ));
                };
                if !is_client_owner(&existing, &user, &session, &options).await? {
                    return client_owner_error_response();
                }
                if body.update.token_endpoint_auth_method.is_some() {
                    return error_response(OAuthProviderError::new(
                        StatusCode::BAD_REQUEST,
                        "invalid_client_metadata",
                        "token_endpoint_auth_method is immutable",
                    ));
                }
                let merged = merge_oauth_client_update(&existing, &body.update);
                if let Err(error) = check_oauth_client(&merged, &options, false) {
                    return oauth_validation_error_response(error);
                }
                let mut data = client_update_record(&body.update);
                data.insert(
                    "updated_at".to_owned(),
                    DbValue::Timestamp(crate::utils::now()),
                );
                let Some(client) = update_client(adapter.as_ref(), &body.client_id, data).await?
                else {
                    return error_response(OAuthProviderError::new(
                        StatusCode::NOT_FOUND,
                        "not_found",
                        "client not found",
                    ));
                };
                let mut response = schema_to_oauth(&client);
                response.client_secret = None;
                json_response(StatusCode::OK, &response)
            }
        },
    )
}

fn merge_oauth_client_update(
    existing: &crate::models::SchemaClient,
    update: &OAuthClient,
) -> OAuthClient {
    let mut merged = schema_to_oauth(existing);
    if update.scope.is_some() {
        merged.scope = update.scope.clone();
    }
    if update.client_name.is_some() {
        merged.client_name = update.client_name.clone();
    }
    if update.client_uri.is_some() {
        merged.client_uri = update.client_uri.clone();
    }
    if update.logo_uri.is_some() {
        merged.logo_uri = update.logo_uri.clone();
    }
    if update.contacts.is_some() {
        merged.contacts = update.contacts.clone();
    }
    if update.tos_uri.is_some() {
        merged.tos_uri = update.tos_uri.clone();
    }
    if update.policy_uri.is_some() {
        merged.policy_uri = update.policy_uri.clone();
    }
    if update.software_id.is_some() {
        merged.software_id = update.software_id.clone();
    }
    if update.software_version.is_some() {
        merged.software_version = update.software_version.clone();
    }
    if update.software_statement.is_some() {
        merged.software_statement = update.software_statement.clone();
    }
    if update.redirect_uris.is_some() {
        merged.redirect_uris = update.redirect_uris.clone();
    }
    if update.post_logout_redirect_uris.is_some() {
        merged.post_logout_redirect_uris = update.post_logout_redirect_uris.clone();
    }
    if update.token_endpoint_auth_method.is_some() {
        merged.token_endpoint_auth_method = update.token_endpoint_auth_method.clone();
    }
    if update.grant_types.is_some() {
        merged.grant_types = update.grant_types.clone();
    }
    if update.response_types.is_some() {
        merged.response_types = update.response_types.clone();
    }
    if update.public.is_some() {
        merged.public = update.public;
    }
    if update.client_type.is_some() {
        merged.client_type = update.client_type.clone();
    }
    if update.disabled.is_some() {
        merged.disabled = update.disabled;
    }
    if update.skip_consent.is_some() {
        merged.skip_consent = update.skip_consent;
    }
    if update.enable_end_session.is_some() {
        merged.enable_end_session = update.enable_end_session;
    }
    if update.require_pkce.is_some() {
        merged.require_pkce = update.require_pkce;
    }
    if update.subject_type.is_some() {
        merged.subject_type = update.subject_type.clone();
    }
    if update.reference_id.is_some() {
        merged.reference_id = update.reference_id.clone();
    }
    if update.metadata.is_some() {
        merged.metadata = update.metadata.clone();
    }
    merged
}

fn client_update_record(update: &OAuthClient) -> DbRecord {
    let mut record = DbRecord::new();
    if let Some(scope) = update.scope.as_deref() {
        record.insert(
            "scopes".to_owned(),
            DbValue::StringArray(split_scope(Some(scope))),
        );
    }
    insert_optional_string(&mut record, "name", update.client_name.clone());
    insert_optional_string(&mut record, "uri", update.client_uri.clone());
    insert_optional_string(&mut record, "icon", update.logo_uri.clone());
    insert_optional_string_array(&mut record, "contacts", update.contacts.clone());
    insert_optional_string(&mut record, "tos", update.tos_uri.clone());
    insert_optional_string(&mut record, "policy", update.policy_uri.clone());
    insert_optional_string(&mut record, "software_id", update.software_id.clone());
    insert_optional_string(
        &mut record,
        "software_version",
        update.software_version.clone(),
    );
    insert_optional_string(
        &mut record,
        "software_statement",
        update.software_statement.clone(),
    );
    insert_optional_string_array(&mut record, "redirect_uris", update.redirect_uris.clone());
    insert_optional_string_array(
        &mut record,
        "post_logout_redirect_uris",
        update.post_logout_redirect_uris.clone(),
    );
    insert_optional_string(
        &mut record,
        "token_endpoint_auth_method",
        update.token_endpoint_auth_method.clone(),
    );
    insert_optional_string_array(&mut record, "grant_types", update.grant_types.clone());
    insert_optional_string_array(&mut record, "response_types", update.response_types.clone());
    if let Some(public) = update.public {
        record.insert("public".to_owned(), DbValue::Boolean(public));
    }
    insert_optional_string(&mut record, "type", update.client_type.clone());
    if let Some(disabled) = update.disabled {
        record.insert("disabled".to_owned(), DbValue::Boolean(disabled));
    }
    if let Some(skip_consent) = update.skip_consent {
        record.insert("skip_consent".to_owned(), DbValue::Boolean(skip_consent));
    }
    if let Some(enable_end_session) = update.enable_end_session {
        record.insert(
            "enable_end_session".to_owned(),
            DbValue::Boolean(enable_end_session),
        );
    }
    if let Some(require_pkce) = update.require_pkce {
        record.insert("require_pkce".to_owned(), DbValue::Boolean(require_pkce));
    }
    insert_optional_string(&mut record, "subject_type", update.subject_type.clone());
    insert_optional_string(&mut record, "reference_id", update.reference_id.clone());
    if let Some(metadata) = update.metadata.clone() {
        record.insert("metadata".to_owned(), DbValue::Json(metadata));
    }
    record
}

fn insert_optional_string(record: &mut DbRecord, field: &str, value: Option<String>) {
    if let Some(value) = value {
        record.insert(field.to_owned(), DbValue::String(value));
    }
}

fn insert_optional_string_array(record: &mut DbRecord, field: &str, value: Option<Vec<String>>) {
    if let Some(value) = value {
        record.insert(field.to_owned(), DbValue::StringArray(value));
    }
}

pub(super) fn oauth_validation_error_response(
    error: RustAuthError,
) -> Result<ApiResponse, RustAuthError> {
    let RustAuthError::Api(message) = error else {
        return Err(error);
    };
    let Some((code, description)) = message.split_once(": ") else {
        return Err(RustAuthError::Api(message));
    };
    let error = match code {
        "invalid_scope" => OAuthProviderError::invalid_scope(description.to_owned()),
        "invalid_client_metadata" | "invalid_redirect_uri" => {
            OAuthProviderError::new(StatusCode::BAD_REQUEST, code, description.to_owned())
        }
        "invalid_request" => OAuthProviderError::invalid_request(description.to_owned()),
        "access_denied" => OAuthProviderError::access_denied(description.to_owned()),
        _ => return Err(RustAuthError::Api(message)),
    };
    error_response(error)
}

#[derive(Debug, Deserialize)]
struct ClientIdBody {
    client_id: String,
}

pub(super) fn rotate_secret_endpoint(
    options: Arc<ResolvedOAuthProviderOptions>,
) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/oauth2/client/rotate-secret",
        Method::POST,
        AuthEndpointOptions::new().allowed_media_types(["application/json"]),
        move |context, request| {
            let options = Arc::clone(&options);
            async move {
                let Some(adapter) = context.adapter() else {
                    return error_response(OAuthProviderError::invalid_request(
                        "database adapter required",
                    ));
                };
                let Some((session, user, _)) =
                    current_session(&context, adapter.as_ref(), &request).await?
                else {
                    return error_response(OAuthProviderError::new(
                        StatusCode::UNAUTHORIZED,
                        "unauthorized",
                        "Unauthorized",
                    ));
                };
                let body: ClientIdBody = parse_body(&request)?;
                if is_trusted_client(&options, &body.client_id) {
                    return trusted_client_error_response();
                }
                if !has_client_privileges(&options, ClientPrivilegeAction::Rotate, &user, &session)
                    .await?
                {
                    return client_privileges_error_response();
                }
                let Some(existing) =
                    get_client_cached(adapter.as_ref(), &options, &body.client_id).await?
                else {
                    return error_response(OAuthProviderError::new(
                        StatusCode::NOT_FOUND,
                        "not_found",
                        "client not found",
                    ));
                };
                if !is_client_owner(&existing, &user, &session, &options).await? {
                    return client_owner_error_response();
                }
                if existing.public == Some(true) || existing.client_secret.is_none() {
                    return error_response(OAuthProviderError::invalid_client(
                        "public clients cannot rotate secrets",
                    ));
                }
                let raw_secret = match &options.generate_client_secret {
                    Some(generator) => generator.generate().await?,
                    None => crate::utils::random_string(32),
                };
                let stored =
                    crate::token::store_client_secret(&context, &options, &raw_secret).await?;
                let mut data = DbRecord::new();
                data.insert("client_secret".to_owned(), DbValue::String(stored));
                data.insert(
                    "updated_at".to_owned(),
                    DbValue::Timestamp(crate::utils::now()),
                );
                let Some(client) = update_client(adapter.as_ref(), &body.client_id, data).await?
                else {
                    return error_response(OAuthProviderError::new(
                        StatusCode::NOT_FOUND,
                        "not_found",
                        "client not found",
                    ));
                };
                let mut response = schema_to_oauth(&client);
                response.client_secret = Some(add_prefix(
                    options.prefixes.client_secret.as_deref(),
                    raw_secret,
                ));
                json_response(StatusCode::OK, &response)
            }
        },
    )
}

pub(super) fn delete_client_endpoint(
    options: Arc<ResolvedOAuthProviderOptions>,
) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/oauth2/delete-client",
        Method::POST,
        AuthEndpointOptions::new().allowed_media_types(["application/json"]),
        move |context, request| {
            let options = Arc::clone(&options);
            async move {
                let Some(adapter) = context.adapter() else {
                    return error_response(OAuthProviderError::invalid_request(
                        "database adapter required",
                    ));
                };
                let Some((session, user, _)) =
                    current_session(&context, adapter.as_ref(), &request).await?
                else {
                    return error_response(OAuthProviderError::new(
                        StatusCode::UNAUTHORIZED,
                        "unauthorized",
                        "Unauthorized",
                    ));
                };
                let body: ClientIdBody = parse_body(&request)?;
                if is_trusted_client(&options, &body.client_id) {
                    return trusted_client_error_response();
                }
                if !has_client_privileges(&options, ClientPrivilegeAction::Delete, &user, &session)
                    .await?
                {
                    return client_privileges_error_response();
                }
                let Some(existing) =
                    get_client_cached(adapter.as_ref(), &options, &body.client_id).await?
                else {
                    return error_response(OAuthProviderError::new(
                        StatusCode::NOT_FOUND,
                        "not_found",
                        "client not found",
                    ));
                };
                if !is_client_owner(&existing, &user, &session, &options).await? {
                    return client_owner_error_response();
                }
                adapter
                    .delete(crate::utils::delete_by_string(
                        OAUTH_CLIENT_MODEL,
                        "client_id",
                        &body.client_id,
                    ))
                    .await?;
                no_content()
            }
        },
    )
}

fn add_prefix(prefix: Option<&str>, value: String) -> String {
    match prefix {
        Some(prefix) => format!("{prefix}{value}"),
        None => value,
    }
}
