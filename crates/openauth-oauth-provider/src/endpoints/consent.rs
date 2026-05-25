use super::*;

pub(super) fn consent_endpoint(options: Arc<ResolvedOAuthProviderOptions>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/oauth2/consent",
        Method::POST,
        AuthEndpointOptions::new().allowed_media_types(["application/json"]),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                let Some(adapter) = context.adapter() else {
                    return error_response(OAuthProviderError::invalid_request(
                        "database adapter required",
                    ));
                };
                let body: ConsentDecisionBody = parse_body(&request)?;
                let Some(mut pending) =
                    load_pending_authorization(adapter.as_ref(), &options, &body.request_id)
                        .await?
                else {
                    return error_response(OAuthProviderError::invalid_request(
                        "authorization request is missing or expired",
                    ));
                };
                if pending.step != PendingAuthorizationStep::Consent {
                    return error_response(OAuthProviderError::invalid_request(
                        "authorization request is not waiting for consent",
                    ));
                }
                let Some((_, user, _)) =
                    current_session(context, adapter.as_ref(), &request).await?
                else {
                    return error_response(OAuthProviderError::new(
                        StatusCode::UNAUTHORIZED,
                        "unauthorized",
                        "Unauthorized",
                    ));
                };
                if user.id != pending.authorization.user_id {
                    return error_response(OAuthProviderError::access_denied(
                        "authorization request belongs to another user",
                    ));
                }
                if !body.accept {
                    delete_pending_authorization(adapter.as_ref(), &options, &body.request_id)
                        .await?;
                    let redirect_uri =
                        pending
                            .authorization
                            .redirect_uri
                            .as_deref()
                            .ok_or_else(|| {
                                OpenAuthError::Api(
                                    "authorization redirect_uri is required".to_owned(),
                                )
                            })?;
                    return authorization_error_redirect(
                        redirect_uri,
                        "access_denied",
                        "End-User denied the authorization request",
                        pending.state.as_deref(),
                        &context.base_url,
                    );
                }
                let accepted_scopes = match accepted_consent_scopes(
                    body.scope.as_deref(),
                    &pending.authorization.scopes,
                ) {
                    Ok(scopes) => scopes,
                    Err(error) => return error_response(error),
                };
                pending.authorization.scopes = accepted_scopes;
                delete_pending_authorization(adapter.as_ref(), &options, &body.request_id).await?;
                upsert_consent(
                    adapter.as_ref(),
                    ConsentGrantInput {
                        client_id: pending.authorization.client_id.clone(),
                        user_id: Some(user.id),
                        reference_id: pending.authorization.reference_id.clone(),
                        scopes: pending.authorization.scopes.clone(),
                    },
                )
                .await?;
                issue_authorization_code_redirect(
                    context,
                    adapter.as_ref(),
                    &options,
                    pending.authorization,
                    pending.state.as_deref(),
                )
                .await
            })
        },
    )
}

pub(super) fn continue_endpoint(
    method: Method,
    options: Arc<ResolvedOAuthProviderOptions>,
) -> AsyncAuthEndpoint {
    let endpoint_options = if method == Method::POST {
        AuthEndpointOptions::new().allowed_media_types(["application/json"])
    } else {
        AuthEndpointOptions::new()
    };
    create_auth_endpoint(
        "/oauth2/continue",
        method.clone(),
        endpoint_options,
        move |context, request| {
            let options = Arc::clone(&options);
            let method = method.clone();
            Box::pin(async move {
                let Some(adapter) = context.adapter() else {
                    return error_response(OAuthProviderError::invalid_request(
                        "database adapter required",
                    ));
                };
                let input = match continue_input(&request, &method) {
                    Ok(input) => input,
                    Err(error) => return error_response(error),
                };
                let Some(request_id) = input.request_id.as_deref() else {
                    return error_response(OAuthProviderError::invalid_request(
                        "request_id is required",
                    ));
                };
                let Some(requested_step) = input.requested_step else {
                    return error_response(OAuthProviderError::invalid_request(
                        "Missing parameters",
                    ));
                };
                let Some(pending) =
                    load_pending_authorization(adapter.as_ref(), &options, request_id).await?
                else {
                    return error_response(OAuthProviderError::invalid_request(
                        "authorization request is missing or expired",
                    ));
                };
                let Some((_, user, _)) =
                    current_session(context, adapter.as_ref(), &request).await?
                else {
                    return error_response(OAuthProviderError::new(
                        StatusCode::UNAUTHORIZED,
                        "unauthorized",
                        "Unauthorized",
                    ));
                };
                if user.id != pending.authorization.user_id {
                    return error_response(OAuthProviderError::access_denied(
                        "authorization request belongs to another user",
                    ));
                }
                if pending.step != requested_step {
                    return error_response(OAuthProviderError::invalid_request(
                        "authorization request step mismatch",
                    ));
                }
                delete_pending_authorization(adapter.as_ref(), &options, request_id).await?;
                resume_pending_authorization(context, adapter.as_ref(), &options, pending, &user)
                    .await
            })
        },
    )
}

#[derive(Debug, Deserialize)]
struct ContinueBody {
    request_id: Option<String>,
    selected: Option<bool>,
    created: Option<bool>,
    #[serde(default, rename = "postLogin", alias = "post_login")]
    post_login: Option<bool>,
}

struct ContinueInput {
    request_id: Option<String>,
    requested_step: Option<PendingAuthorizationStep>,
}

fn continue_input(
    request: &ApiRequest,
    method: &Method,
) -> Result<ContinueInput, OAuthProviderError> {
    let body = if method == Method::POST {
        parse_body::<ContinueBody>(request)
            .map_err(|error| OAuthProviderError::invalid_request(error.to_string()))?
    } else {
        ContinueBody {
            request_id: query_param(request, "request_id"),
            selected: query_bool(request, "selected"),
            created: query_bool(request, "created"),
            post_login: query_bool(request, "postLogin")
                .or_else(|| query_bool(request, "post_login")),
        }
    };
    Ok(ContinueInput {
        request_id: body.request_id,
        requested_step: if body.selected == Some(true) {
            Some(PendingAuthorizationStep::SelectAccount)
        } else if body.created == Some(true) {
            Some(PendingAuthorizationStep::Create)
        } else if body.post_login == Some(true) {
            Some(PendingAuthorizationStep::PostLogin)
        } else {
            None
        },
    })
}

fn query_bool(request: &ApiRequest, name: &str) -> Option<bool> {
    query_param(request, name).and_then(|value| match value.as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    })
}

async fn resume_pending_authorization(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    pending: PendingAuthorizationValue,
    user: &User,
) -> Result<ApiResponse, OpenAuthError> {
    let Some(client) =
        get_client_cached(adapter, options, &pending.authorization.client_id).await?
    else {
        return error_response(OAuthProviderError::invalid_client("client_id is required"));
    };
    let prompt = prompt_after_continue(&pending);
    match decide_authorize(
        adapter,
        &client,
        Some(user.id.as_str()),
        &pending.authorization.scopes,
        prompt.as_deref(),
    )
    .await?
    {
        AuthorizeDecision::IssueCode => {
            issue_authorization_code_redirect(
                context,
                adapter,
                options,
                pending.authorization,
                pending.state.as_deref(),
            )
            .await
        }
        AuthorizeDecision::RedirectToConsent => {
            let request_id = store_pending_authorization(
                adapter,
                options,
                PendingAuthorizationValue {
                    step: PendingAuthorizationStep::Consent,
                    ..pending
                },
            )
            .await?;
            redirect_response(&page_redirect_with_request_id(
                &options.consent_page,
                &request_id,
                &context.base_url,
            )?)
        }
        AuthorizeDecision::RedirectToLogin => redirect_response(&options.login_page),
        AuthorizeDecision::RedirectError { error, description } => {
            let redirect_uri = pending
                .authorization
                .redirect_uri
                .as_deref()
                .ok_or_else(|| {
                    OpenAuthError::Api("authorization redirect_uri is required".to_owned())
                })?;
            authorization_error_redirect(
                redirect_uri,
                error,
                description,
                pending.state.as_deref(),
                &context.base_url,
            )
        }
    }
}

fn prompt_after_continue(pending: &PendingAuthorizationValue) -> Option<String> {
    let prompt = pending
        .original_query
        .iter()
        .find_map(|(key, value)| (key == "prompt").then_some(value.as_str()))?;
    let remove = match pending.step {
        PendingAuthorizationStep::Create => "create",
        PendingAuthorizationStep::SelectAccount => "select_account",
        PendingAuthorizationStep::PostLogin | PendingAuthorizationStep::Consent => "",
    };
    let prompts = prompt
        .split_whitespace()
        .filter(|value| !value.is_empty() && *value != remove)
        .collect::<Vec<_>>();
    (!prompts.is_empty()).then(|| prompts.join(" "))
}

#[derive(Debug, Deserialize)]
struct ConsentDecisionBody {
    request_id: String,
    accept: bool,
    scope: Option<String>,
}

fn accepted_consent_scopes(
    accepted_scope: Option<&str>,
    originally_requested: &[String],
) -> Result<Vec<String>, OAuthProviderError> {
    let Some(accepted_scope) = accepted_scope else {
        return Ok(originally_requested.to_vec());
    };
    let accepted = split_scope(Some(accepted_scope));
    if accepted.is_empty()
        || accepted.iter().any(|scope| {
            !originally_requested
                .iter()
                .any(|requested| requested == scope)
        })
    {
        return Err(OAuthProviderError::invalid_request(
            "Scope not originally requested",
        ));
    }
    Ok(accepted)
}

pub(super) fn get_consent_endpoint(
    options: Arc<ResolvedOAuthProviderOptions>,
) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/oauth2/get-consent",
        Method::GET,
        AuthEndpointOptions::new(),
        move |context, request| {
            let _options = Arc::clone(&options);
            Box::pin(async move {
                let Some(adapter) = context.adapter() else {
                    return error_response(OAuthProviderError::invalid_request(
                        "database adapter required",
                    ));
                };
                let Some((_, user, _)) =
                    current_session(context, adapter.as_ref(), &request).await?
                else {
                    return error_response(OAuthProviderError::new(
                        StatusCode::UNAUTHORIZED,
                        "unauthorized",
                        "Unauthorized",
                    ));
                };
                let Some(id) = query_param(&request, "id") else {
                    return error_response(OAuthProviderError::new(
                        StatusCode::NOT_FOUND,
                        "not_found",
                        "missing id parameter",
                    ));
                };
                match adapter
                    .find_one(find_by_string(OAUTH_CONSENT_MODEL, "id", &id))
                    .await?
                {
                    Some(record) => {
                        let consent = consent_from_record(record.clone())?;
                        if consent.user_id.as_deref() != Some(user.id.as_str()) {
                            return consent_owner_error_response();
                        }
                        json_response(StatusCode::OK, &record_to_json(record))
                    }
                    None => error_response(OAuthProviderError::new(
                        StatusCode::NOT_FOUND,
                        "not_found",
                        "no consent",
                    )),
                }
            })
        },
    )
}

pub(super) fn get_consents_endpoint(
    options: Arc<ResolvedOAuthProviderOptions>,
) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/oauth2/get-consents",
        Method::GET,
        AuthEndpointOptions::new(),
        move |context, request| {
            let _options = Arc::clone(&options);
            Box::pin(async move {
                let Some(adapter) = context.adapter() else {
                    return error_response(OAuthProviderError::invalid_request(
                        "database adapter required",
                    ));
                };
                let Some((_, user, _)) =
                    current_session(context, adapter.as_ref(), &request).await?
                else {
                    return error_response(OAuthProviderError::new(
                        StatusCode::UNAUTHORIZED,
                        "unauthorized",
                        "Unauthorized",
                    ));
                };
                let records = adapter
                    .find_many(find_many_by_string(
                        OAUTH_CONSENT_MODEL,
                        "user_id",
                        &user.id,
                    ))
                    .await?;
                json_response(
                    StatusCode::OK,
                    &records.into_iter().map(record_to_json).collect::<Vec<_>>(),
                )
            })
        },
    )
}

#[derive(Debug, Deserialize)]
struct ConsentIdBody {
    id: String,
    update: Option<serde_json::Value>,
}

pub(super) fn update_consent_endpoint(
    options: Arc<ResolvedOAuthProviderOptions>,
) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/oauth2/update-consent",
        Method::POST,
        AuthEndpointOptions::new().allowed_media_types(["application/json"]),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                let Some(adapter) = context.adapter() else {
                    return error_response(OAuthProviderError::invalid_request(
                        "database adapter required",
                    ));
                };
                let Some((_, user, _)) =
                    current_session(context, adapter.as_ref(), &request).await?
                else {
                    return error_response(OAuthProviderError::new(
                        StatusCode::UNAUTHORIZED,
                        "unauthorized",
                        "Unauthorized",
                    ));
                };
                let body: ConsentIdBody = parse_body(&request)?;
                let Some(existing) = adapter
                    .find_one(find_by_string(OAUTH_CONSENT_MODEL, "id", &body.id))
                    .await?
                else {
                    return error_response(OAuthProviderError::new(
                        StatusCode::NOT_FOUND,
                        "not_found",
                        "no consent",
                    ));
                };
                let consent = consent_from_record(existing)?;
                if consent.user_id.as_deref() != Some(user.id.as_str()) {
                    return consent_owner_error_response();
                }
                let scopes = parse_consent_scope_update(body.update.as_ref())?;
                if let Some(scopes) = scopes.as_ref() {
                    let allowed_scopes =
                        get_client_cached(adapter.as_ref(), &options, &consent.client_id)
                            .await?
                            .and_then(|client| client.scopes)
                            .unwrap_or_else(|| options.scopes.clone());
                    if !scopes
                        .iter()
                        .all(|scope| allowed_scopes.iter().any(|allowed| allowed == scope))
                    {
                        return error_response(OAuthProviderError::invalid_scope(
                            "requested scopes are not allowed for this client",
                        ));
                    }
                }
                let mut data = DbRecord::new();
                if let Some(scopes) = scopes {
                    data.insert("scopes".to_owned(), DbValue::StringArray(scopes));
                }
                data.insert(
                    "updated_at".to_owned(),
                    DbValue::Timestamp(crate::utils::now()),
                );
                match adapter
                    .update(update_by_string(OAUTH_CONSENT_MODEL, "id", &body.id, data))
                    .await?
                {
                    Some(record) => json_response(StatusCode::OK, &record_to_json(record)),
                    None => error_response(OAuthProviderError::new(
                        StatusCode::NOT_FOUND,
                        "not_found",
                        "no consent",
                    )),
                }
            })
        },
    )
}

pub(super) fn delete_consent_endpoint(
    options: Arc<ResolvedOAuthProviderOptions>,
) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/oauth2/delete-consent",
        Method::POST,
        AuthEndpointOptions::new().allowed_media_types(["application/json"]),
        move |context, request| {
            let _options = Arc::clone(&options);
            Box::pin(async move {
                let Some(adapter) = context.adapter() else {
                    return error_response(OAuthProviderError::invalid_request(
                        "database adapter required",
                    ));
                };
                let Some((_, user, _)) =
                    current_session(context, adapter.as_ref(), &request).await?
                else {
                    return error_response(OAuthProviderError::new(
                        StatusCode::UNAUTHORIZED,
                        "unauthorized",
                        "Unauthorized",
                    ));
                };
                let body: ConsentIdBody = parse_body(&request)?;
                let Some(existing) = adapter
                    .find_one(find_by_string(OAUTH_CONSENT_MODEL, "id", &body.id))
                    .await?
                else {
                    return error_response(OAuthProviderError::new(
                        StatusCode::NOT_FOUND,
                        "not_found",
                        "no consent",
                    ));
                };
                let consent = consent_from_record(existing)?;
                if consent.user_id.as_deref() != Some(user.id.as_str()) {
                    return consent_owner_error_response();
                }
                adapter
                    .delete(crate::utils::delete_by_string(
                        OAUTH_CONSENT_MODEL,
                        "id",
                        &body.id,
                    ))
                    .await?;
                no_content()
            })
        },
    )
}

fn consent_owner_error_response() -> Result<ApiResponse, OpenAuthError> {
    error_response(OAuthProviderError::access_denied(
        "consent belongs to another user",
    ))
}

fn parse_consent_scope_update(
    update: Option<&serde_json::Value>,
) -> Result<Option<Vec<String>>, OpenAuthError> {
    let Some(scopes) = update.and_then(|value| value.get("scopes")) else {
        return Ok(None);
    };
    serde_json::from_value(scopes.clone())
        .map(Some)
        .map_err(|error| OpenAuthError::Api(error.to_string()))
}

fn record_to_json(record: DbRecord) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for (key, value) in record {
        map.insert(key, db_value_to_json(value));
    }
    serde_json::Value::Object(map)
}

fn db_value_to_json(value: DbValue) -> serde_json::Value {
    match value {
        DbValue::String(value) => serde_json::Value::String(value),
        DbValue::Number(value) => serde_json::Value::Number(value.into()),
        DbValue::Boolean(value) => serde_json::Value::Bool(value),
        DbValue::Timestamp(value) => serde_json::Value::Number(value.unix_timestamp().into()),
        DbValue::Json(value) => value,
        DbValue::StringArray(values) => values.into_iter().map(serde_json::Value::String).collect(),
        DbValue::NumberArray(values) => values
            .into_iter()
            .map(|value| serde_json::Value::Number(value.into()))
            .collect(),
        DbValue::Record(record) => record_to_json(record),
        DbValue::RecordArray(records) => records.into_iter().map(record_to_json).collect(),
        DbValue::Null => serde_json::Value::Null,
    }
}
