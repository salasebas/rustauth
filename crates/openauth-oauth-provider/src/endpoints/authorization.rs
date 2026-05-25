use serde::Serialize;

use super::*;

async fn resolve_request_uri_request(
    options: &ResolvedOAuthProviderOptions,
    base_url: &str,
    mut request: ApiRequest,
) -> Result<ApiRequest, OAuthProviderError> {
    let Some(request_uri) = query_param(&request, "request_uri") else {
        return Ok(request);
    };
    let Some(resolver) = &options.request_uri_resolver else {
        return Err(OAuthProviderError::invalid_request(
            "request_uri not supported",
        ));
    };
    let url_client_id = query_param(&request, "client_id");
    let Some(params) = resolver
        .resolve(RequestUriResolverInput {
            request_uri,
            client_id: url_client_id.clone(),
        })
        .await
        .map_err(|error| OAuthProviderError::invalid_request(error.to_string()))?
    else {
        return Err(OAuthProviderError::invalid_request(
            "request_uri is invalid or expired",
        ));
    };
    let mut url = request_url(&request, base_url)?;
    url.query_pairs_mut().clear();
    {
        let mut pairs = url.query_pairs_mut();
        let mut resolved_client_id = None;
        for (key, value) in params {
            if key == "client_id" {
                resolved_client_id = Some(value);
                continue;
            }
            pairs.append_pair(&key, &value);
        }
        match (url_client_id, resolved_client_id) {
            (Some(query_client_id), Some(resolved_client_id))
                if query_client_id != resolved_client_id =>
            {
                return Err(OAuthProviderError::invalid_request(
                    "request_uri client_id mismatch",
                ));
            }
            (Some(client_id), _) | (None, Some(client_id)) => {
                pairs.append_pair("client_id", &client_id);
            }
            (None, None) => {}
        }
    }
    *request.uri_mut() = url
        .as_str()
        .parse()
        .map_err(|error: http::uri::InvalidUri| {
            OAuthProviderError::invalid_request(error.to_string())
        })?;
    Ok(request)
}

fn request_url(request: &ApiRequest, base_url: &str) -> Result<url::Url, OAuthProviderError> {
    let uri = request.uri().to_string();
    match url::Url::parse(&uri) {
        Ok(url) => Ok(url),
        Err(url::ParseError::RelativeUrlWithoutBase) => {
            let base = url::Url::parse(base_url)
                .map_err(|error| OAuthProviderError::invalid_request(error.to_string()))?;
            base.join(&uri)
                .map_err(|error| OAuthProviderError::invalid_request(error.to_string()))
        }
        Err(error) => Err(OAuthProviderError::invalid_request(error.to_string())),
    }
}

pub(super) fn authorize_endpoint(options: Arc<ResolvedOAuthProviderOptions>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/oauth2/authorize",
        Method::GET,
        AuthEndpointOptions::new(),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                if !options.grant_types.contains(&GrantType::AuthorizationCode) {
                    return error_response(OAuthProviderError::new(
                        StatusCode::NOT_FOUND,
                        "not_found",
                        "authorization_code disabled",
                    ));
                };
                let Some(adapter) = context.adapter() else {
                    return error_response(OAuthProviderError::invalid_request(
                        "database adapter required",
                    ));
                };
                let request =
                    match resolve_request_uri_request(&options, &context.base_url, request).await {
                        Ok(request) => request,
                        Err(error) => return error_response(error),
                    };
                let client_id = match query_param(&request, "client_id") {
                    Some(value) => value,
                    None => {
                        return error_response(OAuthProviderError::invalid_client(
                            "client_id is required",
                        ))
                    }
                };
                let response_type = query_param(&request, "response_type").unwrap_or_default();
                if response_type != "code" {
                    return error_response(OAuthProviderError::new(
                        StatusCode::BAD_REQUEST,
                        "unsupported_response_type",
                        "unsupported response type",
                    ));
                };
                let Some(client) =
                    get_client_cached(adapter.as_ref(), &options, &client_id).await?
                else {
                    return error_response(OAuthProviderError::invalid_client(
                        "client_id is required",
                    ));
                };
                if client.disabled == Some(true) {
                    return error_response(OAuthProviderError::invalid_client(
                        "client is disabled",
                    ));
                };
                let is_public_client = client.public == Some(true)
                    || client.token_endpoint_auth_method.as_deref() == Some("none")
                    || matches!(
                        client.client_type.as_deref(),
                        Some("native" | "user-agent-based")
                    );
                let code_challenge = query_param(&request, "code_challenge");
                let code_challenge_method = query_param(&request, "code_challenge_method");
                let redirect_uri = query_param(&request, "redirect_uri")
                    .or_else(|| client.redirect_uris.first().cloned())
                    .unwrap_or_default();
                if redirect_uri.is_empty()
                    || !client.redirect_uris.iter().any(|uri| {
                        uri == &redirect_uri || is_loopback_redirect_match(uri, &redirect_uri)
                    })
                {
                    return error_response(OAuthProviderError::invalid_request(
                        "redirect_uri mismatch",
                    ));
                };
                let requested_scopes =
                    crate::utils::split_scope(query_param(&request, "scope").as_deref());
                let scopes = if requested_scopes.is_empty() {
                    client
                        .scopes
                        .clone()
                        .unwrap_or_else(|| options.scopes.clone())
                } else {
                    requested_scopes
                };
                if let Err(error) = validate_requested_scopes(&client, &options, &scopes) {
                    return error_response(error);
                }
                if let Some(reason) = pkce_required_reason(&client, &scopes, is_public_client) {
                    if code_challenge.is_none() || code_challenge_method.is_none() {
                        return error_response(OAuthProviderError::invalid_request(reason));
                    }
                }
                if code_challenge.is_some() != code_challenge_method.is_some() {
                    return error_response(OAuthProviderError::invalid_request(
                        "code_challenge and code_challenge_method must both be provided",
                    ));
                }
                if let Some(method) = code_challenge_method.as_deref() {
                    if method != "S256" {
                        return error_response(OAuthProviderError::invalid_request(
                            "invalid code_challenge method, only S256 is supported",
                        ));
                    }
                };
                let state = query_param(&request, "state");
                let nonce = query_param(&request, "nonce");
                let prompt = query_param(&request, "prompt");
                if let Some((error, description)) = prompt_validation_error(prompt.as_deref()) {
                    return authorization_error_redirect(
                        &redirect_uri,
                        error,
                        description,
                        state.as_deref(),
                        &context.base_url,
                    );
                }
                let current_session = current_session(context, adapter.as_ref(), &request).await?;
                if prompt_contains(&request, "create") {
                    let mut signup_page = options.signup_page.clone();
                    if let Some((session, user, _)) = current_session.as_ref() {
                        if let Some(resolver) = &options.signup_redirect {
                            signup_page = resolver
                                .resolve(PromptRedirectInput {
                                    user: user.clone(),
                                    session: session.clone(),
                                    scopes: scopes.clone(),
                                })
                                .await?
                                .or(signup_page);
                        }
                        let signup_page = signup_page.unwrap_or_else(|| options.login_page.clone());
                        let request_id = store_pending_authorization(
                            adapter.as_ref(),
                            &options,
                            pending_authorization_value(
                                authorization_value(AuthorizationValueInput {
                                    client: &client,
                                    redirect_uri: &redirect_uri,
                                    scopes: &scopes,
                                    user,
                                    session,
                                    nonce: nonce.clone(),
                                    code_challenge: code_challenge.clone(),
                                    code_challenge_method: code_challenge_method.clone(),
                                }),
                                state.clone(),
                                PendingAuthorizationStep::Create,
                                &request,
                            ),
                        )
                        .await?;
                        return redirect_response(&page_redirect_with_request_id(
                            &signup_page,
                            &request_id,
                            &context.base_url,
                        )?);
                    }
                    let signup_page = signup_page.unwrap_or_else(|| options.login_page.clone());
                    return redirect_response(&page_redirect_with_authorize_query(
                        &signup_page,
                        &request,
                        &context.base_url,
                    )?);
                }
                if prompt_contains(&request, "select_account") {
                    let mut select_account_page = options.select_account_page.clone();
                    if let Some((session, user, _)) = current_session.as_ref() {
                        if let Some(resolver) = &options.select_account_redirect {
                            select_account_page = resolver
                                .resolve(PromptRedirectInput {
                                    user: user.clone(),
                                    session: session.clone(),
                                    scopes: scopes.clone(),
                                })
                                .await?
                                .or(select_account_page);
                        }
                        let select_account_page =
                            select_account_page.unwrap_or_else(|| options.login_page.clone());
                        let request_id = store_pending_authorization(
                            adapter.as_ref(),
                            &options,
                            pending_authorization_value(
                                authorization_value(AuthorizationValueInput {
                                    client: &client,
                                    redirect_uri: &redirect_uri,
                                    scopes: &scopes,
                                    user,
                                    session,
                                    nonce: nonce.clone(),
                                    code_challenge: code_challenge.clone(),
                                    code_challenge_method: code_challenge_method.clone(),
                                }),
                                state.clone(),
                                PendingAuthorizationStep::SelectAccount,
                                &request,
                            ),
                        )
                        .await?;
                        return redirect_response(&page_redirect_with_request_id(
                            &select_account_page,
                            &request_id,
                            &context.base_url,
                        )?);
                    }
                    let select_account_page =
                        select_account_page.unwrap_or_else(|| options.login_page.clone());
                    return redirect_response(&page_redirect_with_authorize_query(
                        &select_account_page,
                        &request,
                        &context.base_url,
                    )?);
                }
                if let Some((session, user, _)) = current_session.as_ref() {
                    let post_login_page = match &options.post_login_redirect {
                        Some(resolver) => {
                            resolver
                                .resolve(PromptRedirectInput {
                                    user: user.clone(),
                                    session: session.clone(),
                                    scopes: scopes.clone(),
                                })
                                .await?
                        }
                        None => options.post_login_page.clone(),
                    };
                    let Some(post_login_page) = post_login_page else {
                        let session_user_id = current_session
                            .as_ref()
                            .map(|(_, user, _)| user.id.as_str());
                        if session_exceeds_max_age(
                            &request,
                            current_session.as_ref().map(|(session, _, _)| session),
                        ) {
                            if prompt_contains(&request, "none") {
                                return authorization_error_redirect(
                                    &redirect_uri,
                                    "login_required",
                                    "authentication required",
                                    state.as_deref(),
                                    &context.base_url,
                                );
                            }
                            return redirect_response(&options.login_page);
                        }
                        match decide_authorize(
                            adapter.as_ref(),
                            &client,
                            session_user_id,
                            &scopes,
                            prompt.as_deref(),
                        )
                        .await?
                        {
                            AuthorizeDecision::IssueCode => {}
                            AuthorizeDecision::RedirectToLogin => {
                                return redirect_response(&options.login_page);
                            }
                            AuthorizeDecision::RedirectToConsent => {
                                let request_id = store_pending_authorization(
                                    adapter.as_ref(),
                                    &options,
                                    pending_authorization_value(
                                        authorization_value(AuthorizationValueInput {
                                            client: &client,
                                            redirect_uri: &redirect_uri,
                                            scopes: &scopes,
                                            user,
                                            session,
                                            nonce: nonce.clone(),
                                            code_challenge: code_challenge.clone(),
                                            code_challenge_method: code_challenge_method.clone(),
                                        }),
                                        state.clone(),
                                        PendingAuthorizationStep::Consent,
                                        &request,
                                    ),
                                )
                                .await?;
                                return redirect_response(&page_redirect_with_request_id(
                                    &options.consent_page,
                                    &request_id,
                                    &context.base_url,
                                )?);
                            }
                            AuthorizeDecision::RedirectError { error, description } => {
                                return authorization_error_redirect(
                                    &redirect_uri,
                                    error,
                                    description,
                                    state.as_deref(),
                                    &context.base_url,
                                );
                            }
                        };
                        let value = authorization_value(AuthorizationValueInput {
                            client: &client,
                            redirect_uri: &redirect_uri,
                            scopes: &scopes,
                            user,
                            session,
                            nonce,
                            code_challenge,
                            code_challenge_method,
                        });
                        return issue_authorization_code_redirect(
                            context,
                            adapter.as_ref(),
                            &options,
                            value,
                            state.as_deref(),
                        )
                        .await;
                    };
                    let request_id = store_pending_authorization(
                        adapter.as_ref(),
                        &options,
                        pending_authorization_value(
                            authorization_value(AuthorizationValueInput {
                                client: &client,
                                redirect_uri: &redirect_uri,
                                scopes: &scopes,
                                user,
                                session,
                                nonce: nonce.clone(),
                                code_challenge: code_challenge.clone(),
                                code_challenge_method: code_challenge_method.clone(),
                            }),
                            state.clone(),
                            PendingAuthorizationStep::PostLogin,
                            &request,
                        ),
                    )
                    .await?;
                    return redirect_response(&page_redirect_with_request_id(
                        &post_login_page,
                        &request_id,
                        &context.base_url,
                    )?);
                }
                let session_user_id = current_session
                    .as_ref()
                    .map(|(_, user, _)| user.id.as_str());
                if session_exceeds_max_age(
                    &request,
                    current_session.as_ref().map(|(session, _, _)| session),
                ) {
                    if prompt.as_deref().is_some_and(|prompt| {
                        prompt.split_whitespace().any(|value| value == "none")
                    }) {
                        return authorization_error_redirect(
                            &redirect_uri,
                            "login_required",
                            "authentication required",
                            state.as_deref(),
                            &context.base_url,
                        );
                    }
                    return redirect_response(&options.login_page);
                }
                match decide_authorize(
                    adapter.as_ref(),
                    &client,
                    session_user_id,
                    &scopes,
                    prompt.as_deref(),
                )
                .await?
                {
                    AuthorizeDecision::IssueCode => {}
                    AuthorizeDecision::RedirectToLogin => {
                        return redirect_response(&options.login_page);
                    }
                    AuthorizeDecision::RedirectToConsent => {
                        let Some((session, user, _)) = current_session.as_ref() else {
                            return redirect_response(&options.login_page);
                        };
                        let request_id = store_pending_authorization(
                            adapter.as_ref(),
                            &options,
                            pending_authorization_value(
                                authorization_value(AuthorizationValueInput {
                                    client: &client,
                                    redirect_uri: &redirect_uri,
                                    scopes: &scopes,
                                    user,
                                    session,
                                    nonce: nonce.clone(),
                                    code_challenge: code_challenge.clone(),
                                    code_challenge_method: code_challenge_method.clone(),
                                }),
                                state.clone(),
                                PendingAuthorizationStep::Consent,
                                &request,
                            ),
                        )
                        .await?;
                        return redirect_response(&page_redirect_with_request_id(
                            &options.consent_page,
                            &request_id,
                            &context.base_url,
                        )?);
                    }
                    AuthorizeDecision::RedirectError { error, description } => {
                        return authorization_error_redirect(
                            &redirect_uri,
                            error,
                            description,
                            state.as_deref(),
                            &context.base_url,
                        );
                    }
                };
                let Some((session, user, _)) = current_session else {
                    return redirect_response(&options.login_page);
                };
                let value = authorization_value(AuthorizationValueInput {
                    client: &client,
                    redirect_uri: &redirect_uri,
                    scopes: &scopes,
                    user: &user,
                    session: &session,
                    nonce,
                    code_challenge,
                    code_challenge_method,
                });
                issue_authorization_code_redirect(
                    context,
                    adapter.as_ref(),
                    &options,
                    value,
                    state.as_deref(),
                )
                .await
            })
        },
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct PendingAuthorizationValue {
    pub(super) authorization: AuthorizationCodeValue,
    pub(super) state: Option<String>,
    #[serde(default = "default_pending_authorization_step")]
    pub(super) step: PendingAuthorizationStep,
    #[serde(default)]
    pub(super) original_query: Vec<(String, String)>,
    #[serde(default)]
    pub(super) auth_time: Option<OffsetDateTime>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum PendingAuthorizationStep {
    Consent,
    Create,
    SelectAccount,
    PostLogin,
}

pub(super) fn default_pending_authorization_step() -> PendingAuthorizationStep {
    PendingAuthorizationStep::Consent
}

pub(super) async fn store_pending_authorization(
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    value: PendingAuthorizationValue,
) -> Result<String, OpenAuthError> {
    let request_id = crate::utils::random_string(32);
    DbVerificationStore::new(adapter)
        .create_verification(CreateVerificationInput::new(
            pending_authorization_identifier(options, &request_id).await?,
            serde_json::to_string(&value).map_err(|error| OpenAuthError::Api(error.to_string()))?,
            crate::utils::now() + time::Duration::seconds(options.code_expires_in as i64),
        ))
        .await?;
    Ok(request_id)
}

pub(super) struct AuthorizationValueInput<'a> {
    client: &'a crate::models::SchemaClient,
    redirect_uri: &'a str,
    scopes: &'a [String],
    user: &'a User,
    session: &'a Session,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
}

pub(super) fn authorization_value(input: AuthorizationValueInput<'_>) -> AuthorizationCodeValue {
    AuthorizationCodeValue {
        client_id: input.client.client_id.clone(),
        redirect_uri: Some(input.redirect_uri.to_owned()),
        scopes: input.scopes.to_vec(),
        user_id: input.user.id.clone(),
        session_id: input.session.id.clone(),
        reference_id: input.client.reference_id.clone(),
        nonce: input.nonce,
        code_challenge: input.code_challenge,
        code_challenge_method: input.code_challenge_method,
        auth_time: Some(input.session.created_at),
    }
}

pub(super) fn pending_authorization_value(
    authorization: AuthorizationCodeValue,
    state: Option<String>,
    step: PendingAuthorizationStep,
    request: &ApiRequest,
) -> PendingAuthorizationValue {
    PendingAuthorizationValue {
        auth_time: authorization.auth_time,
        authorization,
        state,
        step,
        original_query: parse_query(request),
    }
}

pub(super) async fn load_pending_authorization(
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    request_id: &str,
) -> Result<Option<PendingAuthorizationValue>, OpenAuthError> {
    let identifier = pending_authorization_identifier(options, request_id).await?;
    DbVerificationStore::new(adapter)
        .find_verification(&identifier)
        .await?
        .map(|verification| {
            serde_json::from_str(&verification.value)
                .map_err(|error| OpenAuthError::Api(error.to_string()))
        })
        .transpose()
}

pub(super) async fn delete_pending_authorization(
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    request_id: &str,
) -> Result<(), OpenAuthError> {
    DbVerificationStore::new(adapter)
        .delete_verification(&pending_authorization_identifier(options, request_id).await?)
        .await
}

pub(super) async fn pending_authorization_identifier(
    options: &ResolvedOAuthProviderOptions,
    request_id: &str,
) -> Result<String, OpenAuthError> {
    store_token(options, request_id, "authorization_request").await
}

pub(super) async fn issue_authorization_code_redirect(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    value: AuthorizationCodeValue,
    state: Option<&str>,
) -> Result<ApiResponse, OpenAuthError> {
    let code = crate::utils::random_string(32);
    DbVerificationStore::new(adapter)
        .create_verification(CreateVerificationInput::new(
            store_token(options, &code, "authorization_code").await?,
            serde_json::to_string(&value).map_err(|error| OpenAuthError::Api(error.to_string()))?,
            crate::utils::now() + time::Duration::seconds(options.code_expires_in as i64),
        ))
        .await?;
    let redirect_uri = value
        .redirect_uri
        .as_deref()
        .ok_or_else(|| OpenAuthError::Api("authorization redirect_uri is required".to_owned()))?;
    let mut redirect =
        url::Url::parse(redirect_uri).map_err(|error| OpenAuthError::Api(error.to_string()))?;
    redirect.query_pairs_mut().append_pair("code", &code);
    if let Some(state) = state {
        redirect.query_pairs_mut().append_pair("state", state);
    }
    redirect
        .query_pairs_mut()
        .append_pair("iss", &context.base_url);
    redirect_response(redirect.as_str())
}

pub(super) fn page_redirect_with_request_id(
    page: &str,
    request_id: &str,
    base_url: &str,
) -> Result<String, OpenAuthError> {
    let base = url::Url::parse(base_url).map_err(|error| OpenAuthError::Api(error.to_string()))?;
    let mut redirect = base
        .join(page)
        .map_err(|error| OpenAuthError::Api(error.to_string()))?;
    redirect
        .query_pairs_mut()
        .append_pair("request_id", request_id);
    if page.starts_with('/') {
        let mut relative = redirect.path().to_owned();
        if let Some(query) = redirect.query() {
            relative.push('?');
            relative.push_str(query);
        }
        Ok(relative)
    } else {
        Ok(redirect.to_string())
    }
}

fn page_redirect_with_authorize_query(
    page: &str,
    request: &ApiRequest,
    base_url: &str,
) -> Result<String, OpenAuthError> {
    let base = url::Url::parse(base_url).map_err(|error| OpenAuthError::Api(error.to_string()))?;
    let mut redirect = base
        .join(page)
        .map_err(|error| OpenAuthError::Api(error.to_string()))?;
    if let Some(query) = request.uri().query() {
        redirect.set_query(Some(query));
    }
    if page.starts_with('/') {
        let mut relative = redirect.path().to_owned();
        if let Some(query) = redirect.query() {
            relative.push('?');
            relative.push_str(query);
        }
        Ok(relative)
    } else {
        Ok(redirect.to_string())
    }
}

fn pkce_required_reason(
    client: &crate::models::SchemaClient,
    scopes: &[String],
    is_public_client: bool,
) -> Option<&'static str> {
    if is_public_client {
        return Some("pkce is required for public clients");
    }
    if scopes.iter().any(|scope| scope == "offline_access") {
        return Some("pkce is required when requesting offline_access scope");
    }
    if client.require_pkce.unwrap_or(true) {
        return Some("pkce is required for this client");
    }
    None
}

pub(super) fn prompt_contains(request: &ApiRequest, expected: &str) -> bool {
    query_param(request, "prompt")
        .as_deref()
        .is_some_and(|prompt| prompt.split_whitespace().any(|value| value == expected))
}

pub(super) fn authorization_error_redirect(
    redirect_uri: &str,
    error: &str,
    description: &str,
    state: Option<&str>,
    issuer: &str,
) -> Result<ApiResponse, OpenAuthError> {
    let mut redirect =
        url::Url::parse(redirect_uri).map_err(|error| OpenAuthError::Api(error.to_string()))?;
    redirect.query_pairs_mut().append_pair("error", error);
    redirect
        .query_pairs_mut()
        .append_pair("error_description", description);
    if let Some(state) = state {
        redirect.query_pairs_mut().append_pair("state", state);
    }
    redirect.query_pairs_mut().append_pair("iss", issuer);
    redirect_response(redirect.as_str())
}

fn session_exceeds_max_age(request: &ApiRequest, session: Option<&Session>) -> bool {
    let Some(max_age) = query_param(request, "max_age")
        .as_deref()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value >= 0)
    else {
        return false;
    };
    let Some(session) = session else {
        return false;
    };
    (crate::utils::now() - session.created_at).whole_seconds() >= max_age
}
