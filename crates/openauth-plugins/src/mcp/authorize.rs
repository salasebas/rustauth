use http::{header, Method, StatusCode};
use openauth_core::api::{create_auth_endpoint, AsyncAuthEndpoint, AuthEndpointOptions};
use openauth_core::cookies::parse_set_cookie_header;
use openauth_core::db::{Create, DbValue, FindOne, Session, Where};
use serde_json::json;
use time::{Duration, OffsetDateTime};

use super::shared::{
    adapter, append_signed_prompt_cookie, current_session, expire_prompt_cookie, find_client,
    redirect, redirect_error_url, request_cookie, verify_signed_cookie, CONSENT_PROMPT_COOKIE,
    LOGIN_PROMPT_COOKIE,
};
use super::ResolvedMcpOptions;

pub fn authorize_endpoint(options: ResolvedMcpOptions) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/mcp/authorize",
        Method::GET,
        AuthEndpointOptions::new().operation_id("mcpOAuthAuthorize"),
        move |context, request| {
            let options = options.clone();
            Box::pin(async move {
                let mut query = query_map(request.uri().query().unwrap_or_default());
                let adapter = adapter(context)?;
                let Some(session) = current_session(adapter.as_ref(), context, &request).await?
                else {
                    let prompt_value = serde_json::to_string(&query).map_err(|error| {
                        openauth_core::error::OpenAuthError::Api(error.to_string())
                    })?;
                    let target = if request.uri().query().is_some() {
                        format!(
                            "{}?{}",
                            options.login_page,
                            request.uri().query().unwrap_or_default()
                        )
                    } else {
                        options.login_page.clone()
                    };
                    let mut response = redirect(&target)?;
                    append_signed_prompt_cookie(
                        &mut response,
                        LOGIN_PROMPT_COOKIE,
                        &prompt_value,
                        &context.secret,
                    )?;
                    return Ok(response);
                };
                authorize_with_session(context, &options, &mut query, session).await
            })
        },
    )
}

pub(crate) async fn resume_after_login(
    context: &openauth_core::context::AuthContext,
    request: &openauth_core::api::ApiRequest,
    mut response: openauth_core::api::ApiResponse,
    options: &ResolvedMcpOptions,
) -> Result<openauth_core::api::ApiResponse, openauth_core::error::OpenAuthError> {
    let Some(cookie) = request_cookie(request, LOGIN_PROMPT_COOKIE) else {
        return Ok(response);
    };
    let set_cookie = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>()
        .join(", ");
    if set_cookie.is_empty() {
        return Ok(response);
    }
    let cookies = parse_set_cookie_header(&set_cookie);
    let cookie_name = &context.auth_cookies.session_token.name;
    let Some(parsed_session) = cookies.get(cookie_name).or_else(|| {
        cookies.get(openauth_core::cookies::strip_secure_cookie_prefix(
            cookie_name,
        ))
    }) else {
        return Ok(response);
    };
    let Some(prompt) = verify_signed_cookie(&cookie, &context.secret)? else {
        return Ok(response);
    };
    let Some(session_token) = verify_signed_cookie(&parsed_session.value, &context.secret)? else {
        return Ok(response);
    };
    let adapter = adapter(context)?;
    let Some(session_record) = adapter
        .find_one(
            FindOne::new("session")
                .where_clause(Where::new("token", DbValue::String(session_token))),
        )
        .await?
    else {
        return Ok(response);
    };
    let session = session_from_record(&session_record)?;
    let mut query: std::collections::BTreeMap<String, String> =
        serde_json::from_str(&prompt).unwrap_or_default();
    remove_prompt(&mut query, "login");
    response = authorize_with_session(context, options, &mut query, session).await?;
    expire_prompt_cookie(&mut response, LOGIN_PROMPT_COOKIE)?;
    Ok(response)
}

pub(crate) async fn authorize_with_session(
    context: &openauth_core::context::AuthContext,
    options: &ResolvedMcpOptions,
    query: &mut std::collections::BTreeMap<String, String>,
    session: Session,
) -> Result<openauth_core::api::ApiResponse, openauth_core::error::OpenAuthError> {
    let adapter = adapter(context)?;
    let error_url = format!("{}{}{}", context.base_url, context.base_path, "/error");
    if prompt_has(query, "none") && prompt_count(query) > 1 {
        return redirect(&redirect_error_url(
            &error_url,
            "invalid_request",
            "prompt none must only be used alone",
        ));
    }
    let Some(client_id) = query.get("client_id").cloned() else {
        return redirect(&format!("{error_url}?error=invalid_client"));
    };
    if !query.contains_key("response_type") {
        return redirect(&redirect_error_url(
            &error_url,
            "invalid_request",
            "response_type is required",
        ));
    }
    let Some(client) = find_client(adapter.as_ref(), &client_id).await? else {
        return redirect(&format!("{error_url}?error=invalid_client"));
    };
    let Some(redirect_uri) = query.get("redirect_uri").cloned() else {
        return super::shared::oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "redirect_uri is required",
        );
    };
    if !client.redirect_urls.iter().any(|url| url == &redirect_uri) {
        return super::shared::oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid redirect URI",
        );
    }
    if client.disabled {
        return redirect(&format!("{error_url}?error=client_disabled"));
    }
    if query.get("response_type").map(String::as_str) != Some("code") {
        return redirect(&format!("{error_url}?error=unsupported_response_type"));
    }

    let request_scope = query
        .get("scope")
        .map(|scope| {
            scope
                .split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| options.default_scope.clone());
    let invalid_scopes = request_scope
        .iter()
        .filter(|scope| !options.scopes.contains(scope))
        .cloned()
        .collect::<Vec<_>>();
    if !invalid_scopes.is_empty() {
        return redirect(&redirect_error_url(
            &redirect_uri,
            "invalid_scope",
            &format!(
                "The following scopes are invalid: {}",
                invalid_scopes.join(", ")
            ),
        ));
    }

    let has_challenge = query.contains_key("code_challenge");
    let has_method = query.contains_key("code_challenge_method");
    if options.require_pkce && (!has_challenge || !has_method) {
        return redirect(&redirect_error_url(
            &redirect_uri,
            "invalid_request",
            "pkce is required",
        ));
    }
    if !has_method {
        query.insert("code_challenge_method".to_owned(), "plain".to_owned());
    }
    let method = query
        .get("code_challenge_method")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_else(|| "plain".to_owned());
    let method_allowed =
        method == "s256" || (options.allow_plain_code_challenge_method && method == "plain");
    if !method_allowed {
        return redirect(&redirect_error_url(
            &redirect_uri,
            "invalid_request",
            "invalid code_challenge method",
        ));
    }

    let code = super::shared::random_token();
    let now = OffsetDateTime::now_utc();
    let value = json!({
        "clientId": client.client_id,
        "redirectURI": redirect_uri,
        "scope": request_scope,
        "userId": session.user_id,
        "authTime": session.created_at.unix_timestamp(),
        "requireConsent": prompt_has(query, "consent"),
        "state": query.get("state"),
        "codeChallenge": query.get("code_challenge"),
        "codeChallengeMethod": query.get("code_challenge_method"),
        "nonce": query.get("nonce"),
    });
    adapter
        .create(
            Create::new("verification")
                .data("id", DbValue::String(format!("mcp_code_{code}")))
                .data("identifier", DbValue::String(code.clone()))
                .data("value", DbValue::String(value.to_string()))
                .data(
                    "expires_at",
                    DbValue::Timestamp(now + Duration::seconds(options.code_expires_in as i64)),
                )
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Timestamp(now)),
        )
        .await?;

    if prompt_has(query, "consent") {
        if let Some(consent_page) = &options.consent_page {
            let mut consent_uri = url::Url::parse(consent_page)
                .or_else(|_| url::Url::parse(&format!("http://localhost{consent_page}")))
                .map_err(|error| openauth_core::error::OpenAuthError::Api(error.to_string()))?;
            consent_uri
                .query_pairs_mut()
                .append_pair("consent_code", &code)
                .append_pair("client_id", &client.client_id)
                .append_pair("scope", &request_scope.join(" "));
            let mut response =
                redirect(consent_uri.as_str().trim_start_matches("http://localhost"))?;
            append_signed_prompt_cookie(
                &mut response,
                CONSENT_PROMPT_COOKIE,
                &code,
                &context.secret,
            )?;
            return Ok(response);
        }
    }

    redirect_with_code(&redirect_uri, &code, query.get("state").map(String::as_str))
}

pub(crate) fn redirect_with_code(
    redirect_uri: &str,
    code: &str,
    state: Option<&str>,
) -> Result<openauth_core::api::ApiResponse, openauth_core::error::OpenAuthError> {
    let mut redirect_url = url::Url::parse(redirect_uri)
        .map_err(|error| openauth_core::error::OpenAuthError::Api(error.to_string()))?;
    redirect_url.query_pairs_mut().append_pair("code", code);
    if let Some(state) = state {
        redirect_url.query_pairs_mut().append_pair("state", state);
    }
    redirect(redirect_url.as_str())
}

fn query_map(query: &str) -> std::collections::BTreeMap<String, String> {
    url::form_urlencoded::parse(query.as_bytes())
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect()
}

fn prompt_has(query: &std::collections::BTreeMap<String, String>, expected: &str) -> bool {
    query
        .get("prompt")
        .is_some_and(|prompt| prompt.split_whitespace().any(|prompt| prompt == expected))
}

fn prompt_count(query: &std::collections::BTreeMap<String, String>) -> usize {
    query
        .get("prompt")
        .map(|prompt| prompt.split_whitespace().count())
        .unwrap_or(0)
}

fn remove_prompt(query: &mut std::collections::BTreeMap<String, String>, removed: &str) {
    let Some(prompt) = query.get("prompt").cloned() else {
        return;
    };
    let prompt = prompt
        .split_whitespace()
        .filter(|value| *value != removed)
        .collect::<Vec<_>>()
        .join(" ");
    if prompt.is_empty() {
        query.remove("prompt");
    } else {
        query.insert("prompt".to_owned(), prompt);
    }
}

fn session_from_record(
    record: &openauth_core::db::DbRecord,
) -> Result<Session, openauth_core::error::OpenAuthError> {
    Ok(Session {
        id: super::shared::required_string(record, "id")?,
        user_id: super::shared::required_string(record, "user_id")?,
        expires_at: super::shared::required_timestamp(record, "expires_at")?,
        token: super::shared::required_string(record, "token")?,
        ip_address: super::shared::optional_string(record, "ip_address")?,
        user_agent: super::shared::optional_string(record, "user_agent")?,
        created_at: super::shared::required_timestamp(record, "created_at")?,
        updated_at: super::shared::required_timestamp(record, "updated_at")?,
    })
}
