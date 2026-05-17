use std::sync::Arc;

use http::{header, Method, Response, StatusCode};
use openauth_core::api::{
    create_auth_endpoint, ApiRequest, ApiResponse, AsyncAuthEndpoint, AuthEndpointOptions,
};
use openauth_core::context::AuthContext;
use openauth_core::db::{DbAdapter, DbRecord, DbValue};
use openauth_core::error::OpenAuthError;
use openauth_core::verification::{CreateVerificationInput, DbVerificationStore};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::authorize::{decide_authorize, AuthorizeDecision};
use crate::client::{
    check_oauth_client, create_oauth_client, get_client, schema_to_oauth, update_client,
    CreateOAuthClientInput, OAuthClient,
};
use crate::consent::{consent_from_record, upsert_consent, ConsentGrantInput};
use crate::error::OAuthProviderError;
use crate::metadata::{auth_server_metadata, oidc_server_metadata};
use crate::options::{GrantType, ResolvedOAuthProviderOptions};
use crate::schema::{OAUTH_CLIENT_MODEL, OAUTH_CONSENT_MODEL};
use crate::token::{
    create_authorization_code_token, create_client_credentials_token, create_refresh_token_grant,
    introspect_token, revoke_token, store_token, validate_access_token,
    validate_client_credentials, validate_id_token_hint, AuthorizationCodeValue,
    RefreshTokenGrantInput, TokenRequest,
};
use crate::utils::{
    basic_credentials, bearer_token, current_session, error_response, find_by_string,
    find_many_by_string, is_loopback_redirect_match, json_response, no_content, parse_body,
    query_param, redirect_response, split_scope, update_by_string,
};

pub(crate) fn oauth_provider_endpoints(
    options: Arc<ResolvedOAuthProviderOptions>,
) -> Vec<AsyncAuthEndpoint> {
    vec![
        metadata_endpoint(
            "/.well-known/oauth-authorization-server",
            Arc::clone(&options),
            false,
        ),
        metadata_endpoint(
            "/.well-known/openid-configuration",
            Arc::clone(&options),
            true,
        ),
        authorize_endpoint(Arc::clone(&options)),
        consent_endpoint(Arc::clone(&options)),
        continue_endpoint(Arc::clone(&options)),
        token_endpoint(Arc::clone(&options)),
        introspect_endpoint(Arc::clone(&options)),
        revoke_endpoint(Arc::clone(&options)),
        userinfo_endpoint(Arc::clone(&options)),
        logout_endpoint(Arc::clone(&options)),
        register_endpoint(Arc::clone(&options)),
        create_client_endpoint("/admin/oauth2/create-client", Arc::clone(&options)),
        create_client_endpoint("/oauth2/create-client", Arc::clone(&options)),
        get_client_endpoint(Arc::clone(&options)),
        public_client_endpoint("/oauth2/public-client", Arc::clone(&options)),
        public_client_prelogin_endpoint(Arc::clone(&options)),
        get_clients_endpoint(Arc::clone(&options)),
        update_client_endpoint("/admin/oauth2/update-client", Arc::clone(&options)),
        update_client_endpoint("/oauth2/update-client", Arc::clone(&options)),
        rotate_secret_endpoint(Arc::clone(&options)),
        delete_client_endpoint(Arc::clone(&options)),
        get_consent_endpoint(Arc::clone(&options)),
        get_consents_endpoint(Arc::clone(&options)),
        update_consent_endpoint(Arc::clone(&options)),
        delete_consent_endpoint(options),
    ]
}

fn metadata_endpoint(
    path: &'static str,
    options: Arc<ResolvedOAuthProviderOptions>,
    oidc: bool,
) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        path,
        Method::GET,
        AuthEndpointOptions::new(),
        move |context, _request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                if oidc {
                    if !options.scopes.contains(&"openid".to_owned()) {
                        return error_response(OAuthProviderError::new(
                            StatusCode::NOT_FOUND,
                            "not_found",
                            "OpenID Connect is disabled",
                        ));
                    }
                    metadata_response(&oidc_server_metadata(context, &options))
                } else {
                    metadata_response(&auth_server_metadata(context, &options))
                }
            })
        },
    )
}

const METADATA_CACHE_CONTROL: &str =
    "public, max-age=15, stale-while-revalidate=15, stale-if-error=86400";

fn metadata_response<T: Serialize>(body: &T) -> Result<ApiResponse, OpenAuthError> {
    let body = serde_json::to_vec(body).map_err(|error| OpenAuthError::Api(error.to_string()))?;
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, METADATA_CACHE_CONTROL)
        .body(body)
        .map_err(|error| OpenAuthError::Api(error.to_string()))
}

fn authorize_endpoint(options: Arc<ResolvedOAuthProviderOptions>) -> AsyncAuthEndpoint {
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
                let Some(client) = get_client(adapter.as_ref(), &client_id).await? else {
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
                let require_pkce = client.require_pkce == Some(true) || is_public_client;
                let code_challenge = query_param(&request, "code_challenge");
                let code_challenge_method = query_param(&request, "code_challenge_method")
                    .or_else(|| code_challenge.as_ref().map(|_| "plain".to_owned()));
                if require_pkce && code_challenge.is_none() {
                    return error_response(OAuthProviderError::invalid_request(
                        "code_challenge is required",
                    ));
                };
                if let Some(method) = code_challenge_method.as_deref() {
                    if method != "S256" {
                        return error_response(OAuthProviderError::invalid_request(
                            "only S256 PKCE code_challenge_method is supported",
                        ));
                    }
                };
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
                let scopes = crate::utils::split_scope(query_param(&request, "scope").as_deref());
                let state = query_param(&request, "state");
                let nonce = query_param(&request, "nonce");
                let current_session = current_session(context, adapter.as_ref(), &request).await?;
                let session_user_id = current_session
                    .as_ref()
                    .map(|(_, user, _)| user.id.as_str());
                match decide_authorize(
                    adapter.as_ref(),
                    &client,
                    session_user_id,
                    &scopes,
                    query_param(&request, "prompt").as_deref(),
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
                            PendingAuthorizationValue {
                                authorization: AuthorizationCodeValue {
                                    client_id: client.client_id.clone(),
                                    redirect_uri: Some(redirect_uri.clone()),
                                    scopes: scopes.clone(),
                                    user_id: user.id.clone(),
                                    session_id: session.id.clone(),
                                    nonce: nonce.clone(),
                                    code_challenge: code_challenge.clone(),
                                    code_challenge_method: code_challenge_method.clone(),
                                },
                                state: state.clone(),
                            },
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
                let value = AuthorizationCodeValue {
                    client_id: client.client_id,
                    redirect_uri: Some(redirect_uri.clone()),
                    scopes,
                    user_id: user.id,
                    session_id: session.id,
                    nonce,
                    code_challenge,
                    code_challenge_method,
                };
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
struct PendingAuthorizationValue {
    authorization: AuthorizationCodeValue,
    state: Option<String>,
}

async fn store_pending_authorization(
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    value: PendingAuthorizationValue,
) -> Result<String, OpenAuthError> {
    let request_id = crate::utils::random_string(32);
    DbVerificationStore::new(adapter)
        .create_verification(CreateVerificationInput::new(
            pending_authorization_identifier(options, &request_id)?,
            serde_json::to_string(&value).map_err(|error| OpenAuthError::Api(error.to_string()))?,
            crate::utils::now() + time::Duration::seconds(options.code_expires_in as i64),
        ))
        .await?;
    Ok(request_id)
}

async fn load_pending_authorization(
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    request_id: &str,
) -> Result<Option<PendingAuthorizationValue>, OpenAuthError> {
    let identifier = pending_authorization_identifier(options, request_id)?;
    DbVerificationStore::new(adapter)
        .find_verification(&identifier)
        .await?
        .map(|verification| {
            serde_json::from_str(&verification.value)
                .map_err(|error| OpenAuthError::Api(error.to_string()))
        })
        .transpose()
}

async fn delete_pending_authorization(
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    request_id: &str,
) -> Result<(), OpenAuthError> {
    DbVerificationStore::new(adapter)
        .delete_verification(&pending_authorization_identifier(options, request_id)?)
        .await
}

fn pending_authorization_identifier(
    options: &ResolvedOAuthProviderOptions,
    request_id: &str,
) -> Result<String, OpenAuthError> {
    store_token(options, request_id, "authorization_request")
}

async fn issue_authorization_code_redirect(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    value: AuthorizationCodeValue,
    state: Option<&str>,
) -> Result<ApiResponse, OpenAuthError> {
    let code = crate::utils::random_string(32);
    DbVerificationStore::new(adapter)
        .create_verification(CreateVerificationInput::new(
            store_token(options, &code, "authorization_code")?,
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

fn page_redirect_with_request_id(
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

fn authorization_error_redirect(
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

fn token_endpoint(options: Arc<ResolvedOAuthProviderOptions>) -> AsyncAuthEndpoint {
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
                let mut body: TokenRequest = parse_body(&request)?;
                if let Some((client_id, client_secret)) = basic_credentials(&request)? {
                    body.client_id.get_or_insert(client_id);
                    body.client_secret.get_or_insert(client_secret);
                }
                match body.grant_type.as_str() {
                    "client_credentials" => {
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
                        let response = create_client_credentials_token(
                            context,
                            adapter.as_ref(),
                            &options,
                            client_id,
                            body.client_secret.as_deref(),
                            requested_scopes,
                            resource,
                        )
                        .await?;
                        json_response(StatusCode::OK, &response)
                    }
                    "authorization_code" => {
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
                        let identifier = store_token(&options, code, "authorization_code")?;
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
                        let response = create_authorization_code_token(
                            context,
                            adapter.as_ref(),
                            &options,
                            client_id,
                            body.client_secret.as_deref(),
                            code_value,
                            resource,
                        )
                        .await?;
                        json_response(StatusCode::OK, &response)
                    }
                    "refresh_token" => {
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
                        let response = create_refresh_token_grant(
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
                        .await?;
                        json_response(StatusCode::OK, &response)
                    }
                    _ => error_response(OAuthProviderError::new(
                        StatusCode::BAD_REQUEST,
                        "unsupported_grant_type",
                        format!("unsupported grant_type {}", body.grant_type),
                    )),
                }
            })
        },
    )
}

fn validate_resource(
    context: &openauth_core::context::AuthContext,
    options: &ResolvedOAuthProviderOptions,
    resource: Option<String>,
    scopes: &[String],
) -> Result<Option<String>, OAuthProviderError> {
    let Some(resource) = resource.filter(|resource| !resource.is_empty()) else {
        return Ok(None);
    };
    let mut valid = if options.valid_audiences.is_empty() {
        vec![context.base_url.clone()]
    } else {
        options.valid_audiences.clone()
    };
    if scopes.iter().any(|scope| scope == "openid") {
        valid.push(format!("{}/oauth2/userinfo", context.base_url));
    }
    if valid.iter().any(|audience| audience == &resource) {
        Ok(Some(resource))
    } else {
        Err(OAuthProviderError::invalid_request(
            "requested resource invalid",
        ))
    }
}

fn register_endpoint(options: Arc<ResolvedOAuthProviderOptions>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/oauth2/register",
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
                let body: OAuthClient = parse_body(&request)?;
                let user_id = current_session(context, adapter.as_ref(), &request)
                    .await?
                    .map(|(_, user, _)| user.id);
                let client = create_oauth_client(
                    context,
                    adapter.as_ref(),
                    &options,
                    body,
                    CreateOAuthClientInput {
                        is_register: true,
                        user_id,
                    },
                )
                .await?;
                json_response(StatusCode::CREATED, &client)
            })
        },
    )
}

fn create_client_endpoint(
    path: &'static str,
    options: Arc<ResolvedOAuthProviderOptions>,
) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        path,
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
                let body: OAuthClient = parse_body(&request)?;
                let client = create_oauth_client(
                    context,
                    adapter.as_ref(),
                    &options,
                    body,
                    CreateOAuthClientInput {
                        is_register: false,
                        user_id: Some(user.id),
                    },
                )
                .await?;
                json_response(StatusCode::CREATED, &client)
            })
        },
    )
}

fn get_client_endpoint(options: Arc<ResolvedOAuthProviderOptions>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/oauth2/get-client",
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
                let Some(client_id) = query_param(&request, "client_id") else {
                    return error_response(OAuthProviderError::invalid_client(
                        "client_id is required",
                    ));
                };
                let Some(client) = get_client(adapter.as_ref(), &client_id).await? else {
                    return error_response(OAuthProviderError::new(
                        StatusCode::NOT_FOUND,
                        "not_found",
                        "client not found",
                    ));
                };
                if !is_client_owner(&client, &user.id) {
                    return client_owner_error_response();
                }
                let mut response = schema_to_oauth(&client);
                response.client_secret = None;
                json_response(StatusCode::OK, &response)
            })
        },
    )
}

fn is_client_owner(client: &crate::models::SchemaClient, user_id: &str) -> bool {
    client.user_id.as_deref() == Some(user_id)
}

fn client_owner_error_response() -> Result<ApiResponse, OpenAuthError> {
    error_response(OAuthProviderError::access_denied(
        "client belongs to another user",
    ))
}

fn public_client_endpoint(
    path: &'static str,
    options: Arc<ResolvedOAuthProviderOptions>,
) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        path,
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
                let Some(client_id) = query_param(&request, "client_id") else {
                    return error_response(OAuthProviderError::invalid_client(
                        "client_id is required",
                    ));
                };
                let Some(client) = get_client(adapter.as_ref(), &client_id).await? else {
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
            })
        },
    )
}

fn public_client_prelogin_endpoint(
    options: Arc<ResolvedOAuthProviderOptions>,
) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/oauth2/public-client-prelogin",
        Method::POST,
        AuthEndpointOptions::new().allowed_media_types(["application/json"]),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                let mut request = request;
                let body: serde_json::Value = parse_body(&request)?;
                let client_id = body
                    .get("client_id")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default();
                let uri = format!("{}?client_id={}", request.uri().path(), client_id);
                *request.uri_mut() = uri.parse().map_err(|error: http::uri::InvalidUri| {
                    OpenAuthError::Api(error.to_string())
                })?;
                (public_client_endpoint("/oauth2/public-client-prelogin", options).handler)(
                    context, request,
                )
                .await
            })
        },
    )
}

fn get_clients_endpoint(options: Arc<ResolvedOAuthProviderOptions>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/oauth2/get-clients",
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
                let clients = adapter
                    .find_many(find_many_by_string(OAUTH_CLIENT_MODEL, "user_id", &user.id))
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
            })
        },
    )
}

#[derive(Debug, Deserialize)]
struct UpdateClientBody {
    client_id: String,
    update: OAuthClient,
}

fn update_client_endpoint(
    path: &'static str,
    options: Arc<ResolvedOAuthProviderOptions>,
) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        path,
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
                let body: UpdateClientBody = parse_body(&request)?;
                let Some(existing) = get_client(adapter.as_ref(), &body.client_id).await? else {
                    return error_response(OAuthProviderError::new(
                        StatusCode::NOT_FOUND,
                        "not_found",
                        "client not found",
                    ));
                };
                if !is_client_owner(&existing, &user.id) {
                    return client_owner_error_response();
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
            })
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

fn oauth_validation_error_response(error: OpenAuthError) -> Result<ApiResponse, OpenAuthError> {
    let OpenAuthError::Api(message) = error else {
        return Err(error);
    };
    let Some((code, description)) = message.split_once(": ") else {
        return Err(OpenAuthError::Api(message));
    };
    let error = match code {
        "invalid_scope" => OAuthProviderError::invalid_scope(description.to_owned()),
        "invalid_client_metadata" | "invalid_redirect_uri" => {
            OAuthProviderError::new(StatusCode::BAD_REQUEST, code, description.to_owned())
        }
        "invalid_request" => OAuthProviderError::invalid_request(description.to_owned()),
        "access_denied" => OAuthProviderError::access_denied(description.to_owned()),
        _ => return Err(OpenAuthError::Api(message)),
    };
    error_response(error)
}

#[derive(Debug, Deserialize)]
struct ClientIdBody {
    client_id: String,
}

fn rotate_secret_endpoint(options: Arc<ResolvedOAuthProviderOptions>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/oauth2/client/rotate-secret",
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
                let body: ClientIdBody = parse_body(&request)?;
                let Some(existing) = get_client(adapter.as_ref(), &body.client_id).await? else {
                    return error_response(OAuthProviderError::new(
                        StatusCode::NOT_FOUND,
                        "not_found",
                        "client not found",
                    ));
                };
                if !is_client_owner(&existing, &user.id) {
                    return client_owner_error_response();
                }
                if existing.public == Some(true) || existing.client_secret.is_none() {
                    return error_response(OAuthProviderError::invalid_client(
                        "public clients cannot rotate secrets",
                    ));
                }
                let secret = crate::utils::random_string(32);
                let stored = crate::token::store_client_secret(context, &options, &secret)?;
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
                response.client_secret = Some(secret);
                json_response(StatusCode::OK, &response)
            })
        },
    )
}

fn delete_client_endpoint(options: Arc<ResolvedOAuthProviderOptions>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/oauth2/delete-client",
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
                let body: ClientIdBody = parse_body(&request)?;
                let Some(existing) = get_client(adapter.as_ref(), &body.client_id).await? else {
                    return error_response(OAuthProviderError::new(
                        StatusCode::NOT_FOUND,
                        "not_found",
                        "client not found",
                    ));
                };
                if !is_client_owner(&existing, &user.id) {
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
            })
        },
    )
}

fn introspect_endpoint(options: Arc<ResolvedOAuthProviderOptions>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/oauth2/introspect",
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
                let body: serde_json::Value = parse_body(&request)?;
                if let Some(response) = authenticate_endpoint_client(
                    context,
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
                json_response(
                    StatusCode::OK,
                    &introspect_token(context, adapter.as_ref(), &options, token).await?,
                )
            })
        },
    )
}

fn revoke_endpoint(options: Arc<ResolvedOAuthProviderOptions>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/oauth2/revoke",
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
                let body: serde_json::Value = parse_body(&request)?;
                if let Some(response) = authenticate_endpoint_client(
                    context,
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
                revoke_token(adapter.as_ref(), &options, token).await?;
                no_content()
            })
        },
    )
}

async fn authenticate_endpoint_client(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    request: &ApiRequest,
    body: &serde_json::Value,
) -> Result<Option<ApiResponse>, OpenAuthError> {
    let (client_id, client_secret) = request_client_auth(request, body)?;
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
) -> Result<(Option<String>, Option<String>), OpenAuthError> {
    let mut client_id = body
        .get("client_id")
        .and_then(|value| value.as_str())
        .map(str::to_owned);
    let mut client_secret = body
        .get("client_secret")
        .and_then(|value| value.as_str())
        .map(str::to_owned);
    if let Some((basic_id, basic_secret)) = basic_credentials(request)? {
        client_id.get_or_insert(basic_id);
        client_secret.get_or_insert(basic_secret);
    }
    Ok((client_id, client_secret))
}

fn client_auth_failure_response(error: OpenAuthError) -> Result<ApiResponse, OpenAuthError> {
    let OpenAuthError::Api(message) = error else {
        return Err(error);
    };
    let Some(description) = message.strip_prefix("invalid_client: ") else {
        return Err(OpenAuthError::Api(message));
    };
    error_response(OAuthProviderError::unauthorized(description.to_owned()))
}

fn userinfo_endpoint(options: Arc<ResolvedOAuthProviderOptions>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/oauth2/userinfo",
        Method::GET,
        AuthEndpointOptions::new(),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                let Some(adapter) = context.adapter() else {
                    return error_response(OAuthProviderError::invalid_request(
                        "database adapter required",
                    ));
                };
                let Some(token) = bearer_token(&request) else {
                    return error_response(OAuthProviderError::new(
                        StatusCode::UNAUTHORIZED,
                        "invalid_request",
                        "authorization header not found",
                    ));
                };
                let Some(validated) =
                    validate_access_token(context, adapter.as_ref(), &options, &token).await?
                else {
                    return error_response(OAuthProviderError::new(
                        StatusCode::UNAUTHORIZED,
                        "invalid_token",
                        "invalid token",
                    ));
                };
                if !validated.active {
                    return error_response(OAuthProviderError::new(
                        StatusCode::UNAUTHORIZED,
                        "invalid_token",
                        "invalid token",
                    ));
                }
                if !validated.scopes.iter().any(|scope| scope == "openid") {
                    return error_response(OAuthProviderError::invalid_scope(
                        "Missing required scope",
                    ));
                }
                let Some(user_id) = validated.user_id.as_deref() else {
                    return error_response(OAuthProviderError::invalid_request("user not found"));
                };
                let Some(user) = adapter
                    .find_one(crate::utils::find_by_string("user", "id", user_id))
                    .await?
                    .map(crate::utils::user_from_record)
                    .transpose()?
                else {
                    return error_response(OAuthProviderError::invalid_request("user not found"));
                };
                let sub = if let Some(client_id) = validated.client_id.as_deref() {
                    match get_client(adapter.as_ref(), client_id).await? {
                        Some(client) => {
                            crate::token::resolve_subject_identifier(&user.id, &client, &options)?
                        }
                        None => user.id.clone(),
                    }
                } else {
                    user.id.clone()
                };
                let mut claims = serde_json::Map::new();
                claims.insert("sub".to_owned(), serde_json::Value::String(sub));
                if validated.scopes.iter().any(|scope| scope == "profile") {
                    claims.insert(
                        "name".to_owned(),
                        serde_json::Value::String(user.name.clone()),
                    );
                    if let Some(image) = user.image {
                        claims.insert("picture".to_owned(), serde_json::Value::String(image));
                    }
                }
                if validated.scopes.iter().any(|scope| scope == "email") {
                    claims.insert("email".to_owned(), serde_json::Value::String(user.email));
                    claims.insert(
                        "email_verified".to_owned(),
                        serde_json::Value::Bool(user.email_verified),
                    );
                }
                json_response(StatusCode::OK, &serde_json::Value::Object(claims))
            })
        },
    )
}

fn logout_endpoint(options: Arc<ResolvedOAuthProviderOptions>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/oauth2/end-session",
        Method::GET,
        AuthEndpointOptions::new(),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                let Some(adapter) = context.adapter() else {
                    return error_response(OAuthProviderError::invalid_request(
                        "database adapter required",
                    ));
                };
                let Some(id_token_hint) = query_param(&request, "id_token_hint") else {
                    return error_response(OAuthProviderError::new(
                        StatusCode::UNAUTHORIZED,
                        "invalid_token",
                        "invalid id token",
                    ));
                };
                let validated = match validate_id_token_hint(
                    context,
                    adapter.as_ref(),
                    &options,
                    &id_token_hint,
                    query_param(&request, "client_id").as_deref(),
                )
                .await
                {
                    Ok(validated) => validated,
                    Err(error) => return error_response(error),
                };
                adapter
                    .delete(crate::utils::delete_by_string(
                        "session",
                        "id",
                        &validated.session_id,
                    ))
                    .await?;
                if let Some(uri) = query_param(&request, "post_logout_redirect_uri") {
                    if validated
                        .client
                        .post_logout_redirect_uris
                        .as_deref()
                        .unwrap_or_default()
                        .iter()
                        .any(|registered| registered == &uri)
                    {
                        let mut redirect = url::Url::parse(&uri)
                            .map_err(|error| OpenAuthError::Api(error.to_string()))?;
                        if let Some(state) = query_param(&request, "state") {
                            redirect.query_pairs_mut().append_pair("state", &state);
                        }
                        return redirect_response(redirect.as_str());
                    }
                }
                no_content()
            })
        },
    )
}

fn consent_endpoint(options: Arc<ResolvedOAuthProviderOptions>) -> AsyncAuthEndpoint {
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
                let Some(pending) =
                    load_pending_authorization(adapter.as_ref(), &options, &body.request_id)
                        .await?
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
                delete_pending_authorization(adapter.as_ref(), &options, &body.request_id).await?;
                if !body.accept {
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
                upsert_consent(
                    adapter.as_ref(),
                    ConsentGrantInput {
                        client_id: pending.authorization.client_id.clone(),
                        user_id: Some(user.id),
                        reference_id: None,
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

fn continue_endpoint(options: Arc<ResolvedOAuthProviderOptions>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/oauth2/continue",
        Method::GET,
        AuthEndpointOptions::new(),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                let Some(adapter) = context.adapter() else {
                    return error_response(OAuthProviderError::invalid_request(
                        "database adapter required",
                    ));
                };
                let Some(request_id) = query_param(&request, "request_id") else {
                    return error_response(OAuthProviderError::invalid_request(
                        "request_id is required",
                    ));
                };
                let Some(pending) =
                    load_pending_authorization(adapter.as_ref(), &options, &request_id).await?
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
                delete_pending_authorization(adapter.as_ref(), &options, &request_id).await?;
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

#[derive(Debug, Deserialize)]
struct ConsentDecisionBody {
    request_id: String,
    accept: bool,
}

fn get_consent_endpoint(options: Arc<ResolvedOAuthProviderOptions>) -> AsyncAuthEndpoint {
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

fn get_consents_endpoint(options: Arc<ResolvedOAuthProviderOptions>) -> AsyncAuthEndpoint {
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

fn update_consent_endpoint(options: Arc<ResolvedOAuthProviderOptions>) -> AsyncAuthEndpoint {
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
                    let allowed_scopes = get_client(adapter.as_ref(), &consent.client_id)
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

fn delete_consent_endpoint(options: Arc<ResolvedOAuthProviderOptions>) -> AsyncAuthEndpoint {
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
