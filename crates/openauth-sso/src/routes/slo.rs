use std::sync::Arc;

use http::{header, Method};
use openauth_core::api::{
    create_auth_endpoint, json_response, parse_request_body, serialize_cookie, ApiRequest,
    ApiResponse, AsyncAuthEndpoint, AuthEndpointOptions, OpenApiOperation,
};
use openauth_core::auth::session::{GetSessionInput, SessionAuth};
use openauth_core::context::AuthContext;
use openauth_core::crypto::random::generate_random_string;
use openauth_core::db::{DbAdapter, DbValue, Delete, Where};
use serde::Deserialize;
use serde_json::json;
use time::OffsetDateTime;

use crate::audit;
use crate::openapi::{
    html_response as openapi_html_response, redirect_response, saml_logout_body_schema,
    saml_slo_body_schema,
};
use crate::options::{SamlConfig, SsoAuditEvent, SsoAuditEventKind, SsoAuditSeverity, SsoOptions};
use crate::saml::SpBuildOptions;
use crate::saml_impl::logout::{
    build_logout_request_binding, build_logout_response_binding, ParsedSamlLogoutRequest,
    ParsedSamlLogoutResponse, SamlLogoutBinding, SamlLogoutBindingResponse, SamlLogoutBuildContext,
    SamlLogoutRequestInput,
};
use crate::saml_impl::state::{logout_request_key, saml_session_by_id_key, saml_session_key};
use crate::state::SsoStateStore;
use crate::store::{SsoProviderRecord, SsoProviderStore};
use crate::utils;

#[path = "slo/verification.rs"]
mod verification;

use verification::{parse_verified_logout_request, parse_verified_logout_response};

use super::support::{
    path_param, query_param, redirect, redirect_with_cookies, redirect_with_error,
    safe_redirect_field, unauthorized,
};

#[derive(Debug, Default, Deserialize)]
struct SamlSloBody {
    #[serde(rename = "SAMLRequest")]
    saml_request: Option<String>,
    #[serde(rename = "SAMLResponse")]
    saml_response: Option<String>,
    #[serde(rename = "RelayState")]
    relay_state: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SamlLogoutBody {
    #[serde(alias = "callbackURL")]
    callback_url: Option<String>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SamlLogoutRequestRecord {
    id: String,
    provider_id: String,
    session_id: String,
    session_lookup_key: String,
    callback_url: String,
    created_at: i64,
    expires_at: i64,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SamlSessionRecord {
    pub(super) session_id: String,
    pub(super) provider_id: String,
    pub(super) name_id: String,
    pub(super) session_index: Option<String>,
}

pub(super) fn endpoint(options: Arc<SsoOptions>, method: Method) -> AsyncAuthEndpoint {
    let mut endpoint_options = AuthEndpointOptions::new()
        .operation_id("handleSAMLSLO")
        .openapi(
            OpenApiOperation::new("handleSAMLSLO")
                .tag("SSO")
                .response("302", redirect_response("SAML SLO redirect"))
                .response("200", openapi_html_response("SAML SLO POST binding form")),
        );
    if method == Method::POST {
        endpoint_options = endpoint_options
            .allowed_media_types(["application/json", "application/x-www-form-urlencoded"])
            .body_schema(saml_slo_body_schema())
            .bypass_origin_security();
    } else {
        endpoint_options = endpoint_options.bypass_origin_security();
    }

    create_auth_endpoint(
        "/sso/saml2/sp/slo/:providerId",
        method.clone(),
        endpoint_options,
        move |context, request| {
            let options = Arc::clone(&options);
            let method = method.clone();
            Box::pin(async move { handle_slo(context, options, method, request).await })
        },
    )
}

async fn handle_slo(
    context: &AuthContext,
    options: Arc<SsoOptions>,
    method: Method,
    request: ApiRequest,
) -> Result<ApiResponse, openauth_core::error::OpenAuthError> {
    if !options.saml.enable_single_logout {
        return utils::json(
            http::StatusCode::BAD_REQUEST,
            &json!({"code": "SINGLE_LOGOUT_NOT_ENABLED"}),
        );
    }
    let Some(provider_id) = path_param(&request, "providerId") else {
        return utils::json(
            http::StatusCode::BAD_REQUEST,
            &json!({"code": "MISSING_PROVIDER_ID"}),
        );
    };
    let Some(adapter) = context.adapter.as_deref() else {
        return unauthorized();
    };
    let Some(provider) = find_saml_provider(&options, adapter, &provider_id).await? else {
        return utils::json(
            http::StatusCode::NOT_FOUND,
            &json!({"code": "SAML_PROVIDER_NOT_FOUND"}),
        );
    };
    let Some(config) = provider
        .saml_config
        .as_deref()
        .and_then(|value| serde_json::from_str::<SamlConfig>(value).ok())
    else {
        return utils::json(
            http::StatusCode::BAD_REQUEST,
            &json!({"code": "SAML_PROVIDER_NOT_CONFIGURED"}),
        );
    };

    let body = slo_body_from_request(&method, &request);
    if let Some(encoded_response) = body.saml_response {
        let parsed = match parse_verified_logout_response(
            context,
            &options,
            &request,
            &method,
            &provider,
            &config,
            &encoded_response,
        )
        .await?
        {
            Ok(parsed) => parsed,
            Err(response) => return Ok(response),
        };
        return handle_saml_logout_response(
            context,
            adapter,
            &options,
            &provider_id,
            parsed.message,
            body.relay_state.as_deref(),
            parsed.signature_verified,
        )
        .await;
    }
    let Some(encoded_request) = body.saml_request else {
        return redirect_with_error(
            &format!(
                "{}/sso/saml2/sp/slo/{}",
                context.base_url.trim_end_matches('/'),
                provider_id
            ),
            "missing_logout_data",
        );
    };
    let parsed = match parse_verified_logout_request(
        context,
        &options,
        &request,
        &method,
        &provider,
        &config,
        &encoded_request,
    )
    .await?
    {
        Ok(parsed) => parsed,
        Err(response) => return Ok(response),
    };
    handle_saml_logout_request(
        SamlLogoutRequestHandlerInput {
            context,
            adapter,
            options: &options,
            config: &config,
            provider_id: &provider_id,
            relay_state: body.relay_state.as_deref(),
            signature_verified: parsed.signature_verified,
        },
        parsed.message,
    )
    .await
}

fn slo_body_from_request(method: &Method, request: &ApiRequest) -> SamlSloBody {
    if method == Method::GET {
        return SamlSloBody {
            saml_request: query_param(request, "SAMLRequest"),
            saml_response: query_param(request, "SAMLResponse"),
            relay_state: query_param(request, "RelayState"),
        };
    }
    parse_request_body::<SamlSloBody>(request).unwrap_or_default()
}

struct SamlLogoutRequestHandlerInput<'a> {
    context: &'a AuthContext,
    adapter: &'a dyn DbAdapter,
    options: &'a SsoOptions,
    config: &'a SamlConfig,
    provider_id: &'a str,
    relay_state: Option<&'a str>,
    signature_verified: bool,
}

async fn handle_saml_logout_response(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    options: &SsoOptions,
    provider_id: &str,
    parsed: ParsedSamlLogoutResponse,
    relay_state: Option<&str>,
    signature_verified: bool,
) -> Result<openauth_core::api::ApiResponse, openauth_core::error::OpenAuthError> {
    if parsed.has_signature && !signature_verified {
        audit::emit(
            context,
            options,
            SsoAuditEvent::new(
                SsoAuditEventKind::SamlSignatureFailed,
                SsoAuditSeverity::Warn,
            )
            .reason("SAML_SIGNATURE_VALIDATION_NOT_IMPLEMENTED"),
        )
        .await;
        return utils::json(
            http::StatusCode::BAD_REQUEST,
            &json!({"code": "SAML_SIGNATURE_VALIDATION_NOT_IMPLEMENTED"}),
        );
    }
    if options.saml.want_logout_response_signed && !signature_verified {
        audit::emit(
            context,
            options,
            SsoAuditEvent::new(
                SsoAuditEventKind::SamlSignatureFailed,
                SsoAuditSeverity::Warn,
            )
            .reason("SAML_LOGOUT_RESPONSE_SIGNATURE_REQUIRED"),
        )
        .await;
        return utils::json(
            http::StatusCode::BAD_REQUEST,
            &json!({"code": "SAML_LOGOUT_RESPONSE_SIGNATURE_REQUIRED"}),
        );
    }
    if parsed
        .status_code
        .as_deref()
        .is_some_and(|status| status != "urn:oasis:names:tc:SAML:2.0:status:Success")
    {
        return utils::json(
            http::StatusCode::BAD_REQUEST,
            &json!({"code": "LOGOUT_FAILED_AT_IDP"}),
        );
    }
    let stored_callback_url = if let Some(in_response_to) = parsed.in_response_to {
        let state_store = SsoStateStore::new(context, adapter);
        let identifier = logout_request_key(&in_response_to);
        let Some(state) = state_store.find(&identifier).await? else {
            return utils::json(
                http::StatusCode::BAD_REQUEST,
                &json!({"code": "UNKNOWN_LOGOUT_REQUEST"}),
            );
        };
        let record = match serde_json::from_str::<SamlLogoutRequestRecord>(&state.value) {
            Ok(record) => record,
            Err(_) => {
                return utils::json(
                    http::StatusCode::BAD_REQUEST,
                    &json!({"code": "INVALID_LOGOUT_REQUEST_STATE"}),
                );
            }
        };
        if record.provider_id != provider_id {
            return utils::json(
                http::StatusCode::BAD_REQUEST,
                &json!({"code": "SAML_IN_RESPONSE_TO_PROVIDER_MISMATCH"}),
            );
        }
        let callback_url = record.callback_url;
        state_store.delete(&identifier).await?;
        Some(callback_url)
    } else {
        None
    };
    let redirect_url = stored_callback_url
        .as_deref()
        .or(relay_state)
        .and_then(|value| utils::safe_redirect_url(context, value))
        .unwrap_or_else(|| context.base_url.clone());
    redirect(&redirect_url)
}

async fn handle_saml_logout_request(
    input: SamlLogoutRequestHandlerInput<'_>,
    parsed: ParsedSamlLogoutRequest,
) -> Result<openauth_core::api::ApiResponse, openauth_core::error::OpenAuthError> {
    if parsed.has_signature && !input.signature_verified {
        audit::emit(
            input.context,
            input.options,
            SsoAuditEvent::new(
                SsoAuditEventKind::SamlSignatureFailed,
                SsoAuditSeverity::Warn,
            )
            .provider_id(input.provider_id.to_owned())
            .reason("SAML_SIGNATURE_VALIDATION_NOT_IMPLEMENTED"),
        )
        .await;
        return utils::json(
            http::StatusCode::BAD_REQUEST,
            &json!({"code": "SAML_SIGNATURE_VALIDATION_NOT_IMPLEMENTED"}),
        );
    }
    if input.options.saml.want_logout_request_signed && !input.signature_verified {
        audit::emit(
            input.context,
            input.options,
            SsoAuditEvent::new(
                SsoAuditEventKind::SamlSignatureFailed,
                SsoAuditSeverity::Warn,
            )
            .provider_id(input.provider_id.to_owned())
            .reason("SAML_LOGOUT_REQUEST_SIGNATURE_REQUIRED"),
        )
        .await;
        return utils::json(
            http::StatusCode::BAD_REQUEST,
            &json!({"code": "SAML_LOGOUT_REQUEST_SIGNATURE_REQUIRED"}),
        );
    }
    if let Some(name_id) = &parsed.name_id {
        let state_store = SsoStateStore::new(input.context, input.adapter);
        let session_key = saml_session_key(input.provider_id, name_id);
        if let Some(record) = state_store.find(&session_key).await? {
            if let Ok(session_state) = serde_json::from_str::<SamlSessionRecord>(&record.value) {
                let session_matches = parsed.session_index.is_none()
                    || session_state.session_index.is_none()
                    || parsed.session_index == session_state.session_index;
                if session_matches {
                    delete_session_by_id(input.adapter, &session_state.session_id).await?;
                    state_store
                        .delete(&saml_session_by_id_key(&session_state.session_id))
                        .await?;
                    state_store.delete(&session_key).await?;
                    audit::emit(
                        input.context,
                        input.options,
                        SsoAuditEvent::new(
                            SsoAuditEventKind::SamlSloSessionDeleted,
                            SsoAuditSeverity::Warn,
                        )
                        .provider_id(input.provider_id.to_owned())
                        .reason("logout_request"),
                    )
                    .await;
                }
            }
        }
    }

    let response = build_logout_response_binding(
        input.config,
        &logout_build_context(
            input.context,
            input.provider_id,
            input.config,
            input.options,
        ),
        format!("id-{}", generate_random_string(32)),
        &parsed.id,
        input.relay_state,
    )
    .map_err(|error| openauth_core::error::OpenAuthError::Api(error.to_string()))?;

    saml_binding_response(response)
}

async fn delete_session_by_id(
    adapter: &dyn DbAdapter,
    session_id: &str,
) -> Result<(), openauth_core::error::OpenAuthError> {
    adapter
        .delete(
            Delete::new("session")
                .where_clause(Where::new("id", DbValue::String(session_id.to_owned()))),
        )
        .await
}

fn saml_binding_response(
    response: SamlLogoutBindingResponse,
) -> Result<openauth_core::api::ApiResponse, openauth_core::error::OpenAuthError> {
    match response.binding {
        SamlLogoutBinding::Redirect { url } => redirect(&url),
        SamlLogoutBinding::Post { html } => html_response(html, Vec::new()),
    }
}

fn saml_binding_response_with_cookies(
    response: SamlLogoutBindingResponse,
    cookies: Vec<openauth_core::cookies::Cookie>,
) -> Result<openauth_core::api::ApiResponse, openauth_core::error::OpenAuthError> {
    match response.binding {
        SamlLogoutBinding::Redirect { url } => redirect_with_cookies(&url, cookies),
        SamlLogoutBinding::Post { html } => html_response(html, cookies),
    }
}

fn html_response(
    html: String,
    cookies: Vec<openauth_core::cookies::Cookie>,
) -> Result<openauth_core::api::ApiResponse, openauth_core::error::OpenAuthError> {
    let mut response = http::Response::builder()
        .status(http::StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(html.into_bytes())
        .map_err(|error| openauth_core::error::OpenAuthError::Api(error.to_string()))?;
    for cookie in cookies {
        response.headers_mut().append(
            header::SET_COOKIE,
            http::HeaderValue::from_str(&serialize_cookie(&cookie))
                .map_err(|error| openauth_core::error::OpenAuthError::Cookie(error.to_string()))?,
        );
    }
    Ok(response)
}

fn logout_build_context<'a>(
    context: &'a AuthContext,
    provider_id: &'a str,
    config: &'a SamlConfig,
    options: &SsoOptions,
) -> SamlLogoutBuildContext<'a> {
    SamlLogoutBuildContext {
        config,
        base_url: &context.base_url,
        provider_id,
        build_options: logout_build_options(options),
    }
}

pub(super) fn logout_build_options(options: &SsoOptions) -> SpBuildOptions {
    SpBuildOptions {
        clock_skew: std::time::Duration::from_secs(
            options.saml.clock_skew.whole_seconds().unsigned_abs(),
        ),
        single_logout_enabled: options.saml.enable_single_logout,
        want_logout_request_signed: options.saml.want_logout_request_signed,
        want_logout_response_signed: options.saml.want_logout_response_signed,
        ..Default::default()
    }
}

pub(super) fn logout_endpoint(options: Arc<SsoOptions>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/sso/saml2/logout/:providerId",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("initiateSAMLSLO")
            .body_schema(saml_logout_body_schema())
            .openapi(
                OpenApiOperation::new("initiateSAMLSLO")
                    .tag("SSO")
                    .response("302", redirect_response("SAML logout redirect"))
                    .response(
                        "200",
                        openapi_html_response("SAML logout POST binding form"),
                    ),
            ),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                let Some(provider_id) = path_param(&request, "providerId") else {
                    return utils::json(
                        http::StatusCode::BAD_REQUEST,
                        &json!({"code": "MISSING_PROVIDER_ID"}),
                    );
                };
                let Some(adapter) = context.adapter.as_deref() else {
                    return unauthorized();
                };
                let cookie_header = request
                    .headers()
                    .get(http::header::COOKIE)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_owned();
                let Some(session_result) = SessionAuth::new(adapter, context)
                    .get_session(GetSessionInput::new(cookie_header.clone()).disable_refresh())
                    .await?
                else {
                    return unauthorized();
                };
                let Some(session) = session_result.session else {
                    return unauthorized();
                };
                let user_email = session_result
                    .user
                    .as_ref()
                    .map(|user| user.email.as_str())
                    .unwrap_or_default();

                let state_store = SsoStateStore::new(context, adapter);
                let by_id_identifier = saml_session_by_id_key(&session.id);
                if let Some(by_id) = state_store.find(&by_id_identifier).await? {
                    let provider_prefix = format!("saml-session:{provider_id}:");
                    if by_id.value.starts_with(&provider_prefix) {
                        if !options.saml.enable_single_logout {
                            return utils::json(
                                http::StatusCode::BAD_REQUEST,
                                &json!({"code": "SINGLE_LOGOUT_NOT_ENABLED"}),
                            );
                        }
                        let Some(provider) =
                            find_saml_provider(&options, adapter, &provider_id).await?
                        else {
                            return utils::json(
                                http::StatusCode::NOT_FOUND,
                                &json!({"code": "SAML_PROVIDER_NOT_FOUND"}),
                            );
                        };
                        let Some(config) = provider
                            .saml_config
                            .as_deref()
                            .and_then(|value| serde_json::from_str::<SamlConfig>(value).ok())
                        else {
                            return utils::json(
                                http::StatusCode::BAD_REQUEST,
                                &json!({"code": "SAML_PROVIDER_NOT_CONFIGURED"}),
                            );
                        };
                        let Some(session_state) =
                            state_store.find(&by_id.value).await?.and_then(|record| {
                                serde_json::from_str::<SamlSessionRecord>(&record.value).ok()
                            })
                        else {
                            return utils::json(
                                http::StatusCode::BAD_REQUEST,
                                &json!({"code": "SAML_SESSION_NOT_FOUND"}),
                            );
                        };
                        let body = parse_request_body::<SamlLogoutBody>(&request)
                            .unwrap_or_else(|_| SamlLogoutBody::default());
                        let raw_callback_url = body
                            .callback_url
                            .filter(|value| !value.is_empty())
                            .unwrap_or_else(|| context.base_url.clone());
                        let callback_url = match safe_redirect_field(
                            context,
                            raw_callback_url,
                            "INVALID_CALLBACK_URL",
                        )? {
                            Ok(url) => url,
                            Err(response) => return Ok(response),
                        };
                        let request_id = format!("id-{}", generate_random_string(32));
                        let logout_request = build_logout_request_binding(
                            &config,
                            &logout_build_context(context, &provider_id, &config, options.as_ref()),
                            SamlLogoutRequestInput {
                                request_id: request_id.clone(),
                                relay_state: callback_url.clone(),
                                name_id: if session_state.name_id.is_empty() {
                                    user_email.to_owned()
                                } else {
                                    session_state.name_id
                                },
                                session_index: session_state.session_index,
                            },
                        )
                        .map_err(|error| {
                            openauth_core::error::OpenAuthError::Api(error.to_string())
                        })?;
                        let now = OffsetDateTime::now_utc();
                        state_store
                            .create(
                                logout_request_key(&logout_request.id),
                                serde_json::to_string(&SamlLogoutRequestRecord {
                                    id: logout_request.id.clone(),
                                    provider_id,
                                    session_id: session.id.clone(),
                                    session_lookup_key: by_id.value.clone(),
                                    callback_url,
                                    created_at: now.unix_timestamp(),
                                    expires_at: (now + options.saml.logout_request_ttl)
                                        .unix_timestamp(),
                                })
                                .map_err(|error| {
                                    openauth_core::error::OpenAuthError::Api(format!(
                                        "failed to serialize SAML LogoutRequest state: {error}"
                                    ))
                                })?,
                                now + options.saml.logout_request_ttl,
                            )
                            .await?;
                        state_store.delete(&by_id.value).await?;
                        state_store.delete(&by_id_identifier).await?;
                        let result = SessionAuth::new(adapter, context)
                            .sign_out(cookie_header)
                            .await?;
                        return saml_binding_response_with_cookies(logout_request, result.cookies);
                    }
                }

                let result = SessionAuth::new(adapter, context)
                    .sign_out(cookie_header)
                    .await?;
                json_response(
                    http::StatusCode::OK,
                    &json!({ "success": result.success }),
                    result.cookies,
                )
            })
        },
    )
}

async fn find_saml_provider(
    options: &SsoOptions,
    adapter: &dyn DbAdapter,
    provider_id: &str,
) -> Result<Option<SsoProviderRecord>, openauth_core::error::OpenAuthError> {
    if let Some(provider) = super::sign_in::default_sso_by_provider_id(options, provider_id)? {
        return Ok(Some(provider));
    }
    SsoProviderStore::new_with_options(adapter, options)
        .find_by_provider_id(provider_id)
        .await
}
