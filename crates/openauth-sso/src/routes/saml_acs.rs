use std::sync::Arc;

use base64::Engine;
use http::Method;
use openauth_core::api::{
    create_auth_endpoint, parse_request_body, session_cookies, ApiRequest, ApiResponse,
    AsyncAuthEndpoint, AuthEndpointOptions, OpenApiOperation,
};
use openauth_core::auth::oauth::{
    handle_oauth_user_info, HandleOAuthUserInfoInput, OAuthAccountInput, OAuthUserInfo,
};
use openauth_core::context::AuthContext;
use serde::Deserialize;
use serde_json::json;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::audit;
use crate::linking_impl::{
    assign_organization_from_provider, provider_matches_email_domain, provision_sso_user,
    NormalizedSsoProfile,
};
use crate::openapi::saml_acs_body_schema;
use crate::options::{
    SamlConfig, SamlMapping, SsoAuditEvent, SsoAuditEventKind, SsoAuditSeverity, SsoOptions,
};
use crate::saml_impl::assertions::{
    parse_saml_login_response, ParsedSamlResponse, SamlLoginParseContext,
};
use crate::saml_impl::authn_request::assertion_consumer_service_url;
use crate::saml_impl::security::{
    validate_saml_runtime_algorithms, validate_saml_timestamp, SamlRuntimeAlgorithmPolicy,
    TimestampValidationOptions,
};
use crate::saml_impl::signature::{
    verify_signed_saml_response, SamlSignedElement, VerifiedSamlSignature,
};
use crate::saml_impl::state::{
    authn_request_key, saml_session_by_id_key, saml_session_key, used_assertion_key,
};
use crate::state::SsoStateStore;
use crate::store::SsoProviderStore;
use crate::utils;
use openauth_saml::SpBuildOptions;

use super::support::{
    authenticated_session_user, path_param, query_param, redirect, redirect_with_cookies,
    redirect_with_error,
};

#[derive(Debug, Deserialize)]
struct SamlAcsBody {
    #[serde(rename = "SAMLResponse")]
    saml_response: Option<String>,
    #[serde(rename = "RelayState")]
    relay_state: Option<String>,
}

pub(super) fn endpoint(
    options: Arc<SsoOptions>,
    path: &'static str,
    operation_id: &'static str,
) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        path,
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id(operation_id)
            .allowed_media_types(["application/json", "application/x-www-form-urlencoded"])
            .body_schema(saml_acs_body_schema())
            .hide_from_openapi()
            .bypass_origin_security()
            .openapi(OpenApiOperation::new(operation_id).tag("SSO")),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move { handle_acs(context, Arc::clone(&options), request).await })
        },
    )
}

async fn handle_acs(
    context: &AuthContext,
    options: Arc<SsoOptions>,
    request: ApiRequest,
) -> Result<ApiResponse, openauth_core::error::OpenAuthError> {
    let Some(provider_id) = path_param(&request, "providerId") else {
        return utils::json(
            http::StatusCode::BAD_REQUEST,
            &json!({"code": "MISSING_PROVIDER_ID"}),
        );
    };
    let body = parse_request_body::<SamlAcsBody>(&request)?;
    let relay_state = body.relay_state.as_deref();
    let Some(adapter) = context.adapter.as_deref() else {
        return utils::json(
            http::StatusCode::NOT_FOUND,
            &json!({"code": "PROVIDER_NOT_FOUND"}),
        );
    };
    let (provider, config) =
        match load_saml_provider(options.as_ref(), adapter, &provider_id).await? {
            SamlProviderLoadResult::Found(provider, config) => (*provider, *config),
            SamlProviderLoadResult::NotFound => {
                return utils::json(
                    http::StatusCode::NOT_FOUND,
                    &json!({"code": "PROVIDER_NOT_FOUND"}),
                );
            }
            SamlProviderLoadResult::InvalidConfig => {
                return utils::json(
                    http::StatusCode::BAD_REQUEST,
                    &json!({"code": "INVALID_SAML_CONFIG"}),
                );
            }
        };
    let Some(saml_response) = body.saml_response else {
        let state_store = SsoStateStore::new(context, adapter);
        let authn_record =
            match load_authn_record_by_relay_state(options.as_ref(), &state_store, relay_state)
                .await?
            {
                Ok(record) => record,
                Err(response) => return Ok(response),
            };
        return acs_error_response(
            context,
            &config,
            authn_record.as_ref(),
            http::StatusCode::BAD_REQUEST,
            "MISSING_SAML_RESPONSE",
        );
    };
    let state_store = SsoStateStore::new(context, adapter);
    let validated = match parse_and_validate_saml_response(
        context,
        options.as_ref(),
        &provider,
        &config,
        &state_store,
        relay_state,
        &saml_response,
    )
    .await?
    {
        Ok(parsed) => parsed,
        Err(response) => return Ok(response),
    };
    let user_info =
        match saml_user_info(&validated.parsed, config.mapping.as_ref(), options.as_ref()) {
            Some(user_info) => user_info,
            None => {
                return utils::json(
                    http::StatusCode::BAD_REQUEST,
                    &json!({"code": "UNABLE_TO_EXTRACT_SAML_USER"}),
                );
            }
        };
    if !provider_matches_email_domain(&provider, &user_info.email) {
        return utils::json(
            http::StatusCode::BAD_REQUEST,
            &json!({"code": "INVALID_EMAIL_DOMAIN"}),
        );
    }

    complete_saml_login(SamlLoginInput {
        context,
        adapter,
        options: options.as_ref(),
        state_store: &state_store,
        provider: &provider,
        config: &config,
        authn_record: validated.authn_record.as_ref(),
        parsed: &validated.parsed,
        user_info,
    })
    .await
}

enum SamlProviderLoadResult {
    Found(Box<crate::SsoProviderRecord>, Box<SamlConfig>),
    NotFound,
    InvalidConfig,
}

async fn load_saml_provider(
    options: &SsoOptions,
    adapter: &dyn openauth_core::db::DbAdapter,
    provider_id: &str,
) -> Result<SamlProviderLoadResult, openauth_core::error::OpenAuthError> {
    let provider =
        if let Some(provider) = super::sign_in::default_sso_by_provider_id(options, provider_id)? {
            Some(provider)
        } else {
            SsoProviderStore::new_with_options(adapter, options)
                .find_by_provider_id(provider_id)
                .await?
        };
    let Some(provider) = provider else {
        return Ok(SamlProviderLoadResult::NotFound);
    };
    let Some(config) = provider
        .saml_config
        .as_deref()
        .and_then(|value| serde_json::from_str::<SamlConfig>(value).ok())
    else {
        return Ok(SamlProviderLoadResult::InvalidConfig);
    };
    Ok(SamlProviderLoadResult::Found(
        Box::new(provider),
        Box::new(config),
    ))
}

async fn load_authn_record_by_relay_state(
    options: &SsoOptions,
    state_store: &SsoStateStore<'_>,
    relay_state: Option<&str>,
) -> Result<
    Result<Option<super::sign_in::SamlAuthnRequestRecord>, ApiResponse>,
    openauth_core::error::OpenAuthError,
> {
    if !options.saml.enable_in_response_to_validation {
        return Ok(Ok(None));
    }
    if let Some(relay_state) = relay_state.filter(|value| !value.is_empty()) {
        let identifier = authn_request_key(relay_state);
        let Some(state) = state_store.find(&identifier).await? else {
            return Ok(Err(utils::json(
                http::StatusCode::BAD_REQUEST,
                &json!({"code": "UNKNOWN_AUTHN_REQUEST"}),
            )?));
        };
        let record =
            match serde_json::from_str::<super::sign_in::SamlAuthnRequestRecord>(&state.value) {
                Ok(record) => record,
                Err(_) => {
                    return Ok(Err(utils::json(
                        http::StatusCode::BAD_REQUEST,
                        &json!({"code": "INVALID_AUTHN_REQUEST_STATE"}),
                    )?));
                }
            };
        return Ok(Ok(Some(record)));
    }
    if !options.saml.allow_idp_initiated {
        return Ok(Err(utils::json(
            http::StatusCode::BAD_REQUEST,
            &json!({"code": "MISSING_RELAY_STATE"}),
        )?));
    }
    Ok(Ok(None))
}

async fn load_authn_record_for_response(
    options: &SsoOptions,
    state_store: &SsoStateStore<'_>,
    provider_id: &str,
    relay_state: Option<&str>,
    parsed: &ParsedSamlResponse,
) -> Result<
    Result<Option<super::sign_in::SamlAuthnRequestRecord>, ApiResponse>,
    openauth_core::error::OpenAuthError,
> {
    if !options.saml.enable_in_response_to_validation {
        return Ok(Ok(None));
    }

    let in_response_to = parsed.response_in_response_to.as_deref().or_else(|| {
        parsed
            .assertion
            .subject_confirmation
            .as_ref()
            .and_then(|confirmation| confirmation.in_response_to.as_deref())
    });
    let request_id = relay_state
        .filter(|value| !value.is_empty())
        .or(in_response_to);

    if let Some(request_id) = request_id {
        let identifier = authn_request_key(request_id);
        let Some(state) = state_store.find(&identifier).await? else {
            return Ok(Err(utils::json(
                http::StatusCode::BAD_REQUEST,
                &json!({"code": "UNKNOWN_AUTHN_REQUEST"}),
            )?));
        };
        let Some(record) =
            serde_json::from_str::<super::sign_in::SamlAuthnRequestRecord>(&state.value).ok()
        else {
            return Ok(Err(utils::json(
                http::StatusCode::BAD_REQUEST,
                &json!({"code": "INVALID_AUTHN_REQUEST_STATE"}),
            )?));
        };
        if record.provider_id != provider_id {
            return Ok(Err(utils::json(
                http::StatusCode::BAD_REQUEST,
                &json!({"code": "SAML_IN_RESPONSE_TO_PROVIDER_MISMATCH"}),
            )?));
        }
        return Ok(Ok(Some(record)));
    }

    if !options.saml.allow_idp_initiated {
        return Ok(Err(utils::json(
            http::StatusCode::BAD_REQUEST,
            &json!({"code": "MISSING_RELAY_STATE"}),
        )?));
    }
    Ok(Ok(None))
}

struct ValidatedSamlResponse {
    parsed: ParsedSamlResponse,
    authn_record: Option<super::sign_in::SamlAuthnRequestRecord>,
}

async fn parse_and_validate_saml_response(
    context: &AuthContext,
    options: &SsoOptions,
    provider: &crate::SsoProviderRecord,
    config: &SamlConfig,
    state_store: &SsoStateStore<'_>,
    relay_state: Option<&str>,
    saml_response: &str,
) -> Result<Result<ValidatedSamlResponse, ApiResponse>, openauth_core::error::OpenAuthError> {
    let relay_authn_record = if relay_state.is_some_and(|value| !value.is_empty()) {
        match load_authn_record_by_relay_state(options, state_store, relay_state).await? {
            Ok(record) => record,
            Err(response) => return Ok(Err(response)),
        }
    } else {
        None
    };
    if saml_response.len() > options.saml.max_response_size {
        return Ok(Err(acs_error_response(
            context,
            config,
            relay_authn_record.as_ref(),
            http::StatusCode::PAYLOAD_TOO_LARGE,
            "SAML_RESPONSE_TOO_LARGE",
        )?));
    }

    if let Ok(compact) = std::str::from_utf8(saml_response.as_bytes()) {
        let compact = compact.split_whitespace().collect::<String>();
        if let Ok(bytes) = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            compact.as_bytes(),
        ) {
            if let Ok(xml) = String::from_utf8(bytes) {
                if let Ok(algorithms) =
                    crate::saml_impl::security::collect_saml_runtime_algorithms(&xml)
                {
                    if let Err(error) = validate_saml_runtime_algorithms(
                        &algorithms,
                        SamlRuntimeAlgorithmPolicy {
                            on_deprecated: options.saml.algorithms.on_deprecated,
                            allowed_signature_algorithms: options
                                .saml
                                .algorithms
                                .allowed_signature_algorithms
                                .as_deref(),
                            allowed_digest_algorithms: options
                                .saml
                                .algorithms
                                .allowed_digest_algorithms
                                .as_deref(),
                            allowed_key_encryption_algorithms: options
                                .saml
                                .algorithms
                                .allowed_key_encryption_algorithms
                                .as_deref(),
                            allowed_data_encryption_algorithms: options
                                .saml
                                .algorithms
                                .allowed_data_encryption_algorithms
                                .as_deref(),
                        },
                    ) {
                        return Ok(Err(acs_error_response(
                            context,
                            config,
                            relay_authn_record.as_ref(),
                            http::StatusCode::BAD_REQUEST,
                            super::saml_runtime_algorithm_error_code(&error),
                        )?));
                    }
                }
            }
        }
    }

    let parsed = match parse_saml_login_response(
        saml_response,
        &SamlLoginParseContext {
            config,
            base_url: &context.base_url,
            provider_id: &provider.provider_id,
            in_response_to: relay_authn_record.as_ref().map(|record| record.id.as_str()),
            build_options: SpBuildOptions {
                clock_skew: std::time::Duration::from_secs(
                    options.saml.clock_skew.whole_seconds().unsigned_abs(),
                ),
                single_logout_enabled: options.saml.enable_single_logout,
                want_logout_request_signed: options.saml.want_logout_request_signed,
                want_logout_response_signed: options.saml.want_logout_response_signed,
                ..Default::default()
            },
        },
    ) {
        Ok(parsed) => parsed,
        Err(error) => {
            return Ok(Err(acs_error_response(
                context,
                config,
                relay_authn_record.as_ref(),
                error.status(),
                error.code(),
            )?));
        }
    };
    let authn_record = if relay_authn_record.is_some() {
        relay_authn_record
    } else {
        match load_authn_record_for_response(
            options,
            state_store,
            &provider.provider_id,
            relay_state,
            &parsed,
        )
        .await?
        {
            Ok(record) => record,
            Err(response) => return Ok(Err(response)),
        }
    };
    if authn_record
        .as_ref()
        .is_some_and(|record| record.provider_id != provider.provider_id)
    {
        return Ok(Err(utils::json(
            http::StatusCode::BAD_REQUEST,
            &json!({"code": "SAML_IN_RESPONSE_TO_PROVIDER_MISMATCH"}),
        )?));
    }
    if let Err(error) = validate_saml_runtime_algorithms(
        &parsed.algorithms,
        SamlRuntimeAlgorithmPolicy {
            on_deprecated: options.saml.algorithms.on_deprecated,
            allowed_signature_algorithms: options
                .saml
                .algorithms
                .allowed_signature_algorithms
                .as_deref(),
            allowed_digest_algorithms: options.saml.algorithms.allowed_digest_algorithms.as_deref(),
            allowed_key_encryption_algorithms: options
                .saml
                .algorithms
                .allowed_key_encryption_algorithms
                .as_deref(),
            allowed_data_encryption_algorithms: options
                .saml
                .algorithms
                .allowed_data_encryption_algorithms
                .as_deref(),
        },
    ) {
        return Ok(Err(acs_error_response(
            context,
            config,
            authn_record.as_ref(),
            http::StatusCode::BAD_REQUEST,
            super::saml_runtime_algorithm_error_code(&error),
        )?));
    }
    let verified_signature =
        match verify_saml_signature(context, options, provider, config, &parsed, saml_response)
            .await?
        {
            Ok(signature) => signature,
            Err(response) => return Ok(Err(response)),
        };
    if let Err(code) = validate_parsed_saml_response(
        &parsed,
        provider,
        config,
        &context.base_url,
        options,
        authn_record.as_ref(),
        verified_signature.as_ref(),
    ) {
        return Ok(Err(acs_error_response(
            context,
            config,
            authn_record.as_ref(),
            http::StatusCode::BAD_REQUEST,
            code,
        )?));
    }
    Ok(Ok(ValidatedSamlResponse {
        parsed,
        authn_record,
    }))
}

async fn verify_saml_signature(
    context: &AuthContext,
    options: &SsoOptions,
    provider: &crate::SsoProviderRecord,
    config: &SamlConfig,
    parsed: &ParsedSamlResponse,
    saml_response: &str,
) -> Result<Result<Option<VerifiedSamlSignature>, ApiResponse>, openauth_core::error::OpenAuthError>
{
    if parsed.signature_verified {
        let element = if parsed.signature.assertion {
            SamlSignedElement::Assertion
        } else {
            SamlSignedElement::Response
        };
        return Ok(Ok(Some(VerifiedSamlSignature { element })));
    }
    if !parsed.signature.is_signed() {
        return Ok(Ok(None));
    }
    match verify_signed_saml_response(saml_response, parsed.signature, &config.cert).await {
        Ok(signature) => Ok(Ok(Some(signature))),
        Err(error) => {
            audit::emit(
                context,
                options,
                SsoAuditEvent::new(
                    SsoAuditEventKind::SamlSignatureFailed,
                    SsoAuditSeverity::Warn,
                )
                .provider_id(provider.provider_id.clone())
                .reason(error.code()),
            )
            .await;
            Ok(Err(super::saml_signature_error_response(error)?))
        }
    }
}

struct SamlLoginInput<'a> {
    context: &'a AuthContext,
    adapter: &'a dyn openauth_core::db::DbAdapter,
    options: &'a SsoOptions,
    state_store: &'a SsoStateStore<'a>,
    provider: &'a crate::SsoProviderRecord,
    config: &'a SamlConfig,
    authn_record: Option<&'a super::sign_in::SamlAuthnRequestRecord>,
    parsed: &'a ParsedSamlResponse,
    user_info: OAuthUserInfo,
}

async fn complete_saml_login(
    input: SamlLoginInput<'_>,
) -> Result<ApiResponse, openauth_core::error::OpenAuthError> {
    let assertion_identifier = used_assertion_key(&input.parsed.assertion.id);
    if input
        .state_store
        .find(&assertion_identifier)
        .await?
        .is_some()
    {
        audit::emit(
            input.context,
            input.options,
            SsoAuditEvent::new(
                SsoAuditEventKind::SamlReplayRejected,
                SsoAuditSeverity::Warn,
            )
            .provider_id(input.provider.provider_id.clone())
            .reason("REPLAYED_SAML_ASSERTION"),
        )
        .await;
        return acs_error_response(
            input.context,
            input.config,
            input.authn_record,
            http::StatusCode::BAD_REQUEST,
            "REPLAYED_SAML_ASSERTION",
        );
    }

    input
        .state_store
        .create(
            assertion_identifier,
            input.provider.provider_id.clone(),
            assertion_replay_expires_at(input.parsed, input.options),
        )
        .await?;
    if let Some(record) = input.authn_record {
        input
            .state_store
            .delete(&authn_request_key(&record.id))
            .await?;
    }

    let callback_url = saml_callback_url(input.context, input.authn_record);
    let result = handle_oauth_user_info(
        input.context,
        input.adapter,
        HandleOAuthUserInfoInput {
            user_info: input.user_info.clone(),
            account: saml_oauth_account(input.provider, &input.user_info),
            callback_url: Some(callback_url.clone()),
            disable_sign_up: input.options.disable_implicit_sign_up
                && !input
                    .authn_record
                    .as_ref()
                    .is_some_and(|record| record.request_sign_up),
            override_user_info: false,
            is_trusted_provider: is_trusted_sso_provider(
                input.options,
                input.provider,
                &input.user_info,
            ),
            require_trusted_provider_for_implicit_link: true,
        },
    )
    .await?;
    let Some(data) = result.data else {
        return utils::json(
            http::StatusCode::BAD_REQUEST,
            &json!({"code": "SAML_SIGN_IN_FAILED"}),
        );
    };
    let profile = normalized_saml_profile(input.provider, &input.user_info);
    provision_sso_user(
        input.options,
        &data.user,
        &profile,
        input.provider,
        None,
        result.is_register,
    )
    .await?;
    assign_organization_from_provider(
        input.context,
        input.adapter,
        &input.options.organization_provisioning,
        &data.user,
        &profile,
        input.provider,
        None,
    )
    .await?;
    record_saml_session_if_enabled(&input, &data.session).await?;

    let target_url = saml_target_url(result.is_register, input.authn_record, &callback_url);
    let target_url = utils::safe_redirect_url(input.context, target_url.as_str())
        .unwrap_or_else(|| input.context.base_url.clone());
    let cookies = session_cookies(input.context, &data.session, &data.user, false)?;
    redirect_with_cookies(&target_url, cookies)
}

fn assertion_replay_expires_at(
    parsed: &ParsedSamlResponse,
    options: &SsoOptions,
) -> OffsetDateTime {
    parsed
        .assertion
        .conditions
        .as_ref()
        .and_then(|conditions| conditions.not_on_or_after.as_deref())
        .or_else(|| {
            parsed
                .assertion
                .subject_confirmation
                .as_ref()
                .and_then(|confirmation| confirmation.conditions.as_ref())
                .and_then(|conditions| conditions.not_on_or_after.as_deref())
        })
        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
        .map(|expires_at| expires_at + options.saml.clock_skew)
        .unwrap_or_else(|| OffsetDateTime::now_utc() + time::Duration::minutes(15))
}

fn saml_callback_url(
    context: &AuthContext,
    authn_record: Option<&super::sign_in::SamlAuthnRequestRecord>,
) -> String {
    let callback_url = authn_record
        .map(|record| record.callback_url.clone())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| context.base_url.clone());
    utils::safe_redirect_url(context, &callback_url).unwrap_or_else(|| context.base_url.clone())
}

fn saml_target_url(
    is_register: bool,
    authn_record: Option<&super::sign_in::SamlAuthnRequestRecord>,
    callback_url: &str,
) -> String {
    if is_register {
        authn_record
            .and_then(|record| record.new_user_url.as_deref())
            .unwrap_or(callback_url)
            .to_owned()
    } else {
        callback_url.to_owned()
    }
}

fn saml_oauth_account(
    provider: &crate::SsoProviderRecord,
    user_info: &OAuthUserInfo,
) -> OAuthAccountInput {
    OAuthAccountInput {
        provider_id: provider.provider_id.clone(),
        account_id: user_info.id.clone(),
        access_token: None,
        refresh_token: None,
        id_token: None,
        access_token_expires_at: None,
        refresh_token_expires_at: None,
        scope: None,
    }
}

fn normalized_saml_profile(
    provider: &crate::SsoProviderRecord,
    user_info: &OAuthUserInfo,
) -> NormalizedSsoProfile {
    NormalizedSsoProfile {
        provider_type: "saml".to_owned(),
        provider_id: provider.provider_id.clone(),
        account_id: user_info.id.clone(),
        email: user_info.email.clone(),
        email_verified: user_info.email_verified,
        name: Some(user_info.name.clone()),
        image: user_info.image.clone(),
        raw_attributes: user_info.raw_attributes.clone(),
        token_data: None,
    }
}

async fn record_saml_session_if_enabled(
    input: &SamlLoginInput<'_>,
    session: &openauth_core::db::Session,
) -> Result<(), openauth_core::error::OpenAuthError> {
    if !input.options.saml.enable_single_logout {
        return Ok(());
    }
    let Some(name_id) = &input.parsed.assertion.name_id else {
        return Ok(());
    };
    let session_key = saml_session_key(&input.provider.provider_id, name_id);
    input
        .state_store
        .create(
            session_key.clone(),
            serde_json::to_string(&super::slo::SamlSessionRecord {
                session_id: session.id.clone(),
                provider_id: input.provider.provider_id.clone(),
                name_id: name_id.clone(),
                session_index: input.parsed.assertion.session_index.clone(),
            })
            .map_err(|error| {
                openauth_core::error::OpenAuthError::Api(format!(
                    "failed to serialize SAML session state: {error}"
                ))
            })?,
            session.expires_at,
        )
        .await?;
    input
        .state_store
        .create(
            saml_session_by_id_key(&session.id),
            session_key,
            session.expires_at,
        )
        .await
}

pub(super) fn get_callback_endpoint() -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/sso/saml2/callback/:providerId",
        Method::GET,
        AuthEndpointOptions::new()
            .operation_id("handleSAMLCallback")
            .hide_from_openapi()
            .openapi(OpenApiOperation::new("handleSAMLCallback").tag("SSO")),
        |context, request| {
            Box::pin(async move {
                let error_url = format!("{}/error", context.base_url.trim_end_matches('/'));
                if authenticated_session_user(context, &request)
                    .await?
                    .is_none()
                {
                    return redirect_with_error(&error_url, "invalid_request");
                }
                let redirect_url = query_param(&request, "RelayState")
                    .and_then(|value| utils::safe_redirect_url(context, &value))
                    .unwrap_or_else(|| base_origin(&context.base_url));
                redirect(&redirect_url)
            })
        },
    )
}

fn base_origin(base_url: &str) -> String {
    url::Url::parse(base_url)
        .map(|url| {
            let mut origin = format!("{}://{}", url.scheme(), url.host_str().unwrap_or_default());
            if let Some(port) = url.port() {
                origin.push(':');
                origin.push_str(&port.to_string());
            }
            origin
        })
        .unwrap_or_else(|_| base_url.trim_end_matches('/').to_owned())
}

fn acs_error_response(
    context: &AuthContext,
    config: &SamlConfig,
    authn_record: Option<&super::sign_in::SamlAuthnRequestRecord>,
    status: http::StatusCode,
    code: &'static str,
) -> Result<openauth_core::api::ApiResponse, openauth_core::error::OpenAuthError> {
    if let Some(location) = acs_error_redirect_url(context, config, authn_record) {
        return redirect_with_error(&location, &error_query_value(code));
    }
    utils::json(status, &json!({"code": code}))
}

fn acs_error_redirect_url(
    context: &AuthContext,
    config: &SamlConfig,
    authn_record: Option<&super::sign_in::SamlAuthnRequestRecord>,
) -> Option<String> {
    authn_record
        .and_then(|record| record.error_url.as_deref())
        .or_else(|| (!config.callback_url.is_empty()).then_some(config.callback_url.as_str()))
        .and_then(|url| utils::safe_redirect_url(context, url))
}

fn error_query_value(code: &str) -> String {
    code.to_ascii_lowercase()
}

fn validate_parsed_saml_response(
    parsed: &ParsedSamlResponse,
    provider: &crate::SsoProviderRecord,
    config: &SamlConfig,
    base_url: &str,
    options: &SsoOptions,
    authn_record: Option<&super::sign_in::SamlAuthnRequestRecord>,
    verified_signature: Option<&VerifiedSamlSignature>,
) -> Result<(), &'static str> {
    if config.want_assertions_signed
        && !verified_signature
            .is_some_and(|signature| signature.element == SamlSignedElement::Assertion)
    {
        return Err("SAML_ASSERTION_SIGNATURE_REQUIRED");
    }
    if parsed
        .status_code
        .as_deref()
        .is_some_and(|status| status != "urn:oasis:names:tc:SAML:2.0:status:Success")
    {
        return Err("SAML_RESPONSE_NOT_SUCCESS");
    }
    let acs_url = assertion_consumer_service_url(&provider.provider_id, base_url, config);
    if parsed
        .response_destination
        .as_deref()
        .is_some_and(|destination| destination != acs_url)
    {
        return Err("SAML_DESTINATION_MISMATCH");
    }
    let expected_issuer = expected_idp_issuer(provider, config);
    if parsed
        .response_issuer
        .as_deref()
        .is_some_and(|issuer| issuer != expected_issuer)
        || parsed
            .assertion
            .issuer
            .as_deref()
            .is_some_and(|issuer| issuer != expected_issuer)
    {
        return Err("SAML_ISSUER_MISMATCH");
    }
    if !parsed.assertion.audiences.is_empty() {
        let expected_audience = expected_saml_audience(config);
        if !parsed
            .assertion
            .audiences
            .iter()
            .any(|audience| audience == expected_audience)
        {
            return Err("SAML_AUDIENCE_MISMATCH");
        }
    }
    if let Some(record) = authn_record {
        let expected = record.id.as_str();
        let response_matches = parsed.response_in_response_to.as_deref() == Some(expected);
        let subject_matches = parsed
            .assertion
            .subject_confirmation
            .as_ref()
            .and_then(|confirmation| confirmation.in_response_to.as_deref())
            == Some(expected);
        if !(response_matches || subject_matches) {
            return Err("SAML_IN_RESPONSE_TO_MISMATCH");
        }
    }
    let timestamp_options = TimestampValidationOptions {
        clock_skew: options.saml.clock_skew,
        require_timestamps: options.saml.require_timestamps,
    };
    validate_saml_timestamp(parsed.assertion.conditions.as_ref(), timestamp_options)
        .map_err(|_| "SAML_TIMESTAMP_INVALID")?;
    if let Some(confirmation) = &parsed.assertion.subject_confirmation {
        if confirmation
            .recipient
            .as_deref()
            .is_some_and(|recipient| recipient != acs_url)
        {
            return Err("SAML_RECIPIENT_MISMATCH");
        }
        validate_saml_timestamp(confirmation.conditions.as_ref(), timestamp_options)
            .map_err(|_| "SAML_TIMESTAMP_INVALID")?;
    }
    Ok(())
}

fn expected_idp_issuer<'a>(
    provider: &'a crate::store::SsoProviderRecord,
    config: &'a SamlConfig,
) -> &'a str {
    config
        .idp_metadata
        .as_ref()
        .and_then(|metadata| metadata.entity_id.as_deref())
        .unwrap_or(provider.issuer.as_str())
}

fn expected_saml_audience(config: &SamlConfig) -> &str {
    config
        .audience
        .as_deref()
        .or(config.sp_metadata.entity_id.as_deref())
        .unwrap_or(config.issuer.as_str())
}

fn saml_user_info(
    parsed: &ParsedSamlResponse,
    mapping: Option<&SamlMapping>,
    options: &SsoOptions,
) -> Option<OAuthUserInfo> {
    let attributes = &parsed.assertion.attributes;
    let name_id = parsed.assertion.name_id.as_deref();
    let mapped = |value: Option<&String>, default: &str| {
        value
            .and_then(|key| attributes.get(key))
            .or_else(|| attributes.get(default))
            .map(String::as_str)
    };
    let id = mapped(mapping.and_then(|mapping| mapping.id.as_ref()), "nameID")
        .or(name_id)?
        .to_owned();
    let email = mapped(mapping.and_then(|mapping| mapping.email.as_ref()), "email")
        .or(name_id)?
        .to_lowercase();
    let first = mapped(
        mapping.and_then(|mapping| mapping.first_name.as_ref()),
        "givenName",
    );
    let last = mapped(
        mapping.and_then(|mapping| mapping.last_name.as_ref()),
        "surname",
    );
    let full_name = [first, last]
        .into_iter()
        .flatten()
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let name = if full_name.is_empty() {
        mapped(
            mapping.and_then(|mapping| mapping.name.as_ref()),
            "displayName",
        )
        .or(name_id)
        .unwrap_or(email.as_str())
        .to_owned()
    } else {
        full_name
    };
    let email_verified = options.trust_email_verified
        && mapping
            .and_then(|mapping| mapping.email_verified.as_ref())
            .and_then(|key| attributes.get(key))
            .is_some_and(|value| value == "true" || value == "1");
    Some(OAuthUserInfo {
        id,
        name,
        email,
        image: None,
        email_verified,
        raw_attributes: mapped_saml_extra_fields(
            attributes,
            mapping.and_then(|mapping| mapping.extra_fields.as_ref()),
        ),
    })
}

fn mapped_saml_extra_fields(
    attributes: &std::collections::BTreeMap<String, String>,
    mapping: Option<&std::collections::BTreeMap<String, String>>,
) -> Option<serde_json::Value> {
    let mapping = mapping?;
    let object = mapping
        .iter()
        .filter_map(|(output_key, source_key)| {
            attributes
                .get(source_key)
                .map(|value| (output_key.clone(), json!(value)))
        })
        .collect::<serde_json::Map<_, _>>();
    (!object.is_empty()).then_some(serde_json::Value::Object(object))
}

fn is_trusted_sso_provider(
    options: &SsoOptions,
    provider: &crate::SsoProviderRecord,
    user_info: &OAuthUserInfo,
) -> bool {
    (options.trust_email_verified && user_info.email_verified)
        || (provider.domain_verified.unwrap_or(false)
            && provider_matches_email_domain(provider, &user_info.email))
}
