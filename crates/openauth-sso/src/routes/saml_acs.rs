use std::sync::Arc;

use http::Method;
use openauth_core::api::{
    create_auth_endpoint, parse_request_body, session_cookies, AsyncAuthEndpoint,
    AuthEndpointOptions, OpenApiOperation,
};
use openauth_core::auth::oauth::{
    handle_oauth_user_info, HandleOAuthUserInfoInput, OAuthAccountInput, OAuthUserInfo,
};
use openauth_core::context::AuthContext;
use serde::Deserialize;
use serde_json::json;
use time::OffsetDateTime;

use crate::audit;
use crate::linking::{
    assign_organization_from_provider, provider_matches_email_domain, provision_sso_user,
    NormalizedSsoProfile,
};
use crate::openapi::saml_acs_body_schema;
use crate::options::{
    SamlConfig, SamlMapping, SsoAuditEvent, SsoAuditEventKind, SsoAuditSeverity, SsoOptions,
};
use crate::saml::assertions::{
    parse_saml_response_with_decryption, ParsedSamlResponse, ENCRYPTED_ASSERTION_UNSUPPORTED,
};
use crate::saml::authn_request::assertion_consumer_service_url;
use crate::saml::security::{
    validate_saml_runtime_algorithms, validate_saml_timestamp, SamlRuntimeAlgorithmPolicy,
    TimestampValidationOptions,
};
use crate::saml::signature::{
    verify_signed_saml_response, SamlSignedElement, VerifiedSamlSignature,
};
use crate::saml::state::{
    authn_request_key, saml_session_by_id_key, saml_session_key, used_assertion_key,
};
use crate::state::SsoStateStore;
use crate::store::SsoProviderStore;
use crate::utils;

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
            Box::pin(async move {
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
                let provider = if let Some(provider) =
                    super::sign_in::default_sso_by_provider_id(&options, &provider_id)?
                {
                    Some(provider)
                } else {
                    SsoProviderStore::new(adapter)
                        .find_by_provider_id(&provider_id)
                        .await?
                };
                let Some(provider) = provider else {
                    return utils::json(
                        http::StatusCode::NOT_FOUND,
                        &json!({"code": "PROVIDER_NOT_FOUND"}),
                    );
                };
                let Some(config) = provider
                    .saml_config
                    .as_deref()
                    .and_then(|value| serde_json::from_str::<SamlConfig>(value).ok())
                else {
                    return utils::json(
                        http::StatusCode::BAD_REQUEST,
                        &json!({"code": "INVALID_SAML_CONFIG"}),
                    );
                };
                let mut authn_record = None;
                let state_store = SsoStateStore::new(context, adapter);
                if options.saml.enable_in_response_to_validation {
                    if let Some(relay_state) = relay_state.filter(|value| !value.is_empty()) {
                        let identifier = authn_request_key(relay_state);
                        let Some(state) = state_store.find(&identifier).await? else {
                            return utils::json(
                                http::StatusCode::BAD_REQUEST,
                                &json!({"code": "UNKNOWN_AUTHN_REQUEST"}),
                            );
                        };
                        authn_record =
                            serde_json::from_str::<super::sign_in::SamlAuthnRequestRecord>(
                                &state.value,
                            )
                            .ok();
                    } else if !options.saml.allow_idp_initiated {
                        return utils::json(
                            http::StatusCode::BAD_REQUEST,
                            &json!({"code": "MISSING_RELAY_STATE"}),
                        );
                    }
                }

                let saml_response = match body.saml_response {
                    Some(saml_response) => saml_response,
                    None => {
                        return acs_error_response(
                            context,
                            &config,
                            authn_record.as_ref(),
                            http::StatusCode::BAD_REQUEST,
                            "MISSING_SAML_RESPONSE",
                        );
                    }
                };
                if saml_response.len() > options.saml.max_response_size {
                    return acs_error_response(
                        context,
                        &config,
                        authn_record.as_ref(),
                        http::StatusCode::PAYLOAD_TOO_LARGE,
                        "SAML_RESPONSE_TOO_LARGE",
                    );
                }

                let parsed = match parse_saml_response_with_decryption(
                    &saml_response,
                    config
                        .decryption_pvk
                        .as_ref()
                        .map(|key| key.expose_secret()),
                ) {
                    Ok(parsed) => parsed,
                    Err(error) if error.to_string().contains(ENCRYPTED_ASSERTION_UNSUPPORTED) => {
                        return acs_error_response(
                            context,
                            &config,
                            authn_record.as_ref(),
                            http::StatusCode::BAD_REQUEST,
                            "ENCRYPTED_SAML_ASSERTION_UNSUPPORTED",
                        )
                    }
                    Err(_) => {
                        return acs_error_response(
                            context,
                            &config,
                            authn_record.as_ref(),
                            http::StatusCode::BAD_REQUEST,
                            "INVALID_SAML_RESPONSE",
                        )
                    }
                };
                if let Err(error) = validate_saml_runtime_algorithms(
                    &parsed.algorithms,
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
                    return acs_error_response(
                        context,
                        &config,
                        authn_record.as_ref(),
                        http::StatusCode::BAD_REQUEST,
                        super::saml_runtime_algorithm_error_code(&error),
                    );
                }
                let verified_signature = if parsed.signature.is_signed() {
                    match verify_signed_saml_response(
                        &saml_response,
                        parsed.signature,
                        &config.cert,
                    )
                    .await
                    {
                        Ok(signature) => Some(signature),
                        Err(error) => {
                            audit::emit(
                                context,
                                &options,
                                SsoAuditEvent::new(
                                    SsoAuditEventKind::SamlSignatureFailed,
                                    SsoAuditSeverity::Warn,
                                )
                                .provider_id(provider.provider_id.clone())
                                .reason(error.code()),
                            )
                            .await;
                            return super::saml_signature_error_response(error);
                        }
                    }
                } else {
                    None
                };
                if let Err(code) = validate_parsed_saml_response(
                    &parsed,
                    &provider,
                    &config,
                    &context.base_url,
                    &options,
                    authn_record.as_ref(),
                    verified_signature.as_ref(),
                ) {
                    return acs_error_response(
                        context,
                        &config,
                        authn_record.as_ref(),
                        http::StatusCode::BAD_REQUEST,
                        code,
                    );
                }

                let assertion_identifier = used_assertion_key(&parsed.assertion.id);
                if state_store.find(&assertion_identifier).await?.is_some() {
                    audit::emit(
                        context,
                        &options,
                        SsoAuditEvent::new(
                            SsoAuditEventKind::SamlReplayRejected,
                            SsoAuditSeverity::Warn,
                        )
                        .provider_id(provider.provider_id.clone())
                        .reason("REPLAYED_SAML_ASSERTION"),
                    )
                    .await;
                    return acs_error_response(
                        context,
                        &config,
                        authn_record.as_ref(),
                        http::StatusCode::BAD_REQUEST,
                        "REPLAYED_SAML_ASSERTION",
                    );
                }

                let Some(user_info) = saml_user_info(&parsed, config.mapping.as_ref(), &options)
                else {
                    return utils::json(
                        http::StatusCode::BAD_REQUEST,
                        &json!({"code": "UNABLE_TO_EXTRACT_SAML_USER"}),
                    );
                };
                if !provider_matches_email_domain(&provider, &user_info.email) {
                    return utils::json(
                        http::StatusCode::BAD_REQUEST,
                        &json!({"code": "INVALID_EMAIL_DOMAIN"}),
                    );
                }

                state_store
                    .create(
                        assertion_identifier,
                        provider.provider_id.clone(),
                        OffsetDateTime::now_utc() + options.saml.request_ttl,
                    )
                    .await?;
                if let Some(record) = &authn_record {
                    state_store.delete(&authn_request_key(&record.id)).await?;
                }

                let callback_url = authn_record
                    .as_ref()
                    .map(|record| record.callback_url.clone())
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| context.base_url.clone());
                let callback_url = utils::safe_redirect_url(context, &callback_url)
                    .unwrap_or_else(|| context.base_url.clone());
                let result = handle_oauth_user_info(
                    context,
                    adapter,
                    HandleOAuthUserInfoInput {
                        user_info: user_info.clone(),
                        account: OAuthAccountInput {
                            provider_id: provider.provider_id.clone(),
                            account_id: user_info.id.clone(),
                            access_token: None,
                            refresh_token: None,
                            id_token: None,
                            access_token_expires_at: None,
                            refresh_token_expires_at: None,
                            scope: None,
                        },
                        callback_url: Some(callback_url.clone()),
                        disable_sign_up: options.disable_implicit_sign_up
                            && !authn_record
                                .as_ref()
                                .is_some_and(|record| record.request_sign_up),
                        override_user_info: false,
                        is_trusted_provider: is_trusted_sso_provider(
                            options.as_ref(),
                            &provider,
                            &user_info,
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
                let profile = NormalizedSsoProfile {
                    provider_type: "saml".to_owned(),
                    provider_id: provider.provider_id.clone(),
                    account_id: user_info.id.clone(),
                    email: user_info.email.clone(),
                    email_verified: user_info.email_verified,
                    name: Some(user_info.name.clone()),
                    image: user_info.image.clone(),
                    raw_attributes: user_info.raw_attributes.clone(),
                    token_data: None,
                };
                provision_sso_user(
                    options.as_ref(),
                    &data.user,
                    &profile,
                    &provider,
                    None,
                    result.is_register,
                )
                .await?;
                assign_organization_from_provider(
                    context,
                    adapter,
                    &options.organization_provisioning,
                    &data.user,
                    &profile,
                    &provider,
                    None,
                )
                .await?;
                if options.saml.enable_single_logout {
                    if let Some(name_id) = &parsed.assertion.name_id {
                        let session_key = saml_session_key(&provider.provider_id, name_id);
                        state_store
                            .create(
                                session_key.clone(),
                                serde_json::to_string(&super::slo::SamlSessionRecord {
                                    session_id: data.session.id.clone(),
                                    provider_id: provider.provider_id.clone(),
                                    name_id: name_id.clone(),
                                    session_index: parsed.assertion.session_index.clone(),
                                })
                                .map_err(|error| {
                                    openauth_core::error::OpenAuthError::Api(format!(
                                        "failed to serialize SAML session state: {error}"
                                    ))
                                })?,
                                data.session.expires_at,
                            )
                            .await?;
                        state_store
                            .create(
                                saml_session_by_id_key(&data.session.id),
                                session_key,
                                data.session.expires_at,
                            )
                            .await?;
                    }
                }
                let target_url = if result.is_register {
                    authn_record
                        .as_ref()
                        .and_then(|record| record.new_user_url.as_deref())
                        .unwrap_or(&callback_url)
                } else {
                    &callback_url
                };
                let target_url = utils::safe_redirect_url(context, target_url)
                    .unwrap_or_else(|| context.base_url.clone());
                let cookies = session_cookies(context, &data.session, &data.user, false)?;
                redirect_with_cookies(&target_url, cookies)
            })
        },
    )
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
