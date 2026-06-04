use std::sync::Arc;

use crate::challenge::{consume_challenge, create_challenge, ChallengeKind, ChallengeValue};
use crate::challenge_rate_limit::consume_verify_challenge_rate_limit;
use crate::cookies::{challenge_cookie, challenge_token};
use crate::openapi::{
    json_openapi_response, passkey_openapi_schema, query_parameter,
    verify_registration_body_schema, webauthn_options_schema,
};
use crate::options::{
    AfterRegistrationVerificationInput, AuthenticatorAttachment, PasskeyExtensionsInput,
    PasskeyOptions, RegistrationWebAuthnOptions,
};
use crate::response::{
    error_response, internal_error, json_response, not_allowed, session_not_fresh,
    too_many_requests,
};
use crate::routes::{
    adapter, query_param, resolve_extensions, verification_webauthn_config, webauthn_config,
    VerifyRegistrationBody,
};
use crate::session::{current_session, registration_user, session_is_fresh, RegistrationUserError};
use crate::store::{Passkey, PasskeyStore};
use http::{Method, StatusCode};
use openauth_core::api::{
    create_auth_endpoint, parse_request_body, AsyncAuthEndpoint, AuthEndpointOptions,
    OpenApiOperation,
};

pub(super) fn generate_register_options_endpoint(
    options: Arc<PasskeyOptions>,
) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/passkey/generate-register-options",
        Method::GET,
        AuthEndpointOptions::new()
            .operation_id("generatePasskeyRegistrationOptions")
            .openapi(
                OpenApiOperation::new("generatePasskeyRegistrationOptions")
                    .tag("Passkey")
                    .description("Generate registration options for a new passkey")
                    .parameter(query_parameter(
                        "authenticatorAttachment",
                        "Optional authenticator attachment: platform or cross-platform",
                    ))
                    .parameter(query_parameter("name", "Optional custom passkey name"))
                    .parameter(query_parameter(
                        "context",
                        "Optional context for pre-auth registration flows",
                    ))
                    .response(
                        "200",
                        json_openapi_response("Success", webauthn_options_schema()),
                    ),
            ),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                let adapter = adapter(context)?;
                let session = current_session(context, &request).await?;
                if let Some((session, _, _)) = &session {
                    if options.registration.require_session && !session_is_fresh(context, session) {
                        return session_not_fresh();
                    }
                }
                let context_value = query_param(&request, "context");
                let user =
                    match registration_user(&options, session.as_ref(), context_value.clone()).await
                    {
                        Ok(user) => user,
                        Err(RegistrationUserError::SessionRequired) => {
                            return error_response(
                                StatusCode::UNAUTHORIZED,
                                "SESSION_REQUIRED",
                                "Passkey registration requires an authenticated session",
                            )
                        }
                        Err(RegistrationUserError::ResolveUserRequired) => {
                            return error_response(
                                StatusCode::BAD_REQUEST,
                                "RESOLVE_USER_REQUIRED",
                                "Passkey registration requires either an authenticated session or a resolveUser callback when requireSession is false",
                            )
                        }
                        Err(RegistrationUserError::ResolvedUserInvalid) => {
                            return error_response(
                                StatusCode::BAD_REQUEST,
                                "RESOLVED_USER_INVALID",
                                "Resolved user is invalid",
                            )
                        }
                    };
                let user_passkeys = PasskeyStore::new(adapter.as_ref())
                    .list_by_user(&user.id)
                    .await?;
                let mut webauthn_user = user.clone();
                if let Some(name) = query_param(&request, "name") {
                    if webauthn_user.display_name.is_none() {
                        webauthn_user.display_name = Some(user.name.clone());
                    }
                    webauthn_user.name = name;
                }
                let attachment = match query_param(&request, "authenticatorAttachment") {
                    Some(value) => match AuthenticatorAttachment::from_query(&value) {
                        Some(attachment) => Some(attachment),
                        None => {
                            return error_response(
                                StatusCode::BAD_REQUEST,
                                "BAD_REQUEST",
                                "Invalid authenticatorAttachment",
                            )
                        }
                    },
                    None => None,
                };
                let extensions = resolve_extensions(
                    &options.registration.extensions,
                    PasskeyExtensionsInput {
                        context: context_value.clone(),
                        user_id: session.as_ref().map(|(_, user, _)| user.id.clone()),
                    },
                )
                .await;
                let request_options = RegistrationWebAuthnOptions::new(
                    options
                        .authenticator_selection
                        .with_attachment_override(attachment),
                    extensions,
                );
                let start = options.backend.start_registration(
                    webauthn_config(context, &options, &request)?,
                    &webauthn_user,
                    user_passkeys
                        .iter()
                        .map(Passkey::registration_exclude_value)
                        .collect(),
                    request_options,
                )?;
                let token = create_challenge(
                    adapter.as_ref(),
                    context,
                    ChallengeValue {
                        kind: ChallengeKind::Registration,
                        state: start.state,
                        user: Some(user),
                        context: context_value,
                    },
                )
                .await?;
                json_response(
                    StatusCode::OK,
                    &start.options,
                    vec![challenge_cookie(context, &options, token)?],
                )
            })
        },
    )
}

pub(super) fn verify_registration_endpoint(options: Arc<PasskeyOptions>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/passkey/verify-registration",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("passkeyVerifyRegistration")
            .allowed_media_types(["application/json"])
            .body_schema(verify_registration_body_schema())
            .openapi(
                OpenApiOperation::new("passkeyVerifyRegistration")
                    .tag("Passkey")
                    .description("Verify registration of a new passkey")
                    .response(
                        "200",
                        json_openapi_response("Success", passkey_openapi_schema()),
                    ),
            ),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                let adapter = adapter(context)?;
                let body: VerifyRegistrationBody = parse_request_body(&request)?;
                let token = match challenge_token(context, &options, &request)? {
                    Some(token) => token,
                    None => {
                        return error_response(
                            StatusCode::BAD_REQUEST,
                            "CHALLENGE_NOT_FOUND",
                            "Challenge not found",
                        )
                    }
                };
                if let Some(rejection) = consume_verify_challenge_rate_limit(
                    context,
                    &options,
                    &request,
                    "/passkey/verify-registration",
                    &token,
                )
                .await?
                {
                    return too_many_requests(rejection);
                }
                let Some(challenge) = consume_challenge(adapter.as_ref(), context, &token).await?
                else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "CHALLENGE_NOT_FOUND",
                        "Challenge not found",
                    );
                };
                if challenge.kind != ChallengeKind::Registration {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "CHALLENGE_NOT_FOUND",
                        "Challenge not found",
                    );
                }
                let session = current_session(context, &request).await?;
                if options.registration.require_session && session.is_none() {
                    return error_response(
                        StatusCode::UNAUTHORIZED,
                        "SESSION_REQUIRED",
                        "Passkey registration requires an authenticated session",
                    );
                }
                if let Some((session, _, _)) = &session {
                    if options.registration.require_session && !session_is_fresh(context, session) {
                        return session_not_fresh();
                    }
                }
                let Some(resolved_user) = challenge.user.clone() else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "RESOLVED_USER_INVALID",
                        "Resolved user is invalid",
                    );
                };
                if let Some((_, user, _)) = &session {
                    if user.id != resolved_user.id {
                        return not_allowed();
                    }
                }
                let Some(config) = verification_webauthn_config(context, &options, &request)?
                else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "FAILED_TO_VERIFY_REGISTRATION",
                        "Failed to verify registration",
                    );
                };
                let verified = match options.backend.finish_registration(
                    config,
                    body.response.clone(),
                    challenge.state,
                ) {
                    Ok(verified) => verified,
                    Err(_) => {
                        return internal_error(
                            "FAILED_TO_VERIFY_REGISTRATION",
                            "Failed to verify registration",
                        )
                    }
                };
                let mut target_user_id = resolved_user.id.clone();
                if let Some(callback) = &options.registration.after_verification {
                    if let Some(user_id) = callback(AfterRegistrationVerificationInput {
                        user: resolved_user.clone(),
                        client_data: body.response,
                        context: challenge.context,
                    })
                    .await
                    {
                        if user_id.is_empty() {
                            return error_response(
                                StatusCode::BAD_REQUEST,
                                "RESOLVED_USER_INVALID",
                                "Resolved user is invalid",
                            );
                        }
                        if let Some((_, user, _)) = &session {
                            if user.id != user_id {
                                return not_allowed();
                            }
                        }
                        target_user_id = user_id;
                    }
                }
                let store = PasskeyStore::new(adapter.as_ref());
                if store
                    .find_by_credential_id(&verified.credential_id)
                    .await?
                    .is_some()
                {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "PREVIOUSLY_REGISTERED",
                        "Previously registered",
                    );
                }
                let credential_id = verified.credential_id.clone();
                let passkey = match store.create(&target_user_id, body.name, verified).await {
                    Ok(passkey) => passkey,
                    Err(error) => {
                        if store.find_by_credential_id(&credential_id).await?.is_some() {
                            return error_response(
                                StatusCode::BAD_REQUEST,
                                "PREVIOUSLY_REGISTERED",
                                "Previously registered",
                            );
                        }
                        return Err(error);
                    }
                };
                json_response(StatusCode::OK, &passkey, Vec::new())
            })
        },
    )
}
