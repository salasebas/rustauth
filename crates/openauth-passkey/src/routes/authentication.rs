use std::sync::Arc;

use http::{Method, StatusCode};
use openauth_core::api::output::session_response_cookies;
use openauth_core::api::{
    create_auth_endpoint, parse_request_body, AsyncAuthEndpoint, AuthEndpointOptions,
    OpenApiOperation,
};
use openauth_core::user::DbUserStore;
use serde_json::json;

use crate::challenge::{consume_challenge, create_challenge, ChallengeKind, ChallengeValue};
use crate::challenge_rate_limit::consume_verify_challenge_rate_limit;
use crate::cookies::{challenge_cookie, challenge_token};
use crate::openapi::{
    json_openapi_response, verify_authentication_body_schema, webauthn_options_schema,
};
use crate::options::{
    AfterAuthenticationVerificationInput, PasskeyExtensionsInput, PasskeyOptions,
    PasskeyRegistrationUser,
};
use crate::response::{
    authentication_failed, error_response, internal_error, json_response, too_many_requests,
};
use crate::routes::{
    adapter, resolve_extensions, verification_webauthn_config, webauthn_config,
    VerifyAuthenticationBody,
};
use crate::session::{create_session_for_user, current_session};
use crate::store::PasskeyStore;
use crate::webauthn::merge_legacy_allow_credentials;

pub(super) fn generate_authenticate_options_endpoint(
    options: Arc<PasskeyOptions>,
) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/passkey/generate-authenticate-options",
        Method::GET,
        AuthEndpointOptions::new()
            .operation_id("passkeyGenerateAuthenticateOptions")
            .openapi(
                OpenApiOperation::new("passkeyGenerateAuthenticateOptions")
                    .tag("Passkey")
                    .description("Generate authentication options for a passkey")
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
                let (credentials, legacy_credential_ids) = if let Some((_, user, _)) = &session {
                    let passkeys = PasskeyStore::new(adapter.as_ref())
                        .list_by_user(&user.id)
                        .await?;
                    let legacy_credential_ids = passkeys
                        .iter()
                        .filter(|passkey| passkey.webauthn_credential.is_null())
                        .map(|passkey| passkey.credential_id.clone())
                        .collect::<Vec<_>>();
                    let credentials = passkeys
                        .into_iter()
                        .filter_map(|passkey| passkey.authentication_credential_value())
                        .collect();
                    (credentials, legacy_credential_ids)
                } else {
                    (Vec::new(), Vec::new())
                };
                let session_user_id = session.as_ref().map(|(_, user, _)| user.id.clone());
                let mut start = options.backend.start_authentication(
                    webauthn_config(context, &options, &request)?,
                    credentials,
                    resolve_extensions(
                        &options.authentication.extensions,
                        PasskeyExtensionsInput {
                            context: None,
                            user_id: session_user_id,
                        },
                    )
                    .await,
                )?;
                merge_legacy_allow_credentials(&mut start.options, &legacy_credential_ids);
                let token = create_challenge(
                    adapter.as_ref(),
                    context,
                    ChallengeValue {
                        kind: ChallengeKind::Authentication,
                        state: start.state,
                        user: session.map(|(_, user, _)| PasskeyRegistrationUser {
                            id: user.id,
                            name: user.email,
                            display_name: None,
                        }),
                        context: None,
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

pub(super) fn verify_authentication_endpoint(options: Arc<PasskeyOptions>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/passkey/verify-authentication",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("passkeyVerifyAuthentication")
            .allowed_media_types(["application/json"])
            .body_schema(verify_authentication_body_schema())
            .openapi(
                OpenApiOperation::new("passkeyVerifyAuthentication")
                    .tag("Passkey")
                    .description("Verify authentication of a passkey")
                    .response(
                        "200",
                        json_openapi_response(
                            "Success",
                            json!({
                                "type": "object",
                                "properties": {
                                    "session": { "$ref": "#/components/schemas/Session" },
                                    "user": { "$ref": "#/components/schemas/User" },
                                },
                                "required": ["session", "user"],
                            }),
                        ),
                    ),
            ),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                let adapter = adapter(context)?;
                let body: VerifyAuthenticationBody = parse_request_body(&request)?;
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
                    "/passkey/verify-authentication",
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
                if challenge.kind != ChallengeKind::Authentication {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "CHALLENGE_NOT_FOUND",
                        "Challenge not found",
                    );
                }
                let Some(credential_id) =
                    body.response.get("id").and_then(serde_json::Value::as_str)
                else {
                    return authentication_failed();
                };
                let store = PasskeyStore::new(adapter.as_ref());
                let Some(passkey) = store.find_by_credential_id(credential_id).await? else {
                    return authentication_failed();
                };
                if challenge
                    .user
                    .as_ref()
                    .is_some_and(|user| user.id != passkey.user_id)
                {
                    return authentication_failed();
                }
                let Some(config) = verification_webauthn_config(context, &options, &request)?
                else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "origin missing",
                        "origin missing",
                    );
                };
                let verified = match options.backend.finish_authentication(
                    config,
                    body.response.clone(),
                    challenge.state,
                    Some(passkey.webauthn_credential.clone()),
                ) {
                    Ok(verified) => verified,
                    Err(_) => return authentication_failed(),
                };
                if let Some(callback) = &options.authentication.after_verification {
                    callback(AfterAuthenticationVerificationInput {
                        credential_id: passkey.credential_id.clone(),
                        client_data: body.response,
                    })
                    .await;
                }
                let _ = store
                    .update_after_authentication(&passkey.id, verified)
                    .await?;
                let Some(user) = DbUserStore::new(adapter.as_ref())
                    .find_user_by_id(&passkey.user_id)
                    .await?
                else {
                    return internal_error("User not found", "User not found");
                };
                let session =
                    create_session_for_user(adapter.as_ref(), context, &request, &user).await?;
                let cookies = session_response_cookies(context, &session, &user, false)?;
                json_response(
                    StatusCode::OK,
                    &json!({ "session": session, "user": user }),
                    cookies,
                )
            })
        },
    )
}
