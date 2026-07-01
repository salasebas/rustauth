use std::sync::Arc;

use http::{Method, StatusCode};
use rustauth_core::api::{
    additional_fields, create_auth_endpoint, parse_request_body, AsyncAuthEndpoint,
    AuthEndpointOptions, BodyField, BodySchema, JsonSchemaType,
};
use rustauth_core::auth::session::{GetSessionInput, SessionAuth};
use rustauth_core::db::{DbAdapter, DbRecord};
use rustauth_core::error::RustAuthError;
use rustauth_core::verification::CreateVerificationInput;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::OffsetDateTime;

use super::{create_session_cookies, validate_phone_number};
use crate::phone_number::errors::{
    error_response, invalid_otp, json_response, otp_expired, phone_number_exists,
    too_many_attempts, unexpected_error,
};
use crate::phone_number::options::PhoneNumberOptions;
use crate::phone_number::{otp, store};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyBody {
    phone_number: String,
    code: String,
    #[serde(default)]
    disable_session: Option<bool>,
    #[serde(default)]
    update_phone_number: Option<bool>,
    #[serde(flatten)]
    additional_fields: Map<String, Value>,
}

#[derive(Debug, Serialize)]
struct VerifyResponse {
    status: bool,
    token: Option<String>,
    user: store::PhoneUser,
}

pub(crate) fn endpoint(options: Arc<PhoneNumberOptions>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/phone-number/verify",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("verifyPhoneNumber")
            .allowed_media_types(["application/json", "application/x-www-form-urlencoded"])
            .body_schema(BodySchema::object([
                BodyField::new("phoneNumber", JsonSchemaType::String),
                BodyField::new("code", JsonSchemaType::String),
                BodyField::optional("disableSession", JsonSchemaType::Boolean),
                BodyField::optional("updatePhoneNumber", JsonSchemaType::Boolean),
            ])),
        move |context, request| {
            let options = Arc::clone(&options);
            async move {
                let adapter = context.require_adapter()?;
                let body: VerifyBody = parse_request_body(&request)?;
                if let Some(response) = validate_phone_number(&options, &body.phone_number)? {
                    return Ok(response);
                }
                if let Some(response) =
                    verify_code(&context, &options, &body.phone_number, &body.code).await?
                {
                    return Ok(response);
                }

                if body.update_phone_number.unwrap_or(false) {
                    let Some(current_session) =
                        current_session_identity(&context, &request).await?
                    else {
                        return error_response(StatusCode::UNAUTHORIZED, unexpected_error());
                    };
                    if store::find_by_phone(adapter.as_ref(), &body.phone_number)
                        .await?
                        .is_some()
                    {
                        return error_response(StatusCode::BAD_REQUEST, phone_number_exists());
                    }
                    let user = store::update_phone(
                        adapter.as_ref(),
                        &current_session.user_id,
                        Some(&body.phone_number),
                        true,
                    )
                    .await?
                    .ok_or_else(|| RustAuthError::Adapter("failed to update user".to_owned()))?;
                    run_callback(&options, &body.phone_number, &user)?;
                    return json_response(
                        StatusCode::OK,
                        &VerifyResponse {
                            status: true,
                            token: Some(current_session.token),
                            user,
                        },
                        Vec::new(),
                    );
                }

                let user = match store::find_by_phone(adapter.as_ref(), &body.phone_number).await? {
                    Some(user) => store::update_verified(adapter.as_ref(), &user.id, true)
                        .await?
                        .ok_or_else(|| {
                            RustAuthError::Adapter("failed to update user".to_owned())
                        })?,
                    None => {
                        let additional_fields = match additional_fields::create_values(
                            &context.options.user.additional_fields,
                            &body.additional_fields,
                        ) {
                            Ok(fields) => fields,
                            Err(error) => {
                                return error_response(
                                    StatusCode::BAD_REQUEST,
                                    rustauth_core::plugin::PluginErrorCode::new(
                                        "INVALID_REQUEST_BODY",
                                        error.message(),
                                    ),
                                );
                            }
                        };
                        let Some(user) = create_user_on_verification(
                            adapter.as_ref(),
                            &options,
                            &body.phone_number,
                            additional_fields,
                        )
                        .await?
                        else {
                            return error_response(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                unexpected_error(),
                            );
                        };
                        user
                    }
                };
                run_callback(&options, &body.phone_number, &user)?;

                if body.disable_session.unwrap_or(false) {
                    return json_response(
                        StatusCode::OK,
                        &VerifyResponse {
                            status: true,
                            token: None,
                            user,
                        },
                        Vec::new(),
                    );
                }
                let (token, cookies) = create_session_cookies(&context, &user, false).await?;
                json_response(
                    StatusCode::OK,
                    &VerifyResponse {
                        status: true,
                        token: Some(token),
                        user,
                    },
                    cookies,
                )
            }
        },
    )
}

async fn verify_code(
    context: &rustauth_core::context::AuthContext,
    options: &PhoneNumberOptions,
    phone_number: &str,
    code: &str,
) -> Result<Option<rustauth_core::api::ApiResponse>, RustAuthError> {
    if let Some(verifier) = &options.verify_otp {
        if verifier(phone_number, code)? {
            let _ = context
                .verifications()?
                .consume_verification_including_expired(phone_number)
                .await?;
            return Ok(None);
        }
        return error_response(StatusCode::BAD_REQUEST, invalid_otp()).map(Some);
    }
    let verifications = context.verifications()?;
    let Some(verification) = verifications
        .consume_verification_including_expired(phone_number)
        .await?
    else {
        return error_response(StatusCode::BAD_REQUEST, invalid_otp()).map(Some);
    };
    if verification.expires_at <= OffsetDateTime::now_utc() {
        return error_response(StatusCode::BAD_REQUEST, otp_expired()).map(Some);
    }
    let Some(stored_otp) = otp::decode(&verification.value) else {
        return error_response(StatusCode::BAD_REQUEST, invalid_otp()).map(Some);
    };
    if stored_otp.attempts >= options.allowed_attempts {
        return error_response(StatusCode::FORBIDDEN, too_many_attempts()).map(Some);
    }
    if !otp::verify(&context.secret, phone_number, stored_otp, code)? {
        let next_attempts = stored_otp.attempts + 1;
        if next_attempts >= options.allowed_attempts {
            return error_response(StatusCode::FORBIDDEN, too_many_attempts()).map(Some);
        }
        verifications
            .create_verification(CreateVerificationInput::new(
                phone_number,
                otp::encode_stored(stored_otp, next_attempts),
                verification.expires_at,
            ))
            .await?;
        return error_response(StatusCode::BAD_REQUEST, invalid_otp()).map(Some);
    }
    Ok(None)
}

struct CurrentSessionIdentity {
    token: String,
    user_id: String,
}

async fn current_session_identity(
    context: &rustauth_core::context::AuthContext,
    request: &rustauth_core::api::ApiRequest,
) -> Result<Option<CurrentSessionIdentity>, RustAuthError> {
    let cookie = request
        .headers()
        .get(http::header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let Some(result) = SessionAuth::new(context)?
        .get_session(GetSessionInput::new(cookie))
        .await?
    else {
        return Ok(None);
    };
    let (Some(session), Some(user)) = (result.session, result.user) else {
        return Ok(None);
    };
    Ok(Some(CurrentSessionIdentity {
        token: session.token,
        user_id: user.id,
    }))
}

async fn create_user_on_verification(
    adapter: &dyn DbAdapter,
    options: &PhoneNumberOptions,
    phone_number: &str,
    additional_fields: DbRecord,
) -> Result<Option<store::PhoneUser>, RustAuthError> {
    let Some(sign_up) = &options.sign_up_on_verification else {
        return Ok(None);
    };
    let email = (sign_up.get_temp_email)(phone_number);
    let name = sign_up
        .get_temp_name
        .as_ref()
        .map(|get_name| get_name(phone_number))
        .unwrap_or_else(|| phone_number.to_owned());
    store::create_user_with_phone(adapter, name, email, phone_number, additional_fields)
        .await
        .map(Some)
}

fn run_callback(
    options: &PhoneNumberOptions,
    phone_number: &str,
    user: &store::PhoneUser,
) -> Result<(), RustAuthError> {
    if let Some(callback) = &options.callback_on_verification {
        callback(phone_number, &user.id)?;
    }
    Ok(())
}
