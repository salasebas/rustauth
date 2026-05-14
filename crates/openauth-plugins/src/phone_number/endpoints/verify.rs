use std::sync::Arc;

use http::{Method, StatusCode};
use openauth_core::api::{
    create_auth_endpoint, parse_request_body, AsyncAuthEndpoint, AuthEndpointOptions, BodyField,
    BodySchema, JsonSchemaType,
};
use openauth_core::auth::session::{GetSessionInput, SessionAuth};
use openauth_core::db::DbAdapter;
use openauth_core::error::OpenAuthError;
use openauth_core::verification::DbVerificationStore;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::{create_session_cookies, validate_phone_number};
use crate::phone_number::errors::{
    error_response, invalid_otp, json_response, otp_expired, otp_not_found, phone_number_exists,
    too_many_attempts, unexpected_error,
};
use crate::phone_number::options::PhoneNumberOptions;
use crate::phone_number::{otp, store};

#[derive(Debug, Deserialize)]
struct VerifyBody {
    #[serde(alias = "phoneNumber")]
    phone_number: String,
    code: String,
    #[serde(default, alias = "disableSession")]
    disable_session: Option<bool>,
    #[serde(default, alias = "updatePhoneNumber")]
    update_phone_number: Option<bool>,
}

#[derive(Debug, Serialize)]
struct VerifyResponse {
    status: bool,
    token: Option<String>,
    user: store::PhoneUser,
}

pub(crate) fn endpoint(
    adapter: Arc<dyn DbAdapter>,
    options: Arc<PhoneNumberOptions>,
) -> AsyncAuthEndpoint {
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
            let adapter = Arc::clone(&adapter);
            let options = Arc::clone(&options);
            Box::pin(async move {
                let body: VerifyBody = parse_request_body(&request)?;
                if let Some(response) = validate_phone_number(&options, &body.phone_number)? {
                    return Ok(response);
                }
                if let Some(response) =
                    verify_code(adapter.as_ref(), &options, &body.phone_number, &body.code).await?
                {
                    return Ok(response);
                }

                if body.update_phone_number.unwrap_or(false) {
                    let Some(user_id) =
                        current_user_id(adapter.as_ref(), context, &request).await?
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
                        &user_id,
                        Some(&body.phone_number),
                        true,
                    )
                    .await?
                    .ok_or_else(|| OpenAuthError::Adapter("failed to update user".to_owned()))?;
                    run_callback(&options, &body.phone_number, &user)?;
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

                let user = match store::find_by_phone(adapter.as_ref(), &body.phone_number).await? {
                    Some(user) => store::update_verified(adapter.as_ref(), &user.id, true)
                        .await?
                        .ok_or_else(|| {
                            OpenAuthError::Adapter("failed to update user".to_owned())
                        })?,
                    None => {
                        let Some(user) = create_user_on_verification(
                            adapter.as_ref(),
                            &options,
                            &body.phone_number,
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
                let (token, cookies) =
                    create_session_cookies(adapter.as_ref(), context, &user, false).await?;
                json_response(
                    StatusCode::OK,
                    &VerifyResponse {
                        status: true,
                        token: Some(token),
                        user,
                    },
                    cookies,
                )
            })
        },
    )
}

async fn verify_code(
    adapter: &dyn DbAdapter,
    options: &PhoneNumberOptions,
    phone_number: &str,
    code: &str,
) -> Result<Option<openauth_core::api::ApiResponse>, OpenAuthError> {
    if let Some(verifier) = &options.verify_otp {
        if verifier(phone_number, code)? {
            return Ok(None);
        }
        return error_response(StatusCode::BAD_REQUEST, invalid_otp()).map(Some);
    }
    let verifications = DbVerificationStore::new(adapter);
    let Some(verification) = otp::find_raw(adapter, phone_number).await? else {
        return error_response(StatusCode::BAD_REQUEST, otp_not_found()).map(Some);
    };
    if verification.expires_at <= OffsetDateTime::now_utc() {
        return error_response(StatusCode::BAD_REQUEST, otp_expired()).map(Some);
    }
    let (otp_value, attempts) = otp::decode(&verification.value);
    if attempts >= options.allowed_attempts {
        verifications.delete_verification(phone_number).await?;
        return error_response(StatusCode::FORBIDDEN, too_many_attempts()).map(Some);
    }
    if otp_value != code {
        let next_attempts = attempts + 1;
        verifications
            .update_verification(
                phone_number,
                openauth_core::verification::UpdateVerificationInput::new()
                    .value(otp::encode(otp_value, next_attempts)),
            )
            .await?;
        return error_response(StatusCode::BAD_REQUEST, invalid_otp()).map(Some);
    }
    verifications.delete_verification(phone_number).await?;
    Ok(None)
}

async fn current_user_id(
    adapter: &dyn DbAdapter,
    context: &openauth_core::context::AuthContext,
    request: &openauth_core::api::ApiRequest,
) -> Result<Option<String>, OpenAuthError> {
    let cookie = request
        .headers()
        .get(http::header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let Some(result) = SessionAuth::new(adapter, context)
        .get_session(GetSessionInput::new(cookie))
        .await?
    else {
        return Ok(None);
    };
    let Some(user) = result.user else {
        return Ok(None);
    };
    Ok(Some(user.id))
}

async fn create_user_on_verification(
    adapter: &dyn DbAdapter,
    options: &PhoneNumberOptions,
    phone_number: &str,
) -> Result<Option<store::PhoneUser>, OpenAuthError> {
    let Some(sign_up) = &options.sign_up_on_verification else {
        return Ok(None);
    };
    let email = (sign_up.get_temp_email)(phone_number);
    let name = sign_up
        .get_temp_name
        .as_ref()
        .map(|get_name| get_name(phone_number))
        .unwrap_or_else(|| phone_number.to_owned());
    store::create_user_with_phone(adapter, name, email, phone_number)
        .await
        .map(Some)
}

fn run_callback(
    options: &PhoneNumberOptions,
    phone_number: &str,
    user: &store::PhoneUser,
) -> Result<(), OpenAuthError> {
    if let Some(callback) = &options.callback_on_verification {
        callback(phone_number, &user.id)?;
    }
    Ok(())
}
