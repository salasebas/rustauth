use std::sync::Arc;

use http::{Method, StatusCode};
use rustauth_core::api::{
    create_auth_endpoint, parse_request_body, AsyncAuthEndpoint, AuthEndpointOptions, BodyField,
    BodySchema, JsonSchemaType,
};
use rustauth_core::context::AuthContext;
use rustauth_core::db::DbAdapter;
use rustauth_core::error::RustAuthError;
use serde::{Deserialize, Serialize};

use rustauth_core::outbound::{dispatch_outbound, ready_outbound};

use super::{create_session_cookies, validate_phone_number};
use crate::phone_number::errors::{
    error_response, invalid_phone_number_or_password, json_response, phone_number_not_verified,
    unexpected_error,
};
use crate::phone_number::options::PhoneNumberOptions;
use crate::phone_number::{otp, store};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignInPhoneBody {
    phone_number: String,
    password: String,
    #[serde(default)]
    remember_me: Option<bool>,
}

#[derive(Debug, Serialize)]
struct AuthResponse {
    token: String,
    user: store::PhoneUser,
}

pub(crate) fn endpoint(options: Arc<PhoneNumberOptions>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/sign-in/phone-number",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("signInPhoneNumber")
            .allowed_media_types(["application/json", "application/x-www-form-urlencoded"])
            .body_schema(BodySchema::object([
                BodyField::new("phoneNumber", JsonSchemaType::String),
                BodyField::new("password", JsonSchemaType::String),
                BodyField::optional("rememberMe", JsonSchemaType::Boolean),
            ])),
        move |context, request| {
            let options = Arc::clone(&options);
            async move {
                let adapter = context.require_adapter()?;
                let body: SignInPhoneBody = parse_request_body(&request)?;
                if let Some(response) = validate_phone_number(&options, &body.phone_number)? {
                    return Ok(response);
                }
                let Some(user) = store::find_by_phone(adapter.as_ref(), &body.phone_number).await?
                else {
                    return error_response(
                        StatusCode::UNAUTHORIZED,
                        invalid_phone_number_or_password(),
                    );
                };
                if options.require_verification && !user.phone_number_verified {
                    send_sign_in_verification(
                        &context,
                        adapter.as_ref(),
                        &options,
                        &body.phone_number,
                    )
                    .await?;
                    return error_response(StatusCode::UNAUTHORIZED, phone_number_not_verified());
                }
                let Some(account) = context.users()?.find_credential_account(&user.id).await?
                else {
                    return error_response(
                        StatusCode::UNAUTHORIZED,
                        invalid_phone_number_or_password(),
                    );
                };
                let Some(password_hash) = account.password.as_deref() else {
                    return error_response(StatusCode::UNAUTHORIZED, unexpected_error());
                };
                if !(context.password.verify)(password_hash, &body.password)? {
                    return error_response(
                        StatusCode::UNAUTHORIZED,
                        invalid_phone_number_or_password(),
                    );
                }
                let remember_me = body.remember_me.unwrap_or(true);
                let (token, cookies) =
                    create_session_cookies(&context, &user, !remember_me).await?;
                json_response(StatusCode::OK, &AuthResponse { token, user }, cookies)
            }
        },
    )
}

async fn send_sign_in_verification(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    options: &PhoneNumberOptions,
    phone_number: &str,
) -> Result<(), RustAuthError> {
    let code = otp::generate_otp(options.otp_length);
    otp::create(
        adapter,
        &context.secret,
        phone_number.to_owned(),
        &code,
        options.expires_in,
    )
    .await?;
    if let Some(sender) = &options.send_otp {
        dispatch_outbound(context, ready_outbound(sender(phone_number, &code)));
    }
    Ok(())
}
