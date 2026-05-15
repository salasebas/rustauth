use std::sync::Arc;

use http::Method;
use openauth_core::api::{
    create_auth_endpoint, ApiRequest, AsyncAuthEndpoint, AuthEndpointOptions,
};
use openauth_core::context::AuthContext;
use openauth_core::db::DbAdapter;
use openauth_core::plugin::AuthPlugin;

use super::change_email::{change_email, request_email_change};
use super::endpoints::{
    check_otp, send_otp, sign_in, verify_email, CHANGE_EMAIL_PATH, CHECK_PATH, CREATE_PATH,
    GET_PATH, REQUEST_CHANGE_EMAIL_PATH, RESET_PASSWORD_PATH, SEND_PATH, SIGN_IN_PATH,
    VERIFY_EMAIL_PATH,
};
use super::password::{request_password_reset, reset_password};
use super::schema::common_schema;
use super::server::{create_verification_otp, get_verification_otp};
use super::types::EmailOtpOptions;

const REQUEST_RESET_PATH: &str = "/email-otp/request-password-reset";
const FORGET_PASSWORD_PATH: &str = "/forget-password/email-otp";

type Handler = fn(
    &AuthContext,
    ApiRequest,
    Arc<dyn DbAdapter>,
    Arc<EmailOtpOptions>,
) -> openauth_core::api::EndpointFuture<'_>;

pub fn paths() -> &'static [&'static str] {
    &[
        SEND_PATH,
        CREATE_PATH,
        GET_PATH,
        CHECK_PATH,
        VERIFY_EMAIL_PATH,
        SIGN_IN_PATH,
        REQUEST_RESET_PATH,
        FORGET_PASSWORD_PATH,
        RESET_PASSWORD_PATH,
        REQUEST_CHANGE_EMAIL_PATH,
        CHANGE_EMAIL_PATH,
    ]
}

pub fn register(
    plugin: AuthPlugin,
    adapter: Arc<dyn DbAdapter>,
    options: EmailOtpOptions,
) -> AuthPlugin {
    let options = Arc::new(options);
    plugin
        .with_endpoint(endpoint(
            SEND_PATH,
            "sendEmailVerificationOTP",
            Arc::clone(&adapter),
            options.clone(),
            send_otp,
        ))
        .with_endpoint(endpoint(
            CREATE_PATH,
            "createEmailVerificationOTP",
            Arc::clone(&adapter),
            options.clone(),
            create_verification_otp,
        ))
        .with_endpoint(endpoint_with_method(
            GET_PATH,
            Method::GET,
            "getEmailVerificationOTP",
            Arc::clone(&adapter),
            options.clone(),
            get_verification_otp,
        ))
        .with_endpoint(endpoint(
            CHECK_PATH,
            "checkEmailVerificationOTP",
            Arc::clone(&adapter),
            options.clone(),
            check_otp,
        ))
        .with_endpoint(endpoint(
            VERIFY_EMAIL_PATH,
            "verifyEmailOTP",
            Arc::clone(&adapter),
            options.clone(),
            verify_email,
        ))
        .with_endpoint(endpoint(
            SIGN_IN_PATH,
            "signInEmailOTP",
            Arc::clone(&adapter),
            options.clone(),
            sign_in,
        ))
        .with_endpoint(endpoint(
            REQUEST_RESET_PATH,
            "requestPasswordResetEmailOTP",
            Arc::clone(&adapter),
            options.clone(),
            request_password_reset,
        ))
        .with_endpoint(endpoint(
            FORGET_PASSWORD_PATH,
            "forgetPasswordEmailOTP",
            Arc::clone(&adapter),
            options.clone(),
            request_password_reset,
        ))
        .with_endpoint(endpoint(
            RESET_PASSWORD_PATH,
            "resetPasswordEmailOTP",
            Arc::clone(&adapter),
            options.clone(),
            reset_password,
        ))
        .with_endpoint(endpoint(
            REQUEST_CHANGE_EMAIL_PATH,
            "requestEmailChangeEmailOTP",
            Arc::clone(&adapter),
            options.clone(),
            request_email_change,
        ))
        .with_endpoint(endpoint(
            CHANGE_EMAIL_PATH,
            "changeEmailEmailOTP",
            adapter,
            options,
            change_email,
        ))
}

fn endpoint(
    path: &'static str,
    operation_id: &'static str,
    adapter: Arc<dyn DbAdapter>,
    options: Arc<EmailOtpOptions>,
    handler: Handler,
) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        path,
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id(operation_id)
            .body_schema(common_schema(path)),
        move |context, request| handler(context, request, Arc::clone(&adapter), options.clone()),
    )
}

fn endpoint_with_method(
    path: &'static str,
    method: Method,
    operation_id: &'static str,
    adapter: Arc<dyn DbAdapter>,
    options: Arc<EmailOtpOptions>,
    handler: Handler,
) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        path,
        method,
        AuthEndpointOptions::new().operation_id(operation_id),
        move |context, request| handler(context, request, Arc::clone(&adapter), options.clone()),
    )
}
