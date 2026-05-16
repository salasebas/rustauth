use std::sync::Arc;

use http::{Method, StatusCode};
use openauth_core::api::{create_auth_endpoint, parse_request_body};
use openauth_core::verification::{
    CreateVerificationInput, DbVerificationStore, UpdateVerificationInput,
};
use time::{Duration, OffsetDateTime};

use super::errors::{error_message, error_response};
use super::flow::verify_context;
use super::options::{TwoFactorOptions, TwoFactorOtpMessage};
use super::otp::{generate_otp, store_otp, verify_stored_otp};
use super::payloads::{body_options, code_schema, optional_trust_schema, CodeBody, StatusBody};
use super::routes::{flow_error_response, json_response};
use super::store::{update_user_two_factor_enabled, user_two_factor_enabled};

pub(super) fn send_otp_endpoint(
    options: Arc<TwoFactorOptions>,
) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/two-factor/send-otp",
        Method::POST,
        body_options("sendTwoFactorOtp", optional_trust_schema()),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                let Some(send_otp) = &options.otp.send_otp else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "OTP_NOT_CONFIGURED",
                        error_message("OTP_NOT_CONFIGURED"),
                    );
                };
                let flow = match verify_context(context, &request, &options).await {
                    Ok(flow) => flow,
                    Err(error) => return flow_error_response(error),
                };
                let code = generate_otp(options.otp.digits);
                let stored = store_otp(&code, &context.secret, &options.otp)?;
                DbVerificationStore::new(flow.adapter.as_ref())
                    .create_verification(CreateVerificationInput::new(
                        format!("2fa-otp-{}", flow.key),
                        format!("{stored}:0"),
                        OffsetDateTime::now_utc()
                            + Duration::seconds(options.otp.period_seconds as i64),
                    ))
                    .await?;
                send_otp(TwoFactorOtpMessage {
                    user: flow.user,
                    otp: code,
                    request,
                })
                .await?;
                json_response(StatusCode::OK, &StatusBody { status: true }, Vec::new())
            })
        },
    )
}

pub(super) fn verify_otp_endpoint(
    options: Arc<TwoFactorOptions>,
) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/two-factor/verify-otp",
        Method::POST,
        body_options("verifyTwoFactorCode", code_schema()),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                if options.otp.send_otp.is_none() {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "OTP_NOT_CONFIGURED",
                        error_message("OTP_NOT_CONFIGURED"),
                    );
                }
                let body: CodeBody = parse_request_body(&request)?;
                let mut flow = match verify_context(context, &request, &options).await {
                    Ok(flow) => flow,
                    Err(error) => return flow_error_response(error),
                };
                let identifier = format!("2fa-otp-{}", flow.key);
                let store = DbVerificationStore::new(flow.adapter.as_ref());
                let Some(record) = store.find_verification(&identifier).await? else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "OTP_HAS_EXPIRED",
                        error_message("OTP_HAS_EXPIRED"),
                    );
                };
                let (stored, counter) = record
                    .value
                    .split_once(':')
                    .unwrap_or((record.value.as_str(), "0"));
                let attempts = counter.parse::<u32>().unwrap_or(0);
                if attempts >= options.otp.allowed_attempts {
                    store.delete_verification(&identifier).await?;
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE",
                        error_message("TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE"),
                    );
                }
                if !verify_stored_otp(stored, &body.code, &context.secret, &options.otp)? {
                    store
                        .update_verification(
                            &identifier,
                            UpdateVerificationInput::new()
                                .value(format!("{stored}:{}", attempts + 1)),
                        )
                        .await?;
                    return error_response(
                        StatusCode::UNAUTHORIZED,
                        "INVALID_CODE",
                        error_message("INVALID_CODE"),
                    );
                }
                if !user_two_factor_enabled(flow.adapter.as_ref(), &flow.user.id).await? {
                    update_user_two_factor_enabled(flow.adapter.as_ref(), &flow.user.id, true)
                        .await?;
                }
                flow.trust_device = body.trust_device.unwrap_or(false);
                flow.valid(context, &options).await
            })
        },
    )
}
