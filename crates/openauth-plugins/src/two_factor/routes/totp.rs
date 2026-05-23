use std::sync::Arc;

use http::{Method, StatusCode};
use openauth_core::api::{create_auth_endpoint, parse_request_body};
use openauth_core::crypto::symmetric_decrypt;

use super::flow_error_response;
use crate::two_factor::errors::{error_message, error_response};
use crate::two_factor::flow::verify_context;
use crate::two_factor::options::TwoFactorOptions;
use crate::two_factor::payloads::{body_options, code_schema, CodeBody};
use crate::two_factor::store::{update_user_two_factor_enabled, TwoFactorStore};
use crate::two_factor::totp::verify_totp_code;

pub(super) fn verify_totp_endpoint(
    options: Arc<TwoFactorOptions>,
) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/two-factor/verify-totp",
        Method::POST,
        body_options("verifyTotp", code_schema()),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                if options.totp.disabled {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "TOTP_NOT_CONFIGURED",
                        error_message("TOTP_NOT_CONFIGURED"),
                    );
                }
                let body: CodeBody = parse_request_body(&request)?;
                let mut flow = match verify_context(context, &request, &options).await {
                    Ok(flow) => flow,
                    Err(error) => return flow_error_response(error),
                };
                let Some(record) =
                    TwoFactorStore::new(flow.adapter.as_ref(), &options.two_factor_table)
                        .find_by_user(&flow.user.id)
                        .await?
                else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "TOTP_NOT_ENABLED",
                        error_message("TOTP_NOT_ENABLED"),
                    );
                };
                if flow.session.is_none() && record.verified == Some(false) {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "TOTP_NOT_ENABLED",
                        error_message("TOTP_NOT_ENABLED"),
                    );
                }
                let secret = symmetric_decrypt(context.secret.as_str(), &record.secret)?;
                if !verify_totp_code(
                    &secret,
                    &body.code,
                    options.totp.digits,
                    options.totp.period,
                ) {
                    return error_response(
                        StatusCode::UNAUTHORIZED,
                        "INVALID_CODE",
                        error_message("INVALID_CODE"),
                    );
                }
                if record.verified != Some(true) {
                    update_user_two_factor_enabled(flow.adapter.as_ref(), &flow.user.id, true)
                        .await?;
                    TwoFactorStore::new(flow.adapter.as_ref(), &options.two_factor_table)
                        .mark_verified(&record.id)
                        .await?;
                }
                flow.trust_device = body.trust_device.unwrap_or(false);
                flow.valid(context, &options).await
            })
        },
    )
}
