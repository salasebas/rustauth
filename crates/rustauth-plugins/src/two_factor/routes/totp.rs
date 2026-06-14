use std::sync::Arc;

use http::{Method, StatusCode};
use rustauth_core::api::{
    create_auth_endpoint, parse_request_body, BodyField, BodySchema, JsonSchemaType,
};
use rustauth_core::crypto::symmetric_decrypt;
use serde::{Deserialize, Serialize};

use super::flow_error_response;
use super::json_response;
use crate::two_factor::errors::{error_message, error_response};
use crate::two_factor::flow::verify_context;
use crate::two_factor::options::TwoFactorOptions;
use crate::two_factor::payloads::{body_options, code_schema, CodeBody};
use crate::two_factor::store::{update_user_two_factor_enabled, TwoFactorStore};
use crate::two_factor::totp::verify_totp_code;

use crate::two_factor::totp::totp_code;

#[derive(Deserialize)]
struct GenerateTotpBody {
    secret: String,
}

#[derive(Serialize)]
struct GenerateTotpResponse {
    code: String,
}

pub(super) fn generate_totp_endpoint(
    options: Arc<TwoFactorOptions>,
) -> rustauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/two-factor/generate-totp",
        Method::POST,
        body_options(
            "generateTotp",
            BodySchema::object([BodyField::new("secret", JsonSchemaType::String)]),
        ),
        move |_context, request| {
            let options = Arc::clone(&options);
            async move {
                if options.totp.disabled {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "TOTP_NOT_CONFIGURED",
                        error_message("TOTP_NOT_CONFIGURED"),
                    );
                }
                let body: GenerateTotpBody = parse_request_body(&request)?;
                if body.secret.is_empty() {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "INVALID_BODY",
                        error_message("INVALID_BODY"),
                    );
                }
                let now = time::OffsetDateTime::now_utc().unix_timestamp();
                let code = totp_code(
                    &body.secret,
                    options.totp.digits,
                    options.totp.period.whole_seconds() as u64,
                    now,
                );
                json_response(StatusCode::OK, &GenerateTotpResponse { code }, Vec::new())
            }
        },
    )
}

pub(super) fn verify_totp_endpoint(
    options: Arc<TwoFactorOptions>,
) -> rustauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/two-factor/verify-totp",
        Method::POST,
        body_options("verifyTotp", code_schema()),
        move |context, request| {
            let options = std::sync::Arc::clone(&options);
            async move {
                if options.totp.disabled {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "TOTP_NOT_CONFIGURED",
                        error_message("TOTP_NOT_CONFIGURED"),
                    );
                }
                let body: CodeBody = parse_request_body(&request)?;
                let mut flow = match verify_context(&context, &request, &options).await {
                    Ok(flow) => flow,
                    Err(error) => return flow_error_response(error),
                };
                let adapter = context.adapter_ref()?;
                let Some(record) = TwoFactorStore::new(adapter)
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
                    options.totp.period.whole_seconds() as u64,
                ) {
                    return error_response(
                        StatusCode::UNAUTHORIZED,
                        "INVALID_CODE",
                        error_message("INVALID_CODE"),
                    );
                }
                if record.verified != Some(true) {
                    update_user_two_factor_enabled(&context, &flow.user.id, true).await?;
                    TwoFactorStore::new(adapter)
                        .mark_verified(&record.id)
                        .await?;
                }
                flow.trust_device = body.trust_device.unwrap_or(false);
                match flow.valid(&context, &options).await {
                    Ok(response) => Ok(response),
                    Err(error) => flow_error_response(error),
                }
            }
        },
    )
}
