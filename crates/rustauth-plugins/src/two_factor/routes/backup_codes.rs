use std::sync::Arc;

use http::{Method, StatusCode};
use rustauth_core::api::output::user_output_value;
use rustauth_core::api::{create_auth_endpoint, parse_request_body};

use super::{flow_error_response, json_response};
use crate::two_factor::backup_codes::{
    consume_backup_code, decode_backup_codes, encode_backup_codes, generate_backup_codes,
};
use crate::two_factor::errors::{error_message, error_response};
use crate::two_factor::flow::{current_session, validate_password, verify_context};
use crate::two_factor::options::TwoFactorOptions;
use crate::two_factor::payloads::{
    body_options, code_schema, password_schema, view_backup_codes_schema, BackupCodesBody,
    CodeBody, PasswordBody, TokenUserBody, ViewBackupCodesBody,
};
use crate::two_factor::store::{user_two_factor_enabled, TwoFactorStore};

pub(super) fn generate_backup_codes_endpoint(
    options: Arc<TwoFactorOptions>,
) -> rustauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/two-factor/generate-backup-codes",
        Method::POST,
        body_options("generateBackupCodes", password_schema()),
        move |context, request| {
            let options = std::sync::Arc::clone(&options);
            async move {
                let body: PasswordBody = parse_request_body(&request)?;
                let (_session, user, cookies) = match current_session(&context, &request).await {
                    Ok(session) => session,
                    Err(error) => return flow_error_response(error),
                };
                let adapter = context.adapter_ref()?;
                if !user_two_factor_enabled(adapter, &user.id).await? {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "TWO_FACTOR_NOT_ENABLED",
                        error_message("TWO_FACTOR_NOT_ENABLED"),
                    );
                }
                if let Err(error) = validate_password(
                    &context,
                    &user.id,
                    body.password.as_deref(),
                    options.allow_passwordless,
                )
                .await
                {
                    return flow_error_response(error);
                }
                let Some(record) = TwoFactorStore::new(adapter).find_by_user(&user.id).await?
                else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "TWO_FACTOR_NOT_ENABLED",
                        error_message("TWO_FACTOR_NOT_ENABLED"),
                    );
                };
                let codes = generate_backup_codes(&options.backup_codes);
                let encoded = encode_backup_codes(&codes, &context.secret, &options.backup_codes)?;
                TwoFactorStore::new(adapter)
                    .update_backup_codes_if_current(&record.id, &record.backup_codes, encoded)
                    .await?;
                json_response(
                    StatusCode::OK,
                    &BackupCodesBody {
                        status: true,
                        backup_codes: codes,
                    },
                    cookies,
                )
            }
        },
    )
}

pub(super) fn verify_backup_code_endpoint(
    options: Arc<TwoFactorOptions>,
) -> rustauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/two-factor/verify-backup-code",
        Method::POST,
        body_options("verifyBackupCode", code_schema()),
        move |context, request| {
            let options = std::sync::Arc::clone(&options);
            async move {
                let body: CodeBody = parse_request_body(&request)?;
                let flow = match verify_context(&context, &request, &options).await {
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
                        "BACKUP_CODES_NOT_ENABLED",
                        error_message("BACKUP_CODES_NOT_ENABLED"),
                    );
                };
                let codes = decode_backup_codes(
                    &record.backup_codes,
                    &context.secret,
                    &options.backup_codes,
                )?;
                let Some(updated) = consume_backup_code(&codes, &body.code) else {
                    return error_response(
                        StatusCode::UNAUTHORIZED,
                        "INVALID_BACKUP_CODE",
                        error_message("INVALID_BACKUP_CODE"),
                    );
                };
                let encoded =
                    encode_backup_codes(&updated, &context.secret, &options.backup_codes)?;
                if !TwoFactorStore::new(adapter)
                    .update_backup_codes_if_current(&record.id, &record.backup_codes, encoded)
                    .await?
                {
                    return error_response(
                        StatusCode::CONFLICT,
                        "INVALID_BACKUP_CODE",
                        "Failed to verify backup code. Please try again.",
                    );
                }
                if body.disable_session.unwrap_or(false) {
                    let user =
                        user_output_value(context.adapter_ref()?, &context, &flow.user).await?;
                    return json_response(
                        StatusCode::OK,
                        &TokenUserBody {
                            token: flow
                                .session
                                .as_ref()
                                .map(|session| session.token.clone())
                                .unwrap_or_default(),
                            user,
                        },
                        Vec::new(),
                    );
                }
                match flow.valid(&context, &options).await {
                    Ok(response) => Ok(response),
                    Err(error) => flow_error_response(error),
                }
            }
        },
    )
}

pub(super) fn view_backup_codes_endpoint(
    options: Arc<TwoFactorOptions>,
) -> rustauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/two-factor/view-backup-codes",
        Method::POST,
        body_options("viewBackupCodes", view_backup_codes_schema()),
        move |context, request| {
            let options = std::sync::Arc::clone(&options);
            async move {
                let body: ViewBackupCodesBody = parse_request_body(&request)?;
                let adapter = context.adapter_ref()?;
                let Some(record) = TwoFactorStore::new(adapter)
                    .find_by_user(&body.user_id)
                    .await?
                else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "BACKUP_CODES_NOT_ENABLED",
                        error_message("BACKUP_CODES_NOT_ENABLED"),
                    );
                };
                let codes = decode_backup_codes(
                    &record.backup_codes,
                    &context.secret,
                    &options.backup_codes,
                )?;
                json_response(
                    StatusCode::OK,
                    &BackupCodesBody {
                        status: true,
                        backup_codes: codes,
                    },
                    Vec::new(),
                )
            }
        },
    )
}
