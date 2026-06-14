use std::sync::Arc;

use http::{Method, StatusCode};
use rustauth_core::api::{create_auth_endpoint, parse_request_body};
use rustauth_core::crypto::random::generate_random_string;
use rustauth_core::crypto::{symmetric_decrypt, symmetric_encrypt};

use super::{flow_error_response, json_response, rotate_session};
use crate::two_factor::backup_codes::{encode_backup_codes, generate_backup_codes};
use crate::two_factor::errors::{error_message, error_response};
use crate::two_factor::flow::{current_session, validate_password};
use crate::two_factor::options::TwoFactorOptions;
use crate::two_factor::payloads::{
    body_options, password_issuer_schema, password_schema, EnableBody, EnableBodyResponse,
    PasswordBody,
};
use crate::two_factor::store::{update_user_two_factor_enabled, TwoFactorStore};
use crate::two_factor::totp::{totp_uri, validate_digits};

pub(super) fn enable_endpoint(
    options: Arc<TwoFactorOptions>,
) -> rustauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/two-factor/enable",
        Method::POST,
        body_options("enableTwoFactor", password_issuer_schema()),
        move |context, request| {
            let options = std::sync::Arc::clone(&options);
            async move {
                validate_digits(options.totp.digits)?;
                let body: EnableBody = parse_request_body(&request)?;
                let (session, user, mut cookies) = match current_session(&context, &request).await {
                    Ok(session) => session,
                    Err(error) => return flow_error_response(error),
                };
                let adapter = context.adapter_ref()?;
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
                let secret = generate_random_string(32);
                let encrypted_secret = symmetric_encrypt(context.secret.as_str(), &secret)?;
                let backup_codes = generate_backup_codes(&options.backup_codes);
                let encoded_backup_codes =
                    encode_backup_codes(&backup_codes, &context.secret, &options.backup_codes)?;
                let store = TwoFactorStore::new(adapter);
                let verified = options.skip_verification_on_enable
                    || store
                        .find_by_user(&user.id)
                        .await?
                        .is_some_and(|record| record.verified != Some(false));
                if verified {
                    update_user_two_factor_enabled(&context, &user.id, true).await?;
                    if options.skip_verification_on_enable {
                        cookies = rotate_session(&context, &session, &user).await?;
                    }
                }
                store
                    .upsert_for_user(&user.id, encrypted_secret, encoded_backup_codes, verified)
                    .await?;
                let issuer = body
                    .issuer
                    .as_deref()
                    .or(options.issuer.as_deref())
                    .unwrap_or(&context.app_name);
                json_response(
                    StatusCode::OK,
                    &EnableBodyResponse {
                        totp_uri: totp_uri(
                            &secret,
                            issuer,
                            &user.email,
                            options.totp.digits,
                            options.totp.period.whole_seconds() as u64,
                        ),
                        backup_codes,
                    },
                    cookies,
                )
            }
        },
    )
}

pub(super) fn get_totp_uri_endpoint(
    options: Arc<TwoFactorOptions>,
) -> rustauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/two-factor/get-totp-uri",
        Method::POST,
        body_options("getTotpUri", password_schema()),
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
                let body: PasswordBody = parse_request_body(&request)?;
                let (_session, user, cookies) = match current_session(&context, &request).await {
                    Ok(session) => session,
                    Err(error) => return flow_error_response(error),
                };
                let adapter = context.adapter_ref()?;
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
                        "TOTP_NOT_ENABLED",
                        error_message("TOTP_NOT_ENABLED"),
                    );
                };
                let secret = symmetric_decrypt(context.secret.as_str(), &record.secret)?;
                let issuer = options.issuer.as_deref().unwrap_or(&context.app_name);
                json_response(
                    StatusCode::OK,
                    &serde_json::json!({
                        "totpURI": totp_uri(&secret, issuer, &user.email, options.totp.digits, options.totp.period.whole_seconds() as u64),
                    }),
                    cookies,
                )
            }
        },
    )
}
