use std::sync::Arc;

use http::{header, Method, StatusCode};
use openauth_core::api::{create_auth_endpoint, parse_request_body, ApiRequest, ApiResponse};
use openauth_core::crypto::random::generate_random_string;
use openauth_core::crypto::{symmetric_decrypt, symmetric_encrypt};
use openauth_core::error::OpenAuthError;
use openauth_core::plugin::{AuthPlugin, PluginRateLimitRule};
use openauth_core::verification::DbVerificationStore;
use serde::Serialize;

use super::backup_codes::{
    consume_backup_code, decode_backup_codes, encode_backup_codes, generate_backup_codes,
};
use super::cookies::{
    append_cookies, expire_cookie, plugin_cookie, read_signed_cookie, TRUST_DEVICE_COOKIE_NAME,
};
use super::errors::{error_message, error_response, plugin_error_codes};
use super::flow::{current_session, sign_in_after_hook, validate_password, verify_context};
use super::options::TwoFactorOptions;
use super::payloads::{
    body_options, code_schema, password_issuer_schema, password_schema, view_backup_codes_schema,
    BackupCodesBody, CodeBody, EnableBody, EnableBodyResponse, PasswordBody, StatusBody,
    TokenUserBody, ViewBackupCodesBody,
};
use super::schema;
use super::store::{update_user_two_factor_enabled, user_two_factor_enabled, TwoFactorStore};
use super::totp::{totp_uri, validate_digits, verify_totp_code};

pub fn plugin(options: Arc<TwoFactorOptions>) -> AuthPlugin {
    let mut plugin = AuthPlugin::new(super::UPSTREAM_PLUGIN_ID)
        .with_version(env!("CARGO_PKG_VERSION"))
        .with_rate_limit(PluginRateLimitRule::new(
            "/two-factor/*",
            openauth_core::options::RateLimitRule { window: 10, max: 3 },
        ))
        .with_async_after_hook("/sign-in/email", {
            let options = Arc::clone(&options);
            move |context, request, response| {
                let options = Arc::clone(&options);
                Box::pin(
                    async move { sign_in_after_hook(context, request, response, options).await },
                )
            }
        });
    for contribution in schema::contributions(&options.two_factor_table) {
        plugin = plugin.with_schema(contribution);
    }
    for code in plugin_error_codes() {
        plugin = plugin.with_error_code(code);
    }
    for endpoint in endpoints(options) {
        plugin = plugin.with_endpoint(endpoint);
    }
    plugin
}

fn endpoints(options: Arc<TwoFactorOptions>) -> Vec<openauth_core::api::AsyncAuthEndpoint> {
    vec![
        enable_endpoint(Arc::clone(&options)),
        disable_endpoint(Arc::clone(&options)),
        get_totp_uri_endpoint(Arc::clone(&options)),
        verify_totp_endpoint(Arc::clone(&options)),
        super::otp_routes::send_otp_endpoint(Arc::clone(&options)),
        super::otp_routes::verify_otp_endpoint(Arc::clone(&options)),
        generate_backup_codes_endpoint(Arc::clone(&options)),
        verify_backup_code_endpoint(Arc::clone(&options)),
        view_backup_codes_endpoint(options),
    ]
}

fn enable_endpoint(options: Arc<TwoFactorOptions>) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/two-factor/enable",
        Method::POST,
        body_options(password_issuer_schema()),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                validate_digits(options.totp.digits)?;
                let body: EnableBody = parse_request_body(&request)?;
                let (adapter, _session, user, cookies) =
                    match current_session(context, &request).await {
                        Ok(session) => session,
                        Err(error) => return flow_error_response(error),
                    };
                if let Err(error) = validate_password(
                    context,
                    adapter.as_ref(),
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
                let store = TwoFactorStore::new(adapter.as_ref(), &options.two_factor_table);
                let verified = options.skip_verification_on_enable
                    || store
                        .find_by_user(&user.id)
                        .await?
                        .is_some_and(|record| record.verified != Some(false));
                if verified {
                    update_user_two_factor_enabled(adapter.as_ref(), &user.id, true).await?;
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
                            options.totp.period,
                        ),
                        backup_codes,
                    },
                    cookies,
                )
            })
        },
    )
}

fn disable_endpoint(options: Arc<TwoFactorOptions>) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/two-factor/disable",
        Method::POST,
        body_options(password_schema()),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                let body: PasswordBody = parse_request_body(&request)?;
                let (adapter, _session, user, mut cookies) =
                    match current_session(context, &request).await {
                        Ok(session) => session,
                        Err(error) => return flow_error_response(error),
                    };
                if let Err(error) = validate_password(
                    context,
                    adapter.as_ref(),
                    &user.id,
                    body.password.as_deref(),
                    options.allow_passwordless,
                )
                .await
                {
                    return flow_error_response(error);
                }
                update_user_two_factor_enabled(adapter.as_ref(), &user.id, false).await?;
                TwoFactorStore::new(adapter.as_ref(), &options.two_factor_table)
                    .delete_for_user(&user.id)
                    .await?;
                let trust_cookie = plugin_cookie(
                    &context.auth_cookies.session_token,
                    TRUST_DEVICE_COOKIE_NAME,
                    options.trust_device_max_age,
                );
                if let Some(value) = request_cookie(&request)
                    .and_then(|header| {
                        read_signed_cookie(&header, &trust_cookie.name, &context.secret).transpose()
                    })
                    .transpose()?
                {
                    if let Some((_, identifier)) = value.split_once('!') {
                        DbVerificationStore::new(adapter.as_ref())
                            .delete_verification(identifier)
                            .await?;
                    }
                    cookies.push(expire_cookie(&trust_cookie));
                }
                json_response(StatusCode::OK, &StatusBody { status: true }, cookies)
            })
        },
    )
}

fn get_totp_uri_endpoint(options: Arc<TwoFactorOptions>) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/two-factor/get-totp-uri",
        Method::POST,
        body_options(password_schema()),
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
                let body: PasswordBody = parse_request_body(&request)?;
                let (adapter, _session, user, cookies) =
                    match current_session(context, &request).await {
                        Ok(session) => session,
                        Err(error) => return flow_error_response(error),
                    };
                if let Err(error) = validate_password(
                    context,
                    adapter.as_ref(),
                    &user.id,
                    body.password.as_deref(),
                    options.allow_passwordless,
                )
                .await
                {
                    return flow_error_response(error);
                }
                let Some(record) = TwoFactorStore::new(adapter.as_ref(), &options.two_factor_table)
                    .find_by_user(&user.id)
                    .await?
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
                        "totpURI": totp_uri(&secret, issuer, &user.email, options.totp.digits, options.totp.period),
                    }),
                    cookies,
                )
            })
        },
    )
}

fn verify_totp_endpoint(options: Arc<TwoFactorOptions>) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/two-factor/verify-totp",
        Method::POST,
        body_options(code_schema()),
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

fn generate_backup_codes_endpoint(
    options: Arc<TwoFactorOptions>,
) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/two-factor/generate-backup-codes",
        Method::POST,
        body_options(password_schema()),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                let body: PasswordBody = parse_request_body(&request)?;
                let (adapter, _session, user, cookies) =
                    match current_session(context, &request).await {
                        Ok(session) => session,
                        Err(error) => return flow_error_response(error),
                    };
                if !user_two_factor_enabled(adapter.as_ref(), &user.id).await? {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "TWO_FACTOR_NOT_ENABLED",
                        error_message("TWO_FACTOR_NOT_ENABLED"),
                    );
                }
                if let Err(error) = validate_password(
                    context,
                    adapter.as_ref(),
                    &user.id,
                    body.password.as_deref(),
                    options.allow_passwordless,
                )
                .await
                {
                    return flow_error_response(error);
                }
                let Some(record) = TwoFactorStore::new(adapter.as_ref(), &options.two_factor_table)
                    .find_by_user(&user.id)
                    .await?
                else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "TWO_FACTOR_NOT_ENABLED",
                        error_message("TWO_FACTOR_NOT_ENABLED"),
                    );
                };
                let codes = generate_backup_codes(&options.backup_codes);
                let encoded = encode_backup_codes(&codes, &context.secret, &options.backup_codes)?;
                TwoFactorStore::new(adapter.as_ref(), &options.two_factor_table)
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
            })
        },
    )
}

fn verify_backup_code_endpoint(
    options: Arc<TwoFactorOptions>,
) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/two-factor/verify-backup-code",
        Method::POST,
        body_options(code_schema()),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                let body: CodeBody = parse_request_body(&request)?;
                let flow = match verify_context(context, &request, &options).await {
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
                if !TwoFactorStore::new(flow.adapter.as_ref(), &options.two_factor_table)
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
                    return json_response(
                        StatusCode::OK,
                        &TokenUserBody {
                            token: flow
                                .session
                                .as_ref()
                                .map(|session| session.token.clone())
                                .unwrap_or_default(),
                            user: flow.user,
                        },
                        Vec::new(),
                    );
                }
                flow.valid(context, &options).await
            })
        },
    )
}

fn view_backup_codes_endpoint(
    options: Arc<TwoFactorOptions>,
) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/two-factor/view-backup-codes",
        Method::POST,
        body_options(view_backup_codes_schema()),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                let body: ViewBackupCodesBody = parse_request_body(&request)?;
                let adapter = context.adapter().ok_or_else(|| {
                    OpenAuthError::InvalidConfig(
                        "two factor plugin requires a database adapter".to_owned(),
                    )
                })?;
                let Some(record) = TwoFactorStore::new(adapter.as_ref(), &options.two_factor_table)
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
            })
        },
    )
}

fn request_cookie(request: &ApiRequest) -> Option<String> {
    request
        .headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

pub(super) fn flow_error_response(error: OpenAuthError) -> Result<ApiResponse, OpenAuthError> {
    match error {
        OpenAuthError::Api(code) if code == "INVALID_TWO_FACTOR_COOKIE" => error_response(
            StatusCode::UNAUTHORIZED,
            "INVALID_TWO_FACTOR_COOKIE",
            error_message("INVALID_TWO_FACTOR_COOKIE"),
        ),
        OpenAuthError::Api(code) if code == "INVALID_PASSWORD" => error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_PASSWORD",
            error_message("INVALID_PASSWORD"),
        ),
        OpenAuthError::Api(code) if code == "UNAUTHORIZED" => error_response(
            StatusCode::UNAUTHORIZED,
            "INVALID_TWO_FACTOR_COOKIE",
            error_message("INVALID_TWO_FACTOR_COOKIE"),
        ),
        error => Err(error),
    }
}

pub(super) fn json_response<T: Serialize>(
    status: StatusCode,
    body: &T,
    cookies: Vec<openauth_core::cookies::Cookie>,
) -> Result<ApiResponse, OpenAuthError> {
    let body = serde_json::to_vec(body).map_err(|error| OpenAuthError::Api(error.to_string()))?;
    let mut response = http::Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .map_err(|error| OpenAuthError::Api(error.to_string()))?;
    append_cookies(&mut response, &cookies)?;
    Ok(response)
}
