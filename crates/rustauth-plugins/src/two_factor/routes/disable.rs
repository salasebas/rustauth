use std::sync::Arc;

use http::{Method, StatusCode};
use rustauth_core::api::{create_auth_endpoint, parse_request_body};

use super::{flow_error_response, json_response, request_cookie, rotate_session};
use crate::two_factor::cookies::{
    expire_cookie, plugin_cookie, read_signed_cookie, TRUST_DEVICE_COOKIE_NAME,
};
use crate::two_factor::flow::{current_session, validate_password};
use crate::two_factor::options::TwoFactorOptions;
use crate::two_factor::payloads::{body_options, password_schema, PasswordBody, StatusBody};
use crate::two_factor::store::{update_user_two_factor_enabled, TwoFactorStore};

pub(super) fn disable_endpoint(
    options: Arc<TwoFactorOptions>,
) -> rustauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/two-factor/disable",
        Method::POST,
        body_options("disableTwoFactor", password_schema()),
        move |context, request| {
            let options = std::sync::Arc::clone(&options);
            async move {
                let body: PasswordBody = parse_request_body(&request)?;
                let (session, user, _cookies) = match current_session(&context, &request).await {
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
                update_user_two_factor_enabled(&context, &user.id, false).await?;
                TwoFactorStore::new(adapter)
                    .delete_for_user(&user.id)
                    .await?;
                let mut cookies = rotate_session(&context, &session, &user).await?;
                let trust_cookie = plugin_cookie(
                    &context.auth_cookies.session_token,
                    TRUST_DEVICE_COOKIE_NAME,
                    options.trust_device_max_age.whole_seconds() as u64,
                );
                if let Some(value) = request_cookie(&request)
                    .and_then(|header| {
                        read_signed_cookie(&header, &trust_cookie.name, &context.secret).transpose()
                    })
                    .transpose()?
                {
                    if let Some((_, identifier)) = value.split_once('!') {
                        context
                            .verifications()?
                            .delete_verification(identifier)
                            .await?;
                    }
                    cookies.push(expire_cookie(&trust_cookie));
                }
                json_response(StatusCode::OK, &StatusBody { status: true }, cookies)
            }
        },
    )
}
