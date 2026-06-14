use std::sync::Arc;

use data_encoding::BASE64URL_NOPAD;
use hmac::{Hmac, Mac};
use http::{header, StatusCode};
use rustauth_core::api::output::user_output_value;
use rustauth_core::api::{ApiRequest, ApiResponse};
use rustauth_core::auth::session::{GetSessionInput, SessionAuth};
use rustauth_core::cookies::{delete_session_cookie, set_session_cookie, SessionCookieOptions};
use rustauth_core::crypto::random::generate_random_string;
use rustauth_core::db::{DbAdapter, User};
use rustauth_core::error::RustAuthError;
use rustauth_core::plugin::PluginAfterHookAction;
use rustauth_core::session::CreateSessionInput;
use rustauth_core::verification::CreateVerificationInput;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use time::{Duration, OffsetDateTime};

use super::cookies::{
    append_cookies, expire_cookie, plugin_cookie, read_signed_cookie, signed_cookie,
    TRUST_DEVICE_COOKIE_NAME, TWO_FACTOR_COOKIE_NAME,
};
use super::options::TwoFactorOptions;
use super::store::{credential_password_hash, user_two_factor_enabled, TwoFactorStore};

type HmacSha256 = Hmac<Sha256>;

#[derive(Serialize)]
struct TokenUserBody {
    token: String,
    user: Value,
}

#[derive(Deserialize)]
struct SignInUserRef {
    id: String,
}

#[derive(Serialize)]
struct TwoFactorRedirectBody {
    #[serde(rename = "twoFactorRedirect")]
    two_factor_redirect: bool,
    #[serde(rename = "twoFactorMethods")]
    two_factor_methods: Vec<&'static str>,
}

#[derive(Deserialize)]
struct SignInBody {
    token: String,
    user: SignInUserRef,
}

pub(super) async fn sign_in_after_hook(
    context: &rustauth_core::context::AuthContext,
    request: &ApiRequest,
    response: ApiResponse,
    options: Arc<TwoFactorOptions>,
) -> Result<PluginAfterHookAction, RustAuthError> {
    if response.status() != StatusCode::OK {
        return Ok(PluginAfterHookAction::Continue(response));
    }
    let body: SignInBody = match serde_json::from_slice(response.body()) {
        Ok(body) => body,
        Err(_) => return Ok(PluginAfterHookAction::Continue(response)),
    };
    let Ok(adapter) = context.require_adapter() else {
        return Ok(PluginAfterHookAction::Continue(response));
    };
    if !user_two_factor_enabled(adapter.as_ref(), &body.user.id).await? {
        return Ok(PluginAfterHookAction::Continue(response));
    }
    let preserve_dont_remember =
        response_sets_cookie(&response, &context.auth_cookies.dont_remember_token.name);
    let invalid_trust_device_cookie =
        match trusted_device_cookie_if_valid(context, request, &body.user.id, &options).await? {
            TrustedDeviceCheck::Valid(cookie) => {
                let mut response = response;
                append_cookies(&mut response, &[cookie])?;
                return Ok(PluginAfterHookAction::Continue(response));
            }
            TrustedDeviceCheck::Invalid(cookie) => Some(cookie),
            TrustedDeviceCheck::Missing => None,
        };
    context.sessions()?.delete_session(&body.token).await?;
    let identifier = format!("2fa-{}", generate_random_string(20));
    context
        .verifications()?
        .create_verification(CreateVerificationInput::new(
            identifier.clone(),
            body.user.id.clone(),
            OffsetDateTime::now_utc() + options.two_factor_cookie_max_age,
        ))
        .await?;
    let two_factor_cookie = plugin_cookie(
        &context.auth_cookies.session_token,
        TWO_FACTOR_COOKIE_NAME,
        options.two_factor_cookie_max_age.whole_seconds() as u64,
    );
    let mut cookies = delete_session_cookie(
        &context.auth_cookies,
        request_cookie(request).as_deref().unwrap_or_default(),
        true,
    );
    cookies.push(signed_cookie(
        &two_factor_cookie,
        &identifier,
        &context.secret,
    )?);
    if preserve_dont_remember {
        cookies.push(signed_cookie(
            &context.auth_cookies.dont_remember_token,
            "true",
            &context.secret,
        )?);
    }
    if let Some(cookie) = invalid_trust_device_cookie {
        cookies.push(cookie);
    }
    let methods = two_factor_methods(adapter.as_ref(), &body.user.id, &options).await?;
    let response = json_response(
        StatusCode::OK,
        &TwoFactorRedirectBody {
            two_factor_redirect: true,
            two_factor_methods: methods,
        },
        cookies,
    )?;
    Ok(PluginAfterHookAction::Continue(response))
}

pub(super) struct VerifyFlow {
    pub(super) user: User,
    pub(super) session: Option<rustauth_core::db::Session>,
    pub(super) key: String,
    pub(super) trust_device: bool,
    dont_remember: bool,
}

impl VerifyFlow {
    pub(super) async fn valid(
        self,
        context: &rustauth_core::context::AuthContext,
        options: &TwoFactorOptions,
    ) -> Result<ApiResponse, RustAuthError> {
        if let Some(session) = self.session {
            let user = user_output_value(context.adapter_ref()?, context, &self.user).await?;
            return json_response(
                StatusCode::OK,
                &TokenUserBody {
                    token: session.token,
                    user,
                },
                Vec::new(),
            );
        }
        let verification_store = context.verifications()?;
        let Some(verification) = verification_store.take_verification(&self.key).await? else {
            return Err(RustAuthError::Api("INVALID_TWO_FACTOR_COOKIE".to_owned()));
        };
        if verification.value != self.user.id {
            return Err(RustAuthError::Api("INVALID_TWO_FACTOR_COOKIE".to_owned()));
        }
        let expires_in = if self.dont_remember {
            time::Duration::days(1)
        } else {
            context.session_config.expires_in
        };
        let expires_at = OffsetDateTime::now_utc() + expires_in;
        let session = context
            .sessions()?
            .create_session(CreateSessionInput::new(&self.user.id, expires_at))
            .await?;
        let mut cookies = set_session_cookie(
            &context.auth_cookies,
            &context.secret,
            &session.token,
            SessionCookieOptions {
                dont_remember: self.dont_remember,
                ..SessionCookieOptions::default()
            },
        )?;
        let two_factor_cookie = plugin_cookie(
            &context.auth_cookies.session_token,
            TWO_FACTOR_COOKIE_NAME,
            options.two_factor_cookie_max_age.whole_seconds() as u64,
        );
        cookies.push(expire_cookie(&two_factor_cookie));
        if self.trust_device {
            cookies.push(
                create_trust_device_cookie(
                    context,
                    &self.user.id,
                    options.trust_device_max_age.whole_seconds() as u64,
                )
                .await?,
            );
            if self.dont_remember {
                cookies.push(expire_cookie(&context.auth_cookies.dont_remember_token));
            }
        }
        let user = user_output_value(context.adapter_ref()?, context, &self.user).await?;
        json_response(
            StatusCode::OK,
            &TokenUserBody {
                token: session.token,
                user,
            },
            cookies,
        )
    }
}

pub(super) async fn verify_context(
    context: &rustauth_core::context::AuthContext,
    request: &ApiRequest,
    options: &TwoFactorOptions,
) -> Result<VerifyFlow, RustAuthError> {
    if let Some((session, user, _cookies)) = maybe_current_session(context, request).await? {
        return Ok(VerifyFlow {
            key: format!("{}!{}", user.id, session.id),
            user,
            session: Some(session),
            trust_device: false,
            dont_remember: false,
        });
    }
    let two_factor_cookie = plugin_cookie(
        &context.auth_cookies.session_token,
        TWO_FACTOR_COOKIE_NAME,
        options.two_factor_cookie_max_age.whole_seconds() as u64,
    );
    let cookie_header = request_cookie(request).unwrap_or_default();
    let Some(identifier) =
        read_signed_cookie(&cookie_header, &two_factor_cookie.name, &context.secret)?
    else {
        return Err(RustAuthError::Api("INVALID_TWO_FACTOR_COOKIE".to_owned()));
    };
    let Some(verification) = context
        .verifications()?
        .find_verification(&identifier)
        .await?
    else {
        return Err(RustAuthError::Api("INVALID_TWO_FACTOR_COOKIE".to_owned()));
    };
    let Some(user) = context
        .users()?
        .find_user_by_id(&verification.value)
        .await?
    else {
        return Err(RustAuthError::Api("INVALID_TWO_FACTOR_COOKIE".to_owned()));
    };
    let dont_remember = read_signed_cookie(
        &cookie_header,
        &context.auth_cookies.dont_remember_token.name,
        &context.secret,
    )?
    .is_some();
    Ok(VerifyFlow {
        user,
        session: None,
        key: identifier,
        trust_device: false,
        dont_remember,
    })
}

pub(super) async fn current_session(
    context: &rustauth_core::context::AuthContext,
    request: &ApiRequest,
) -> Result<
    (
        rustauth_core::db::Session,
        User,
        Vec<rustauth_core::cookies::Cookie>,
    ),
    RustAuthError,
> {
    let Some((session, user, cookies)) = maybe_current_session(context, request).await? else {
        return Err(RustAuthError::Api("UNAUTHORIZED".to_owned()));
    };
    Ok((session, user, cookies))
}

pub(super) async fn validate_password(
    context: &rustauth_core::context::AuthContext,
    user_id: &str,
    password: Option<&str>,
    allow_passwordless: bool,
) -> Result<(), RustAuthError> {
    let hash = credential_password_hash(context, user_id).await?;
    let requires_password = hash.is_some() || !allow_passwordless;
    if !requires_password {
        return Ok(());
    }
    let Some(password) = password else {
        return Err(RustAuthError::Api("INVALID_PASSWORD".to_owned()));
    };
    let Some(hash) = hash else {
        return Err(RustAuthError::Api("INVALID_PASSWORD".to_owned()));
    };
    if !(context.password.verify)(&hash, password)? {
        return Err(RustAuthError::Api("INVALID_PASSWORD".to_owned()));
    }
    Ok(())
}

pub(super) fn request_cookie(request: &ApiRequest) -> Option<String> {
    request
        .headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn response_sets_cookie(response: &ApiResponse, name: &str) -> bool {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| value.trim_start().starts_with(&format!("{name}=")))
}

async fn maybe_current_session(
    context: &rustauth_core::context::AuthContext,
    request: &ApiRequest,
) -> Result<
    Option<(
        rustauth_core::db::Session,
        User,
        Vec<rustauth_core::cookies::Cookie>,
    )>,
    RustAuthError,
> {
    let cookie_header = request_cookie(request).unwrap_or_default();
    let Some(result) = SessionAuth::new(context)?
        .get_session(GetSessionInput::new(cookie_header))
        .await?
    else {
        return Ok(None);
    };
    Ok(result
        .session
        .zip(result.user)
        .map(|(session, user)| (session, user, result.cookies)))
}

enum TrustedDeviceCheck {
    Valid(rustauth_core::cookies::Cookie),
    Invalid(rustauth_core::cookies::Cookie),
    Missing,
}

async fn trusted_device_cookie_if_valid(
    context: &rustauth_core::context::AuthContext,
    request: &ApiRequest,
    user_id: &str,
    options: &TwoFactorOptions,
) -> Result<TrustedDeviceCheck, RustAuthError> {
    let trust_cookie = plugin_cookie(
        &context.auth_cookies.session_token,
        TRUST_DEVICE_COOKIE_NAME,
        options.trust_device_max_age.whole_seconds() as u64,
    );
    let cookie_header = request_cookie(request).unwrap_or_default();
    let has_trust_cookie =
        rustauth_core::cookies::parse_cookies(&cookie_header).contains_key(&trust_cookie.name);
    let Some(value) = read_signed_cookie(&cookie_header, &trust_cookie.name, &context.secret)?
    else {
        return Ok(if has_trust_cookie {
            TrustedDeviceCheck::Invalid(expire_cookie(&trust_cookie))
        } else {
            TrustedDeviceCheck::Missing
        });
    };
    let Some((token, identifier)) = value.split_once('!') else {
        return Ok(TrustedDeviceCheck::Invalid(expire_cookie(&trust_cookie)));
    };
    if token != trust_token(&context.secret, user_id, identifier)? {
        return Ok(TrustedDeviceCheck::Invalid(expire_cookie(&trust_cookie)));
    }
    let store = context.verifications()?;
    let Some(record) = store.find_verification(identifier).await? else {
        return Ok(TrustedDeviceCheck::Invalid(expire_cookie(&trust_cookie)));
    };
    if record.value != user_id {
        return Ok(TrustedDeviceCheck::Invalid(expire_cookie(&trust_cookie)));
    }
    store.delete_verification(identifier).await?;
    Ok(TrustedDeviceCheck::Valid(
        create_trust_device_cookie(
            context,
            user_id,
            options.trust_device_max_age.whole_seconds() as u64,
        )
        .await?,
    ))
}

async fn create_trust_device_cookie(
    context: &rustauth_core::context::AuthContext,
    user_id: &str,
    max_age: u64,
) -> Result<rustauth_core::cookies::Cookie, RustAuthError> {
    let identifier = format!("trust-device-{}", generate_random_string(32));
    let token = trust_token(&context.secret, user_id, &identifier)?;
    context
        .verifications()?
        .create_verification(CreateVerificationInput::new(
            identifier.clone(),
            user_id.to_owned(),
            OffsetDateTime::now_utc() + Duration::seconds(max_age as i64),
        ))
        .await?;
    let trust_cookie = plugin_cookie(
        &context.auth_cookies.session_token,
        TRUST_DEVICE_COOKIE_NAME,
        max_age,
    );
    signed_cookie(
        &trust_cookie,
        &format!("{token}!{identifier}"),
        &context.secret,
    )
}

async fn two_factor_methods(
    adapter: &dyn DbAdapter,
    user_id: &str,
    options: &TwoFactorOptions,
) -> Result<Vec<&'static str>, RustAuthError> {
    let mut methods = Vec::new();
    if !options.totp.disabled
        && TwoFactorStore::new(adapter)
            .find_by_user(user_id)
            .await?
            .is_some_and(|record| record.verified != Some(false))
    {
        methods.push("totp");
    }
    if options.otp.send_otp.is_some() {
        methods.push("otp");
    }
    Ok(methods)
}

fn trust_token(secret: &str, user_id: &str, identifier: &str) -> Result<String, RustAuthError> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|error| RustAuthError::Crypto(error.to_string()))?;
    mac.update(format!("{user_id}!{identifier}").as_bytes());
    Ok(BASE64URL_NOPAD.encode(&mac.finalize().into_bytes()))
}

fn json_response<T: Serialize>(
    status: StatusCode,
    body: &T,
    cookies: Vec<rustauth_core::cookies::Cookie>,
) -> Result<ApiResponse, RustAuthError> {
    let body = serde_json::to_vec(body).map_err(|error| RustAuthError::Api(error.to_string()))?;
    let mut response = http::Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .map_err(|error| RustAuthError::Api(error.to_string()))?;
    append_cookies(&mut response, &cookies)?;
    Ok(response)
}
