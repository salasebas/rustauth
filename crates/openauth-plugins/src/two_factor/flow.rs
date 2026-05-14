use std::sync::Arc;

use data_encoding::BASE64URL_NOPAD;
use hmac::{Hmac, Mac};
use http::{header, StatusCode};
use openauth_core::api::{ApiRequest, ApiResponse};
use openauth_core::auth::session::{GetSessionInput, SessionAuth};
use openauth_core::cookies::{delete_session_cookie, set_session_cookie, SessionCookieOptions};
use openauth_core::crypto::random::generate_random_string;
use openauth_core::db::{DbAdapter, User};
use openauth_core::error::OpenAuthError;
use openauth_core::plugin::PluginAfterHookAction;
use openauth_core::session::{CreateSessionInput, DbSessionStore};
use openauth_core::verification::{CreateVerificationInput, DbVerificationStore};
use serde::{Deserialize, Serialize};
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
    user: User,
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
    user: User,
}

pub(super) async fn sign_in_after_hook(
    context: &openauth_core::context::AuthContext,
    request: &ApiRequest,
    response: ApiResponse,
    options: Arc<TwoFactorOptions>,
) -> Result<PluginAfterHookAction, OpenAuthError> {
    if response.status() != StatusCode::OK {
        return Ok(PluginAfterHookAction::Continue(response));
    }
    let body: SignInBody = match serde_json::from_slice(response.body()) {
        Ok(body) => body,
        Err(_) => return Ok(PluginAfterHookAction::Continue(response)),
    };
    let Some(adapter) = context.adapter() else {
        return Ok(PluginAfterHookAction::Continue(response));
    };
    if !user_two_factor_enabled(adapter.as_ref(), &body.user.id).await? {
        return Ok(PluginAfterHookAction::Continue(response));
    }
    let invalid_trust_device_cookie = match trusted_device_cookie_if_valid(
        context,
        adapter.as_ref(),
        request,
        &body.user.id,
        &options,
    )
    .await?
    {
        TrustedDeviceCheck::Valid(cookie) => {
            let mut response = response;
            append_cookies(&mut response, &[cookie])?;
            return Ok(PluginAfterHookAction::Continue(response));
        }
        TrustedDeviceCheck::Invalid(cookie) => Some(cookie),
        TrustedDeviceCheck::Missing => None,
    };
    DbSessionStore::new(adapter.as_ref())
        .delete_session(&body.token)
        .await?;
    let identifier = format!("2fa-{}", generate_random_string(20));
    DbVerificationStore::new(adapter.as_ref())
        .create_verification(CreateVerificationInput::new(
            identifier.clone(),
            body.user.id.clone(),
            OffsetDateTime::now_utc() + Duration::seconds(options.two_factor_cookie_max_age as i64),
        ))
        .await?;
    let two_factor_cookie = plugin_cookie(
        &context.auth_cookies.session_token,
        TWO_FACTOR_COOKIE_NAME,
        options.two_factor_cookie_max_age,
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
    pub(super) adapter: Arc<dyn DbAdapter>,
    pub(super) user: User,
    pub(super) session: Option<openauth_core::db::Session>,
    pub(super) key: String,
    pub(super) trust_device: bool,
}

impl VerifyFlow {
    pub(super) async fn valid(
        self,
        context: &openauth_core::context::AuthContext,
        options: &TwoFactorOptions,
    ) -> Result<ApiResponse, OpenAuthError> {
        if let Some(session) = self.session {
            return json_response(
                StatusCode::OK,
                &TokenUserBody {
                    token: session.token,
                    user: self.user,
                },
                Vec::new(),
            );
        }
        let expires_at =
            OffsetDateTime::now_utc() + Duration::seconds(context.session_config.expires_in as i64);
        let session = DbSessionStore::new(self.adapter.as_ref())
            .create_session(CreateSessionInput::new(&self.user.id, expires_at))
            .await?;
        DbVerificationStore::new(self.adapter.as_ref())
            .delete_verification(&self.key)
            .await?;
        let mut cookies = set_session_cookie(
            &context.auth_cookies,
            &context.secret,
            &session.token,
            SessionCookieOptions::default(),
        )?;
        let two_factor_cookie = plugin_cookie(
            &context.auth_cookies.session_token,
            TWO_FACTOR_COOKIE_NAME,
            options.two_factor_cookie_max_age,
        );
        cookies.push(expire_cookie(&two_factor_cookie));
        if self.trust_device {
            cookies.push(
                create_trust_device_cookie(
                    context,
                    self.adapter.as_ref(),
                    &self.user.id,
                    options.trust_device_max_age,
                )
                .await?,
            );
        }
        json_response(
            StatusCode::OK,
            &TokenUserBody {
                token: session.token,
                user: self.user,
            },
            cookies,
        )
    }
}

pub(super) async fn verify_context(
    context: &openauth_core::context::AuthContext,
    request: &ApiRequest,
    options: &TwoFactorOptions,
) -> Result<VerifyFlow, OpenAuthError> {
    let adapter = context.adapter().ok_or_else(|| {
        OpenAuthError::InvalidConfig("two factor plugin requires a database adapter".to_owned())
    })?;
    if let Some((session, user, _cookies)) =
        maybe_current_session(context, adapter.as_ref(), request).await?
    {
        return Ok(VerifyFlow {
            adapter,
            key: format!("{}!{}", user.id, session.id),
            user,
            session: Some(session),
            trust_device: false,
        });
    }
    let two_factor_cookie = plugin_cookie(
        &context.auth_cookies.session_token,
        TWO_FACTOR_COOKIE_NAME,
        options.two_factor_cookie_max_age,
    );
    let cookie_header = request_cookie(request).unwrap_or_default();
    let Some(identifier) =
        read_signed_cookie(&cookie_header, &two_factor_cookie.name, &context.secret)?
    else {
        return Err(OpenAuthError::Api("INVALID_TWO_FACTOR_COOKIE".to_owned()));
    };
    let Some(verification) = DbVerificationStore::new(adapter.as_ref())
        .find_verification(&identifier)
        .await?
    else {
        return Err(OpenAuthError::Api("INVALID_TWO_FACTOR_COOKIE".to_owned()));
    };
    let Some(user) = openauth_core::user::DbUserStore::new(adapter.as_ref())
        .find_user_by_id(&verification.value)
        .await?
    else {
        return Err(OpenAuthError::Api("INVALID_TWO_FACTOR_COOKIE".to_owned()));
    };
    Ok(VerifyFlow {
        adapter,
        user,
        session: None,
        key: identifier,
        trust_device: false,
    })
}

pub(super) async fn current_session(
    context: &openauth_core::context::AuthContext,
    request: &ApiRequest,
) -> Result<
    (
        Arc<dyn DbAdapter>,
        openauth_core::db::Session,
        User,
        Vec<openauth_core::cookies::Cookie>,
    ),
    OpenAuthError,
> {
    let adapter = context.adapter().ok_or_else(|| {
        OpenAuthError::InvalidConfig("two factor plugin requires a database adapter".to_owned())
    })?;
    let Some((session, user, cookies)) =
        maybe_current_session(context, adapter.as_ref(), request).await?
    else {
        return Err(OpenAuthError::Api("UNAUTHORIZED".to_owned()));
    };
    Ok((adapter, session, user, cookies))
}

pub(super) async fn validate_password(
    context: &openauth_core::context::AuthContext,
    adapter: &dyn DbAdapter,
    user_id: &str,
    password: Option<&str>,
    allow_passwordless: bool,
) -> Result<(), OpenAuthError> {
    let hash = credential_password_hash(adapter, user_id).await?;
    let requires_password = hash.is_some() || !allow_passwordless;
    if !requires_password {
        return Ok(());
    }
    let Some(password) = password else {
        return Err(OpenAuthError::Api("INVALID_PASSWORD".to_owned()));
    };
    let Some(hash) = hash else {
        return Err(OpenAuthError::Api("INVALID_PASSWORD".to_owned()));
    };
    if !(context.password.verify)(&hash, password)? {
        return Err(OpenAuthError::Api("INVALID_PASSWORD".to_owned()));
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

async fn maybe_current_session(
    context: &openauth_core::context::AuthContext,
    adapter: &dyn DbAdapter,
    request: &ApiRequest,
) -> Result<
    Option<(
        openauth_core::db::Session,
        User,
        Vec<openauth_core::cookies::Cookie>,
    )>,
    OpenAuthError,
> {
    let cookie_header = request_cookie(request).unwrap_or_default();
    let Some(result) = SessionAuth::new(adapter, context)
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
    Valid(openauth_core::cookies::Cookie),
    Invalid(openauth_core::cookies::Cookie),
    Missing,
}

async fn trusted_device_cookie_if_valid(
    context: &openauth_core::context::AuthContext,
    adapter: &dyn DbAdapter,
    request: &ApiRequest,
    user_id: &str,
    options: &TwoFactorOptions,
) -> Result<TrustedDeviceCheck, OpenAuthError> {
    let trust_cookie = plugin_cookie(
        &context.auth_cookies.session_token,
        TRUST_DEVICE_COOKIE_NAME,
        options.trust_device_max_age,
    );
    let cookie_header = request_cookie(request).unwrap_or_default();
    let has_trust_cookie =
        openauth_core::cookies::parse_cookies(&cookie_header).contains_key(&trust_cookie.name);
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
    let store = DbVerificationStore::new(adapter);
    let Some(record) = store.find_verification(identifier).await? else {
        return Ok(TrustedDeviceCheck::Invalid(expire_cookie(&trust_cookie)));
    };
    if record.value != user_id {
        return Ok(TrustedDeviceCheck::Invalid(expire_cookie(&trust_cookie)));
    }
    store.delete_verification(identifier).await?;
    Ok(TrustedDeviceCheck::Valid(
        create_trust_device_cookie(context, adapter, user_id, options.trust_device_max_age).await?,
    ))
}

async fn create_trust_device_cookie(
    context: &openauth_core::context::AuthContext,
    adapter: &dyn DbAdapter,
    user_id: &str,
    max_age: u64,
) -> Result<openauth_core::cookies::Cookie, OpenAuthError> {
    let identifier = format!("trust-device-{}", generate_random_string(32));
    let token = trust_token(&context.secret, user_id, &identifier)?;
    DbVerificationStore::new(adapter)
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
) -> Result<Vec<&'static str>, OpenAuthError> {
    let mut methods = Vec::new();
    if !options.totp.disabled
        && TwoFactorStore::new(adapter, &options.two_factor_table)
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

fn trust_token(secret: &str, user_id: &str, identifier: &str) -> Result<String, OpenAuthError> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|error| OpenAuthError::Crypto(error.to_string()))?;
    mac.update(format!("{user_id}!{identifier}").as_bytes());
    Ok(BASE64URL_NOPAD.encode(&mac.finalize().into_bytes()))
}

fn json_response<T: Serialize>(
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
