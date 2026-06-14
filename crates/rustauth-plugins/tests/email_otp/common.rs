#![allow(clippy::expect_used)]

use std::sync::{Arc, Mutex};

pub use http::StatusCode;
use http::{header, Method, Request};
use rustauth_core::api::{core_auth_async_endpoints, AuthRouter};
use rustauth_core::context::create_auth_context_with_adapter;
use rustauth_core::cookies::{set_session_cookie, Cookie, SessionCookieOptions};
use rustauth_core::db::{DbAdapter, DbValue, FindOne, MemoryAdapter, User, Where};
use rustauth_core::options::{AdvancedOptions, RustAuthOptions};
use rustauth_core::session::{CreateSessionInput, DbSessionStore};
use rustauth_core::test_utils::{with_integration_test_defaults, MemorySecondaryStorage};
use rustauth_core::user::{CreateCredentialAccountInput, CreateUserInput, DbUserStore};
use rustauth_core::TokioBackgroundTaskRunner;
use rustauth_plugins::email_otp::{email_otp, EmailOtpOptions, EmailOtpPayload};
pub use serde_json::Value;
use time::{Duration, OffsetDateTime};

const SECRET: &str = "test-secret-123456789012345678901234";

#[derive(Clone, Default)]
pub struct CaptureSender {
    sent: Arc<Mutex<Vec<EmailOtpPayload>>>,
}

impl CaptureSender {
    pub async fn wait_for_count(&self, min: usize) {
        for _ in 0..200 {
            if self.sent.lock().map(|sent| sent.len()).unwrap_or(0) >= min {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
    }

    pub async fn last_otp(&self) -> String {
        self.wait_for_count(1).await;
        self.sent
            .lock()
            .expect("capture sender lock")
            .last()
            .expect("captured otp")
            .otp
            .clone()
    }

    pub fn count(&self) -> usize {
        self.sent.lock().expect("capture sender lock").len()
    }

    pub async fn count_after_dispatch(&self, min: usize) -> usize {
        self.wait_for_count(min).await;
        self.count()
    }

    pub async fn otps(&self) -> Vec<String> {
        self.wait_for_count(1).await;
        self.sent
            .lock()
            .expect("capture sender lock")
            .iter()
            .map(|payload| payload.otp.clone())
            .collect()
    }
}

impl rustauth_plugins::email_otp::SendEmailOtp for CaptureSender {
    fn send_email_otp(
        &self,
        payload: EmailOtpPayload,
        _request: Option<&Request<Vec<u8>>>,
    ) -> rustauth_core::outbound::OutboundSendFuture {
        let sent = Arc::clone(&self.sent);
        Box::pin(async move {
            sent.lock().expect("capture sender lock").push(payload);
            Ok(())
        })
    }
}

pub fn router(
    adapter: Arc<MemoryAdapter>,
    sender: CaptureSender,
    options: EmailOtpOptions,
) -> Result<AuthRouter, rustauth_core::error::RustAuthError> {
    build_router(adapter, sender, options)
}

pub fn router_with_async_outbound(
    adapter: Arc<MemoryAdapter>,
    sender: CaptureSender,
    options: EmailOtpOptions,
) -> Result<AuthRouter, rustauth_core::error::RustAuthError> {
    build_router(adapter, sender, options)
}

fn build_router(
    adapter: Arc<MemoryAdapter>,
    sender: CaptureSender,
    mut options: EmailOtpOptions,
) -> Result<AuthRouter, rustauth_core::error::RustAuthError> {
    if options.sender.is_none() {
        options.sender = Some(Arc::new(sender));
    }
    let context = create_auth_context_with_adapter(
        with_integration_test_defaults(RustAuthOptions {
            secret: Some(SECRET.to_owned()),
            advanced: AdvancedOptions {
                disable_csrf_check: true,
                disable_origin_check: true,
                background_tasks: Some(Arc::new(TokioBackgroundTaskRunner)),
                ..AdvancedOptions::default()
            },
            plugins: vec![email_otp(options)?],
            ..RustAuthOptions::default()
        }),
        adapter.clone(),
    )?;
    AuthRouter::with_async_endpoints(context, Vec::new(), core_auth_async_endpoints())
}

pub fn router_with_auth_options(
    adapter: Arc<MemoryAdapter>,
    sender: CaptureSender,
    mut options: EmailOtpOptions,
    auth_options: RustAuthOptions,
) -> Result<AuthRouter, rustauth_core::error::RustAuthError> {
    if options.sender.is_none() {
        options.sender = Some(Arc::new(sender));
    }
    let context = create_auth_context_with_adapter(
        with_integration_test_defaults(RustAuthOptions {
            secret: Some(SECRET.to_owned()),
            advanced: AdvancedOptions {
                disable_csrf_check: true,
                disable_origin_check: true,
                background_tasks: Some(Arc::new(TokioBackgroundTaskRunner)),
                ..AdvancedOptions::default()
            },
            ..auth_options
        })
        .plugins(vec![email_otp(options)?]),
        adapter.clone(),
    )?;
    AuthRouter::with_async_endpoints(context, Vec::new(), core_auth_async_endpoints())
}

pub fn json_request(
    path: &str,
    body: &str,
    cookie: Option<&str>,
) -> Result<Request<Vec<u8>>, http::Error> {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(format!("http://localhost:3000/api/auth{path}"))
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(body.as_bytes().to_vec())
}

pub fn get_json_request(
    path: &str,
    body: &str,
    cookie: Option<&str>,
) -> Result<Request<Vec<u8>>, http::Error> {
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(format!("http://localhost:3000/api/auth{path}"))
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(body.as_bytes().to_vec())
}

pub fn set_cookie_values(response: &http::Response<Vec<u8>>) -> Vec<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok().map(str::to_owned))
        .collect()
}

pub async fn create_user(adapter: &MemoryAdapter, email: &str, verified: bool) -> User {
    DbUserStore::new(adapter)
        .create_user(
            CreateUserInput::new("Ada", email)
                .id(format!("user-{email}"))
                .email_verified(verified),
        )
        .await
        .expect("create user")
}

pub async fn create_credential(adapter: &MemoryAdapter, user_id: &str, password: &str) {
    let hash = fast_hash_password(password).expect("hash password");
    DbUserStore::new(adapter)
        .create_credential_account(CreateCredentialAccountInput::new(user_id, hash))
        .await
        .expect("create credential");
}

pub async fn session_cookie(adapter: &MemoryAdapter, user_id: &str) -> String {
    let session = DbSessionStore::new(adapter)
        .create_session(CreateSessionInput::new(
            user_id,
            OffsetDateTime::now_utc() + Duration::days(7),
        ))
        .await
        .expect("create session");
    let context = rustauth_core::context::create_auth_context(RustAuthOptions {
        secret: Some(SECRET.to_owned()),
        ..RustAuthOptions::default()
    })
    .expect("context");
    let cookies = set_session_cookie(
        &context.auth_cookies,
        &context.secret,
        &session.token,
        SessionCookieOptions::default(),
    )
    .expect("session cookie");
    cookie_header(&cookies)
}

pub async fn verification_value(adapter: &MemoryAdapter, identifier: &str) -> Option<String> {
    adapter
        .find_one(FindOne::new("verification").where_clause(Where::new(
            "identifier",
            DbValue::String(identifier.to_owned()),
        )))
        .await
        .expect("find verification")
        .and_then(|record| match record.get("value") {
            Some(DbValue::String(value)) => Some(value.clone()),
            _ => None,
        })
}

pub type TestSecondaryStorage = MemorySecondaryStorage;

pub use rustauth_core::test_utils::{fast_hash_password, fast_verify_password};

fn cookie_header(cookies: &[Cookie]) -> String {
    cookies
        .iter()
        .map(|cookie| format!("{}={}", cookie.name, cookie.value))
        .collect::<Vec<_>>()
        .join("; ")
}
