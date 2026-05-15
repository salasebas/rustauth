#![allow(clippy::expect_used)]

use std::sync::{Arc, Mutex};

pub use http::StatusCode;
use http::{header, Method, Request};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::cookies::{set_session_cookie, Cookie, SessionCookieOptions};
use openauth_core::crypto::password::hash_password;
use openauth_core::db::{DbAdapter, DbValue, FindOne, MemoryAdapter, User, Where};
use openauth_core::options::{AdvancedOptions, OpenAuthOptions};
use openauth_core::session::{CreateSessionInput, DbSessionStore};
use openauth_core::user::{CreateCredentialAccountInput, CreateUserInput, DbUserStore};
use openauth_plugins::email_otp::{email_otp, EmailOtpOptions, EmailOtpPayload};
pub use serde_json::Value;
use time::{Duration, OffsetDateTime};

const SECRET: &str = "test-secret-123456789012345678901234";

#[derive(Clone, Default)]
pub struct CaptureSender {
    sent: Arc<Mutex<Vec<EmailOtpPayload>>>,
}

impl CaptureSender {
    pub fn last_otp(&self) -> String {
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

    pub fn otps(&self) -> Vec<String> {
        self.sent
            .lock()
            .expect("capture sender lock")
            .iter()
            .map(|payload| payload.otp.clone())
            .collect()
    }
}

impl openauth_plugins::email_otp::SendEmailOtp for CaptureSender {
    fn send_email_otp(
        &self,
        payload: EmailOtpPayload,
        _request: Option<&Request<Vec<u8>>>,
    ) -> Result<(), openauth_core::error::OpenAuthError> {
        self.sent.lock().expect("capture sender lock").push(payload);
        Ok(())
    }
}

pub fn router(
    adapter: Arc<MemoryAdapter>,
    sender: CaptureSender,
    mut options: EmailOtpOptions,
) -> Result<AuthRouter, openauth_core::error::OpenAuthError> {
    options.sender = Some(Arc::new(sender));
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some(SECRET.to_owned()),
            advanced: AdvancedOptions {
                disable_csrf_check: true,
                disable_origin_check: true,
                ..AdvancedOptions::default()
            },
            plugins: vec![email_otp(adapter.clone(), options)],
            ..OpenAuthOptions::default()
        },
        adapter.clone(),
    )?;
    AuthRouter::with_async_endpoints(context, Vec::new(), core_auth_async_endpoints(adapter))
}

pub fn router_with_auth_options(
    adapter: Arc<MemoryAdapter>,
    sender: CaptureSender,
    mut options: EmailOtpOptions,
    auth_options: OpenAuthOptions,
) -> Result<AuthRouter, openauth_core::error::OpenAuthError> {
    options.sender = Some(Arc::new(sender));
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some(SECRET.to_owned()),
            advanced: AdvancedOptions {
                disable_csrf_check: true,
                disable_origin_check: true,
                ..AdvancedOptions::default()
            },
            plugins: vec![email_otp(adapter.clone(), options)],
            ..auth_options
        },
        adapter.clone(),
    )?;
    AuthRouter::with_async_endpoints(context, Vec::new(), core_auth_async_endpoints(adapter))
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
    let hash = hash_password(password).expect("hash password");
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
    let context = openauth_core::context::create_auth_context(OpenAuthOptions {
        secret: Some(SECRET.to_owned()),
        ..OpenAuthOptions::default()
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

fn cookie_header(cookies: &[Cookie]) -> String {
    cookies
        .iter()
        .map(|cookie| format!("{}={}", cookie.name, cookie.value))
        .collect::<Vec<_>>()
        .join("; ")
}
