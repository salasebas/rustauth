//! Typed HTTP request builders for the most common public auth flows.
//!
//! These helpers are framework-agnostic: pass the resulting `http::Request` to
//! Axum, `reqwest`, or [`RustAuth::handler_async`].

use http::{Method, Request};
use serde::Serialize;

use crate::config::AppConfig;

/// Build an absolute auth route URI from runtime config and a path suffix.
pub fn absolute_uri(config: &AppConfig, path: &str) -> String {
    let path = path.strip_prefix('/').unwrap_or(path);
    format!("{}/{}", config.auth_base_path.trim_end_matches('/'), path)
}

fn build_request(
    builder: http::request::Builder,
    body: Vec<u8>,
) -> Result<Request<Vec<u8>>, http::Error> {
    builder.body(body)
}

/// JSON POST against an auth route under the configured base path.
pub fn json_post(
    config: &AppConfig,
    path: &str,
    body: impl Serialize,
) -> Result<Request<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
    let payload = serde_json::to_vec(&body)?;
    Ok(build_request(
        Request::builder()
            .method(Method::POST)
            .uri(absolute_uri(config, path))
            .header(http::header::CONTENT_TYPE, "application/json"),
        payload,
    )?)
}

/// GET against an auth route, optionally forwarding a session cookie.
pub fn get(
    config: &AppConfig,
    path: &str,
    session_cookie: Option<&str>,
) -> Result<Request<Vec<u8>>, http::Error> {
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(absolute_uri(config, path));
    if let Some(cookie) = session_cookie {
        builder = builder.header(http::header::COOKIE, cookie);
    }
    build_request(builder, Vec::new())
}

#[derive(Debug, Serialize)]
pub struct SignUpEmailBody<'a> {
    pub name: &'a str,
    pub email: &'a str,
    pub password: &'a str,
    #[serde(rename = "rememberMe", skip_serializing_if = "Option::is_none")]
    pub remember_me: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct SignInEmailBody<'a> {
    pub email: &'a str,
    pub password: &'a str,
    #[serde(rename = "rememberMe", skip_serializing_if = "Option::is_none")]
    pub remember_me: Option<bool>,
}

pub fn sign_up_email(
    config: &AppConfig,
    body: SignUpEmailBody<'_>,
) -> Result<Request<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
    json_post(config, "/sign-up/email", body)
}

pub fn sign_in_email(
    config: &AppConfig,
    body: SignInEmailBody<'_>,
) -> Result<Request<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
    json_post(config, "/sign-in/email", body)
}

pub fn get_session(
    config: &AppConfig,
    session_cookie: &str,
) -> Result<Request<Vec<u8>>, http::Error> {
    get(config, "/get-session", Some(session_cookie))
}

pub fn sign_out(config: &AppConfig, session_cookie: &str) -> Result<Request<Vec<u8>>, http::Error> {
    build_request(
        Request::builder()
            .method(Method::POST)
            .uri(absolute_uri(config, "/sign-out"))
            .header(http::header::COOKIE, session_cookie),
        Vec::new(),
    )
}
