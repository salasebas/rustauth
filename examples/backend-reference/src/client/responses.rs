//! Minimal response parsing helpers for integrators.

use http::Response;
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
pub struct AuthSessionResponse {
    pub user: Value,
    pub session: Value,
    pub token: Option<String>,
}

pub fn parse_json_body(response: &Response<Vec<u8>>) -> Result<Value, serde_json::Error> {
    serde_json::from_slice(response.body())
}

pub fn session_cookie(response: &Response<Vec<u8>>) -> Option<String> {
    response
        .headers()
        .get_all(http::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|cookie| cookie.split(';').next().map(str::to_owned))
}
