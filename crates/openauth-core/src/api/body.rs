//! Request body parsing helpers for framework-neutral auth endpoints.

use http::header;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use super::ApiRequest;
use crate::error::OpenAuthError;

/// Parse a request body as JSON or `application/x-www-form-urlencoded`.
pub fn parse_request_body<T>(request: &ApiRequest) -> Result<T, OpenAuthError>
where
    T: DeserializeOwned,
{
    match request_content_type(request) {
        Some("application/json") => parse_json_body(request.body()),
        Some("application/x-www-form-urlencoded") => parse_form_body(request.body()),
        Some(content_type) => Err(OpenAuthError::UnsupportedContentType {
            content_type: content_type.to_owned(),
        }),
        None => Err(OpenAuthError::MissingContentType),
    }
}

fn parse_json_body<T>(body: &[u8]) -> Result<T, OpenAuthError>
where
    T: DeserializeOwned,
{
    serde_json::from_slice(body).map_err(|error| OpenAuthError::InvalidRequestBody {
        encoding: "JSON",
        message: error.to_string(),
    })
}

fn parse_form_body<T>(body: &[u8]) -> Result<T, OpenAuthError>
where
    T: DeserializeOwned,
{
    let body = std::str::from_utf8(body).map_err(|error| OpenAuthError::InvalidRequestBody {
        encoding: "form",
        message: error.to_string(),
    })?;
    let mut map = Map::new();

    if !body.is_empty() {
        for pair in body.split('&') {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            let name =
                decode_form_component(name).map_err(|error| OpenAuthError::InvalidRequestBody {
                    encoding: "form",
                    message: error.to_owned(),
                })?;
            let value = decode_form_component(value).map_err(|error| {
                OpenAuthError::InvalidRequestBody {
                    encoding: "form",
                    message: error.to_owned(),
                }
            })?;
            map.insert(name, form_value(value));
        }
    }

    serde_json::from_value(Value::Object(map)).map_err(|error| OpenAuthError::InvalidRequestBody {
        encoding: "form",
        message: error.to_string(),
    })
}

fn request_content_type(request: &ApiRequest) -> Option<&str> {
    let content_type = request.headers().get(header::CONTENT_TYPE)?.to_str().ok()?;
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim();
    media_type
        .eq_ignore_ascii_case("application/json")
        .then_some("application/json")
        .or_else(|| {
            media_type
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
                .then_some("application/x-www-form-urlencoded")
        })
        .or(Some(media_type))
}

fn form_value(value: String) -> Value {
    match value.as_str() {
        "true" => Value::Bool(true),
        "false" => Value::Bool(false),
        _ => Value::String(value),
    }
}

fn decode_form_component(value: &str) -> Result<String, &'static str> {
    let mut decoded = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' => {
                if index + 2 >= bytes.len() {
                    return Err("incomplete percent escape");
                }
                let high = hex_value(bytes[index + 1]).ok_or("invalid percent escape")?;
                let low = hex_value(bytes[index + 2]).ok_or("invalid percent escape")?;
                decoded.push((high << 4) | low);
                index += 3;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }

    String::from_utf8(decoded).map_err(|_| "decoded form value is not valid UTF-8")
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
