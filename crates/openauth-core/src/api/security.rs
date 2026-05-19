use http::{Method, StatusCode};
use serde_json::Value;

use crate::auth::trusted_origins::OriginMatchSettings;
use crate::context::AuthContext;
use crate::error::OpenAuthError;

use super::endpoint::{ApiRequest, ApiResponse};
use super::error::{api_error, ApiErrorCode};

pub(super) fn validate_request_security(
    context: &AuthContext,
    request: &ApiRequest,
    bypass_origin_security: bool,
) -> Result<Option<ApiResponse>, OpenAuthError> {
    if bypass_origin_security {
        return Ok(None);
    }

    if matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    ) {
        return Ok(None);
    }

    if !context.options.advanced.disable_csrf_check
        && !context.options.advanced.disable_origin_check
    {
        if request.headers().contains_key(http::header::COOKIE) {
            if let Some(rejection) = validate_origin_header(context, request)? {
                return Ok(Some(rejection));
            }
        } else if has_fetch_metadata(request) {
            if header_value(request, "sec-fetch-site") == Some("cross-site")
                && header_value(request, "sec-fetch-mode") == Some("navigate")
            {
                return forbidden(ApiErrorCode::CrossSiteNavigationLoginBlocked).map(Some);
            }
            if let Some(rejection) = validate_origin_header(context, request)? {
                return Ok(Some(rejection));
            }
        }
    }

    if context.options.advanced.disable_origin_check {
        return Ok(None);
    }

    for (label, url) in callback_urls(request) {
        let settings = Some(OriginMatchSettings {
            allow_relative_paths: true,
        });
        if !context.is_trusted_origin_for_request(&url, settings, Some(request))? {
            return forbidden(callback_error_code(label)).map(Some);
        }
    }

    Ok(None)
}

fn validate_origin_header(
    context: &AuthContext,
    request: &ApiRequest,
) -> Result<Option<ApiResponse>, OpenAuthError> {
    let Some(origin) = request_origin(request) else {
        return forbidden(ApiErrorCode::MissingOrNullOrigin).map(Some);
    };
    if origin == "null" {
        return forbidden(ApiErrorCode::MissingOrNullOrigin).map(Some);
    }
    if !context.is_trusted_origin_for_request(origin, None, Some(request))? {
        return forbidden(ApiErrorCode::InvalidOrigin).map(Some);
    }
    Ok(None)
}

fn request_origin(request: &ApiRequest) -> Option<&str> {
    request
        .headers()
        .get(http::header::ORIGIN)
        .or_else(|| request.headers().get(http::header::REFERER))
        .and_then(|value| value.to_str().ok())
}

fn has_fetch_metadata(request: &ApiRequest) -> bool {
    ["sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest"]
        .iter()
        .any(|name| header_value(request, name).is_some_and(|value| !value.trim().is_empty()))
}

fn header_value<'a>(request: &'a ApiRequest, name: &str) -> Option<&'a str> {
    request.headers().get(name)?.to_str().ok()
}

fn callback_urls(request: &ApiRequest) -> Vec<(&'static str, String)> {
    let mut urls = Vec::new();
    for key in [
        "callbackURL",
        "redirectTo",
        "errorCallbackURL",
        "newUserCallbackURL",
    ] {
        if let Some(value) = query_param(request.uri().query(), key) {
            urls.push((url_label(key), value));
        }
    }

    if let Ok(Value::Object(body)) = serde_json::from_slice::<Value>(request.body()) {
        for key in [
            "callbackURL",
            "redirectTo",
            "errorCallbackURL",
            "newUserCallbackURL",
        ] {
            if let Some(Value::String(value)) = body.get(key) {
                urls.push((url_label(key), value.clone()));
            }
        }
    }

    urls
}

fn query_param(query: Option<&str>, key: &str) -> Option<String> {
    query?.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (decode_query_component(name) == key).then(|| decode_query_component(value))
    })
}

fn decode_query_component(value: &str) -> String {
    let mut decoded = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let high = hex_value(bytes[index + 1]);
                let low = hex_value(bytes[index + 2]);
                if let (Some(high), Some(low)) = (high, low) {
                    decoded.push((high << 4) | low);
                    index += 3;
                } else {
                    decoded.push(bytes[index]);
                    index += 1;
                }
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }

    String::from_utf8(decoded).unwrap_or_else(|_| value.to_owned())
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn url_label(key: &str) -> &'static str {
    match key {
        "callbackURL" => "callbackURL",
        "redirectTo" => "redirectURL",
        "errorCallbackURL" => "errorCallbackURL",
        "newUserCallbackURL" => "newUserCallbackURL",
        _ => "url",
    }
}

fn callback_error_code(label: &str) -> ApiErrorCode {
    match label {
        "callbackURL" => ApiErrorCode::InvalidCallbackUrl,
        "redirectURL" => ApiErrorCode::InvalidRedirectUrl,
        "errorCallbackURL" => ApiErrorCode::InvalidErrorCallbackUrl,
        "newUserCallbackURL" => ApiErrorCode::InvalidNewUserCallbackUrl,
        _ => ApiErrorCode::InvalidCallbackUrl,
    }
}

fn forbidden(code: ApiErrorCode) -> Result<ApiResponse, OpenAuthError> {
    api_error(StatusCode::FORBIDDEN, code)
}
