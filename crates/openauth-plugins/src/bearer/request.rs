use openauth_core::context::AuthContext;
use openauth_core::cookies::{sign_cookie_value, verify_cookie_value};
use openauth_core::error::OpenAuthError;
use openauth_core::plugin::{PluginRequest, PluginRequestAction};

use super::BearerOptions;

const AUTHORIZATION: &str = "authorization";
const COOKIE: &str = "cookie";
const BEARER_SCHEME: &str = "bearer";

pub(super) fn handle(
    context: &AuthContext,
    mut request: PluginRequest,
    options: BearerOptions,
) -> Result<PluginRequestAction, OpenAuthError> {
    let Some(header) = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return Ok(PluginRequestAction::Continue(request));
    };
    let Some(token) = bearer_token(header) else {
        return Ok(PluginRequestAction::Continue(request));
    };
    let Some(signed_token) = signed_session_token(token, &context.secret, options)? else {
        return Ok(PluginRequestAction::Continue(request));
    };

    let cookie = session_cookie(context, &signed_token);
    let header_value = match request
        .headers()
        .get(COOKIE)
        .and_then(|value| value.to_str().ok())
    {
        Some(existing) if !existing.trim().is_empty() => format!("{existing}; {cookie}"),
        _ => cookie,
    };
    if let Ok(value) = header_value.parse() {
        request.headers_mut().insert(COOKIE, value);
    }
    Ok(PluginRequestAction::Continue(request))
}

fn bearer_token(header: &str) -> Option<&str> {
    let trimmed = header.trim_start();
    let (scheme, rest) = trimmed.split_once(char::is_whitespace)?;
    if !scheme.eq_ignore_ascii_case(BEARER_SCHEME) {
        return None;
    }
    let token = rest.trim();
    (!token.is_empty()).then_some(token)
}

fn signed_session_token(
    token: &str,
    secret: &str,
    options: BearerOptions,
) -> Result<Option<String>, OpenAuthError> {
    if token.contains('.') {
        let decoded = percent_decode(token);
        return verify_cookie_value(&decoded, secret).map(|valid| valid.map(|_| decoded));
    }
    if options.require_signature {
        return Ok(None);
    }
    sign_cookie_value(token, secret).map(Some)
}

fn session_cookie(context: &AuthContext, signed_token: &str) -> String {
    format!("{}={signed_token}", context.auth_cookies.session_token.name)
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (from_hex(bytes[index + 1]), from_hex(bytes[index + 2])) {
                output.push((hi << 4) | lo);
                index += 3;
                continue;
            }
        }
        output.push(bytes[index]);
        index += 1;
    }
    String::from_utf8(output).unwrap_or_else(|_| value.to_owned())
}

fn from_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
