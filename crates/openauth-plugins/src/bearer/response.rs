use std::collections::BTreeSet;

use openauth_core::context::AuthContext;
use openauth_core::cookies::parse_set_cookie_header;
use openauth_core::error::OpenAuthError;
use openauth_core::plugin::{PluginRequest, PluginResponse};

const ACCESS_CONTROL_EXPOSE_HEADERS: &str = "access-control-expose-headers";
const SET_AUTH_TOKEN: &str = "set-auth-token";
const SET_COOKIE: &str = "set-cookie";

pub(super) fn handle(
    context: &AuthContext,
    _request: &PluginRequest,
    mut response: PluginResponse,
) -> Result<PluginResponse, OpenAuthError> {
    let Some(token) = session_cookie_token(context, &response) else {
        return Ok(response);
    };
    let Ok(token_value) = token.parse() else {
        return Ok(response);
    };
    response.headers_mut().insert(SET_AUTH_TOKEN, token_value);
    expose_auth_token_header(&mut response)?;
    Ok(response)
}

fn session_cookie_token(context: &AuthContext, response: &PluginResponse) -> Option<String> {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .find_map(|value| {
            let value = value.to_str().ok()?;
            let cookies = parse_set_cookie_header(value);
            let cookie = cookies.get(&context.auth_cookies.session_token.name)?;
            if cookie.value.is_empty() || cookie.max_age == Some(0) {
                return None;
            }
            Some(cookie.value.clone())
        })
}

fn expose_auth_token_header(response: &mut PluginResponse) -> Result<(), OpenAuthError> {
    let mut exposed = response
        .headers()
        .get(ACCESS_CONTROL_EXPOSE_HEADERS)
        .and_then(|value| value.to_str().ok())
        .map(header_set)
        .unwrap_or_default();
    exposed.insert(SET_AUTH_TOKEN.to_owned());
    let value = exposed.into_iter().collect::<Vec<_>>().join(", ");
    let value = value
        .parse()
        .map_err(|error| OpenAuthError::Api(format!("invalid expose header: {error}")))?;
    response
        .headers_mut()
        .insert(ACCESS_CONTROL_EXPOSE_HEADERS, value);
    Ok(())
}

fn header_set(value: &str) -> BTreeSet<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|header| !header.is_empty())
        .map(str::to_owned)
        .collect()
}
