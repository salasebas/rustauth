use http::{header, HeaderValue, StatusCode};
use openauth_core::api::{ApiErrorResponse, ApiResponse};
use openauth_core::cookies::Cookie;
use openauth_core::error::OpenAuthError;
use serde::Serialize;
use url::Url;

pub(crate) fn json<T: Serialize>(
    status: StatusCode,
    body: &T,
    cookies: Vec<Cookie>,
) -> Result<ApiResponse, OpenAuthError> {
    let body = serde_json::to_vec(body).map_err(|error| OpenAuthError::Api(error.to_string()))?;
    let mut response = http::Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .map_err(|error| OpenAuthError::Api(error.to_string()))?;
    append_cookies(&mut response, cookies)?;
    Ok(response)
}

pub(crate) fn redirect(location: &str, cookies: Vec<Cookie>) -> Result<ApiResponse, OpenAuthError> {
    let mut response = http::Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, location)
        .body(Vec::new())
        .map_err(|error| OpenAuthError::Api(error.to_string()))?;
    append_cookies(&mut response, cookies)?;
    Ok(response)
}

pub(crate) fn redirect_with_error(
    location: &str,
    error: &str,
) -> Result<ApiResponse, OpenAuthError> {
    if let Ok(mut url) = Url::parse(location) {
        let mut pairs = url
            .query_pairs()
            .filter(|(key, _)| key != "error")
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect::<Vec<_>>();
        pairs.push(("error".to_owned(), error.to_owned()));
        url.set_query(None);
        {
            let mut query = url.query_pairs_mut();
            for (key, value) in pairs {
                query.append_pair(&key, &value);
            }
        }
        return redirect(url.as_str(), Vec::new());
    }
    let separator = if location.contains('?') { '&' } else { '?' };
    redirect(&format!("{location}{separator}error={error}"), Vec::new())
}

pub(crate) fn error(
    status: StatusCode,
    code: &str,
    message: &str,
) -> Result<ApiResponse, OpenAuthError> {
    json(
        status,
        &ApiErrorResponse {
            code: code.to_owned(),
            message: message.to_owned(),
            original_message: None,
        },
        Vec::new(),
    )
}

fn append_cookies(response: &mut ApiResponse, cookies: Vec<Cookie>) -> Result<(), OpenAuthError> {
    for cookie in cookies {
        response.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_str(&serialize_cookie(&cookie))
                .map_err(|error| OpenAuthError::Cookie(error.to_string()))?,
        );
    }
    Ok(())
}

fn serialize_cookie(cookie: &Cookie) -> String {
    let mut parts = vec![format!("{}={}", cookie.name, cookie.value)];
    if let Some(max_age) = cookie.attributes.max_age {
        parts.push(format!("Max-Age={max_age}"));
    }
    if let Some(expires) = &cookie.attributes.expires {
        parts.push(format!("Expires={expires}"));
    }
    if let Some(domain) = &cookie.attributes.domain {
        parts.push(format!("Domain={domain}"));
    }
    if let Some(path) = &cookie.attributes.path {
        parts.push(format!("Path={path}"));
    }
    if cookie.attributes.secure == Some(true) {
        parts.push("Secure".to_owned());
    }
    if cookie.attributes.http_only == Some(true) {
        parts.push("HttpOnly".to_owned());
    }
    if let Some(same_site) = &cookie.attributes.same_site {
        parts.push(format!("SameSite={same_site}"));
    }
    if cookie.attributes.partitioned == Some(true) {
        parts.push("Partitioned".to_owned());
    }
    parts.join("; ")
}
