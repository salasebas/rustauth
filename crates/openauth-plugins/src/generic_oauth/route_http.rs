use http::{header, HeaderValue, StatusCode};
use openauth_core::api::{ApiResponse, BodyField, BodySchema, JsonSchemaType};
use openauth_core::cookies::Cookie;
use openauth_core::error::OpenAuthError;
use serde::Serialize;

pub(super) fn json_response<T: Serialize>(
    status: StatusCode,
    value: &T,
) -> Result<ApiResponse, OpenAuthError> {
    http::Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(serde_json::to_vec(value).map_err(|error| OpenAuthError::Api(error.to_string()))?)
        .map_err(|error| OpenAuthError::Api(error.to_string()))
}

pub(super) fn api_error(
    status: StatusCode,
    code: &str,
    message: &str,
) -> Result<ApiResponse, OpenAuthError> {
    json_response(
        status,
        &serde_json::json!({ "code": code, "message": message }),
    )
}

pub(super) fn redirect(location: &str, cookies: Vec<Cookie>) -> Result<ApiResponse, OpenAuthError> {
    let mut response = http::Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, location)
        .body(Vec::new())
        .map_err(|error| OpenAuthError::Api(error.to_string()))?;
    for cookie in cookies {
        response.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_str(&serialize_cookie(&cookie))
                .map_err(|error| OpenAuthError::Cookie(error.to_string()))?,
        );
    }
    Ok(response)
}

pub(super) fn redirect_with_error(
    location: &str,
    error: &str,
) -> Result<ApiResponse, OpenAuthError> {
    redirect_with_error_description(location, error, None)
}

pub(super) fn redirect_with_error_description(
    location: &str,
    error: &str,
    description: Option<&str>,
) -> Result<ApiResponse, OpenAuthError> {
    let separator = if location.contains('?') { '&' } else { '?' };
    let mut target = format!("{location}{separator}error={}", percent_encode(error));
    if let Some(description) = description {
        target.push_str("&error_description=");
        target.push_str(&percent_encode(description));
    }
    redirect(&target, Vec::new())
}

pub(super) fn sign_in_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("providerId", JsonSchemaType::String),
        BodyField::optional("callbackURL", JsonSchemaType::String),
        BodyField::optional("errorCallbackURL", JsonSchemaType::String),
        BodyField::optional("newUserCallbackURL", JsonSchemaType::String),
        BodyField::optional("disableRedirect", JsonSchemaType::Boolean),
        BodyField::optional("scopes", JsonSchemaType::Array),
        BodyField::optional("requestSignUp", JsonSchemaType::Boolean),
        BodyField::optional("additionalData", JsonSchemaType::Object),
    ])
}

pub(super) fn link_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("providerId", JsonSchemaType::String),
        BodyField::new("callbackURL", JsonSchemaType::String),
        BodyField::optional("errorCallbackURL", JsonSchemaType::String),
        BodyField::optional("scopes", JsonSchemaType::Array),
    ])
}

fn serialize_cookie(cookie: &Cookie) -> String {
    let mut value = format!("{}={}", cookie.name, cookie.value);
    if let Some(path) = &cookie.attributes.path {
        value.push_str(&format!("; Path={path}"));
    }
    if let Some(max_age) = cookie.attributes.max_age {
        value.push_str(&format!("; Max-Age={max_age}"));
    }
    if cookie.attributes.http_only.unwrap_or(false) {
        value.push_str("; HttpOnly");
    }
    if cookie.attributes.secure.unwrap_or(false) {
        value.push_str("; Secure");
    }
    if let Some(same_site) = &cookie.attributes.same_site {
        value.push_str(&format!("; SameSite={same_site}"));
    }
    value
}

fn percent_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}
