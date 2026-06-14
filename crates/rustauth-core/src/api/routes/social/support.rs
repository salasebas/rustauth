use http::{header, HeaderValue, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::api::{
    json_response, request_base_url, serialize_cookie, ApiRequest, ApiResponse, BodyField,
    BodySchema, JsonSchemaType, PathParams,
};
use crate::auth::oauth::OAuthBaseUrlOverride;
use crate::auth::oauth::OAuthUserInfoError;
use crate::error::RustAuthError;

#[derive(Debug, Serialize)]
struct SocialRedirectBody {
    url: String,
    redirect: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SocialSignInBody {
    pub provider: String,
    #[serde(default, rename = "callbackURL", alias = "callbackUrl")]
    pub callback_url: Option<String>,
    #[serde(default, rename = "errorCallbackURL", alias = "errorCallbackUrl")]
    pub error_callback_url: Option<String>,
    #[serde(default, rename = "newUserCallbackURL", alias = "newUserCallbackUrl")]
    pub new_user_callback_url: Option<String>,
    #[serde(default)]
    pub disable_redirect: bool,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub login_hint: Option<String>,
    #[serde(default)]
    pub request_sign_up: bool,
    #[serde(default)]
    pub additional_data: Option<Value>,
    #[serde(default, rename = "idToken")]
    pub id_token: Option<IdTokenBody>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct LinkSocialBody {
    pub provider: String,
    #[serde(default, rename = "callbackURL", alias = "callbackUrl")]
    pub callback_url: Option<String>,
    #[serde(default, rename = "errorCallbackURL", alias = "errorCallbackUrl")]
    pub error_callback_url: Option<String>,
    #[serde(default)]
    pub disable_redirect: bool,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub request_sign_up: bool,
    #[serde(default)]
    pub additional_data: Option<Value>,
    #[serde(default, rename = "idToken")]
    pub id_token: Option<IdTokenBody>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct IdTokenBody {
    pub token: String,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub access_token: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub user: Option<Value>,
}

#[derive(Debug, Serialize)]
pub(super) struct SocialSessionBody {
    pub redirect: bool,
    pub token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub user: Value,
}

#[derive(Debug, Serialize)]
pub(super) struct LinkStatusBody {
    pub url: String,
    pub redirect: bool,
    pub status: bool,
}

pub(super) fn path_param<'a>(
    request: &'a ApiRequest,
    name: &str,
) -> Result<&'a str, RustAuthError> {
    request
        .extensions()
        .get::<PathParams>()
        .and_then(|params| params.get(name))
        .ok_or_else(|| RustAuthError::MissingPathParam {
            name: name.to_owned(),
        })
}

pub(super) fn redirect_uri(
    context: &crate::context::AuthContext,
    request: &ApiRequest,
    provider_id: &str,
) -> String {
    let base_url = request
        .extensions()
        .get::<OAuthBaseUrlOverride>()
        .map(|value| value.0.as_str())
        .unwrap_or_else(|| request_base_url(context, Some(request)));
    format!("{}/callback/{provider_id}", base_url.trim_end_matches('/'))
}

pub(super) fn redirect_json_response(
    url: String,
    redirect: bool,
    cookies: Vec<crate::cookies::Cookie>,
) -> Result<ApiResponse, RustAuthError> {
    let mut response = json_response(
        StatusCode::OK,
        &SocialRedirectBody {
            url: url.clone(),
            redirect,
        },
        Vec::new(),
    )?;
    if redirect {
        response.headers_mut().insert(
            header::LOCATION,
            HeaderValue::from_str(&url).map_err(|error| RustAuthError::Serialization {
                context: "building social redirect headers",
                message: error.to_string(),
            })?,
        );
    }
    for cookie in cookies {
        response.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_str(&serialize_cookie(&cookie))
                .map_err(|error| RustAuthError::Cookie(error.to_string()))?,
        );
    }
    Ok(response)
}

pub(super) fn redirect(
    location: &str,
    cookies: Vec<crate::cookies::Cookie>,
) -> Result<ApiResponse, RustAuthError> {
    let mut response = http::Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, location)
        .body(Vec::new())
        .map_err(|error| RustAuthError::Serialization {
            context: "building social redirect response",
            message: error.to_string(),
        })?;
    for cookie in cookies {
        response.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_str(&serialize_cookie(&cookie))
                .map_err(|error| RustAuthError::Cookie(error.to_string()))?,
        );
    }
    Ok(response)
}

pub(super) fn redirect_with_error(
    location: &str,
    error: &str,
) -> Result<ApiResponse, RustAuthError> {
    let separator = if location.contains('?') { '&' } else { '?' };
    redirect(
        &format!("{location}{separator}error={}", percent_encode(error)),
        Vec::new(),
    )
}

pub(super) fn body_string(body: &Value, key: &str) -> Option<String> {
    body.get(key).and_then(|value| match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    })
}

pub(super) fn percent_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

pub(super) fn social_sign_in_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("provider", JsonSchemaType::String),
        BodyField::optional("callbackURL", JsonSchemaType::String),
        BodyField::optional("errorCallbackURL", JsonSchemaType::String),
        BodyField::optional("newUserCallbackURL", JsonSchemaType::String),
        BodyField::optional("disableRedirect", JsonSchemaType::Boolean),
        BodyField::optional("scopes", JsonSchemaType::Array),
        BodyField::optional("loginHint", JsonSchemaType::String),
        BodyField::optional("requestSignUp", JsonSchemaType::Boolean),
        BodyField::optional("additionalData", JsonSchemaType::Object),
        BodyField::optional("idToken", JsonSchemaType::Object),
    ])
}

pub(super) fn link_social_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("provider", JsonSchemaType::String),
        BodyField::optional("callbackURL", JsonSchemaType::String),
        BodyField::optional("errorCallbackURL", JsonSchemaType::String),
        BodyField::optional("disableRedirect", JsonSchemaType::Boolean),
        BodyField::optional("scopes", JsonSchemaType::Array),
        BodyField::optional("requestSignUp", JsonSchemaType::Boolean),
        BodyField::optional("additionalData", JsonSchemaType::Object),
        BodyField::optional("idToken", JsonSchemaType::Object),
    ])
}

pub(super) fn oauth_user_info_error(error: OAuthUserInfoError) -> String {
    error.code_str().to_owned()
}
