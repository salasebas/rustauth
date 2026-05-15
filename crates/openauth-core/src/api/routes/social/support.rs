use http::{header, HeaderValue, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::api::{
    json_response, serialize_cookie, ApiRequest, ApiResponse, BodyField, BodySchema,
    JsonSchemaType, PathParams,
};
use crate::auth::oauth::OAuthBaseUrlOverride;
use crate::auth::oauth::OAuthUserInfoError;
use crate::error::OpenAuthError;

#[derive(Debug, Serialize)]
struct SocialRedirectBody {
    url: String,
    redirect: bool,
}

#[derive(Debug, Deserialize)]
pub(super) struct SocialSignInBody {
    pub provider: String,
    #[serde(default, alias = "callbackURL")]
    pub callback_url: Option<String>,
    #[serde(default, alias = "errorCallbackURL")]
    pub error_callback_url: Option<String>,
    #[serde(default, alias = "newUserCallbackURL")]
    pub new_user_callback_url: Option<String>,
    #[serde(default, alias = "disableRedirect")]
    pub disable_redirect: bool,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default, alias = "loginHint")]
    pub login_hint: Option<String>,
    #[serde(default, alias = "requestSignUp")]
    pub request_sign_up: bool,
    #[serde(default, alias = "additionalData")]
    pub additional_data: Option<Value>,
    #[serde(default, alias = "idToken")]
    pub id_token: Option<IdTokenBody>,
}

#[derive(Debug, Deserialize)]
pub(super) struct LinkSocialBody {
    pub provider: String,
    #[serde(default, alias = "callbackURL")]
    pub callback_url: Option<String>,
    #[serde(default, alias = "errorCallbackURL")]
    pub error_callback_url: Option<String>,
    #[serde(default, alias = "disableRedirect")]
    pub disable_redirect: bool,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default, alias = "requestSignUp")]
    pub request_sign_up: bool,
    #[serde(default, alias = "additionalData")]
    pub additional_data: Option<Value>,
    #[serde(default, alias = "idToken")]
    pub id_token: Option<IdTokenBody>,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct IdTokenBody {
    pub token: String,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default, alias = "accessToken")]
    pub access_token: Option<String>,
    #[serde(default, alias = "refreshToken")]
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
    pub user: crate::db::User,
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
) -> Result<&'a str, OpenAuthError> {
    request
        .extensions()
        .get::<PathParams>()
        .and_then(|params| params.get(name))
        .ok_or_else(|| OpenAuthError::Api(format!("missing path param `{name}`")))
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
        .unwrap_or(&context.base_url);
    format!("{}/callback/{provider_id}", base_url.trim_end_matches('/'))
}

pub(super) fn redirect_json_response(
    url: String,
    redirect: bool,
) -> Result<ApiResponse, OpenAuthError> {
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
            HeaderValue::from_str(&url).map_err(|error| OpenAuthError::Api(error.to_string()))?,
        );
    }
    Ok(response)
}

pub(super) fn redirect(
    location: &str,
    cookies: Vec<crate::cookies::Cookie>,
) -> Result<ApiResponse, OpenAuthError> {
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
    match error {
        OAuthUserInfoError::AccountNotLinked => "account_not_linked",
        OAuthUserInfoError::SignupDisabled => "signup_disabled",
        OAuthUserInfoError::UnableToCreateUser => "unable_to_create_user",
        OAuthUserInfoError::UnableToCreateSession => "unable_to_create_session",
        OAuthUserInfoError::UnableToLinkAccount => "unable_to_link_account",
    }
    .to_owned()
}
