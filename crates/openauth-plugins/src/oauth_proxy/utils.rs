use http::{header, HeaderValue};
use openauth_core::api::{
    parse_request_body, redirect_with_error_response, ApiRequest, ApiResponse,
};
use openauth_core::context::{AuthContext, SecretMaterial};
use openauth_core::crypto::{symmetric_decrypt, symmetric_encrypt};
use openauth_core::error::OpenAuthError;
use serde_json::{Map, Value};
use url::Url;

use super::options::OAuthProxyOptions;

pub(crate) fn strip_trailing_slash(value: &str) -> &str {
    value.trim_end_matches('/')
}

pub(crate) fn current_url(
    context: &AuthContext,
    request: &ApiRequest,
    options: &OAuthProxyOptions,
) -> Option<Url> {
    if let Some(value) = &options.current_url {
        return Url::parse(value).ok();
    }
    if let Some(value) = request_origin(request) {
        return Url::parse(&value).ok();
    }
    if let Some(value) = vendor_current_url() {
        return Url::parse(&value).ok();
    }
    (!context.base_url.is_empty())
        .then(|| Url::parse(&context.base_url).ok())
        .flatten()
}

pub(crate) fn production_url(context: &AuthContext, options: &OAuthProxyOptions) -> Option<Url> {
    let value = options
        .production_url
        .clone()
        .or_else(|| std::env::var("OPENAUTH_URL").ok())
        .or_else(|| (!context.base_url.is_empty()).then(|| context.base_url.clone()))?;
    Url::parse(&value).ok()
}

pub(crate) fn should_skip_proxy(
    context: &AuthContext,
    request: &ApiRequest,
    options: &OAuthProxyOptions,
) -> bool {
    if request.headers().contains_key("x-skip-oauth-proxy") {
        return true;
    }
    let Some(current) = current_url(context, request, options) else {
        return false;
    };
    let Some(production) = production_url(context, options) else {
        return false;
    };
    current.origin() == production.origin()
}

pub(crate) fn proxy_callback_url(
    context: &AuthContext,
    request: &ApiRequest,
    options: &OAuthProxyOptions,
    original_callback_url: &str,
) -> Option<String> {
    let current = current_url(context, request, options)?;
    Some(format!(
        "{}{}/oauth-proxy-callback?callbackURL={}",
        strip_trailing_slash(current.origin().ascii_serialization().as_str()),
        context.base_path,
        percent_encode(original_callback_url)
    ))
}

pub(crate) fn production_base_url(context: &AuthContext, options: &OAuthProxyOptions) -> String {
    production_url(context, options)
        .map(|url| {
            format!(
                "{}{}",
                strip_trailing_slash(url.origin().ascii_serialization().as_str()),
                context.base_path
            )
        })
        .unwrap_or_else(|| context.base_url.clone())
}

pub(crate) fn encrypt(
    context: &AuthContext,
    options: &OAuthProxyOptions,
    data: &str,
) -> Result<String, OpenAuthError> {
    if let Some(secret) = &options.secret {
        return symmetric_encrypt(secret.as_str(), data);
    }
    match &context.secret_config {
        SecretMaterial::Single(secret) => symmetric_encrypt(secret.as_str(), data),
        SecretMaterial::Rotating(config) => symmetric_encrypt(config, data),
    }
}

pub(crate) fn decrypt(
    context: &AuthContext,
    options: &OAuthProxyOptions,
    data: &str,
) -> Result<String, OpenAuthError> {
    if let Some(secret) = &options.secret {
        return symmetric_decrypt(secret.as_str(), data);
    }
    match &context.secret_config {
        SecretMaterial::Single(secret) => symmetric_decrypt(secret.as_str(), data),
        SecretMaterial::Rotating(config) => symmetric_decrypt(config, data),
    }
}

pub(crate) fn query_param(request: &ApiRequest, name: &str) -> Option<String> {
    request.uri().query().and_then(|query| {
        query.split('&').find_map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (key == name).then(|| percent_decode(value))
        })
    })
}

pub(crate) fn query_or_body_param(request: &ApiRequest, name: &str) -> Option<String> {
    query_param(request, name).or_else(|| {
        if request.body().is_empty() {
            return None;
        }
        parse_request_body::<Value>(request)
            .ok()
            .and_then(|body| body_string(&body, name))
    })
}

pub(crate) fn rewrite_callback_body(
    request: &mut ApiRequest,
    callback_url: &str,
) -> Result<(), OpenAuthError> {
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("application/json");
    let mut body = if request.body().is_empty() {
        Value::Object(Map::new())
    } else {
        parse_request_body::<Value>(request)?
    };
    let object = body
        .as_object_mut()
        .ok_or_else(|| OpenAuthError::Api("OAuth sign-in body must be an object".to_owned()))?;
    object.insert(
        "callbackURL".to_owned(),
        Value::String(callback_url.to_owned()),
    );
    if content_type.starts_with("application/x-www-form-urlencoded") {
        let mut encoded = url::form_urlencoded::Serializer::new(String::new());
        for (key, value) in object {
            encoded.append_pair(key, &body_string_value(value));
        }
        *request.body_mut() = encoded.finish().into_bytes();
    } else {
        *request.body_mut() =
            serde_json::to_vec(&body).map_err(|error| OpenAuthError::Api(error.to_string()))?;
        request.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
    }
    Ok(())
}

pub(crate) fn redirect_error(error_url: &str, error: &str) -> Result<ApiResponse, OpenAuthError> {
    redirect_with_error_response(error_url, error)
}

pub(crate) fn is_trusted_callback_url(
    context: &AuthContext,
    request: &ApiRequest,
    callback_url: &str,
) -> Result<bool, OpenAuthError> {
    if callback_url.starts_with('/') && !callback_url.starts_with("//") {
        return Ok(true);
    }
    let Ok(url) = Url::parse(callback_url) else {
        return Ok(false);
    };
    context.is_trusted_origin_for_request(url.as_str(), None, Some(request))
}

pub(crate) fn percent_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn request_origin(request: &ApiRequest) -> Option<String> {
    let uri = request.uri();
    let scheme = uri.scheme_str()?;
    let authority = uri.authority()?;
    Some(format!("{scheme}://{authority}"))
}

fn vendor_current_url() -> Option<String> {
    [
        "VERCEL_URL",
        "NETLIFY_URL",
        "RENDER_URL",
        "AWS_LAMBDA_FUNCTION_URL",
        "AWS_LAMBDA_FUNCTION_NAME",
        "AWS_FUNCTION_URL",
        "GOOGLE_CLOUD_FUNCTION_URL",
        "GOOGLE_CLOUD_FUNCTION_NAME",
        "AZURE_FUNCTION_URL",
        "AZURE_FUNCTION_NAME",
        "FUNCTIONS_CUSTOMHANDLER_PORT",
    ]
    .into_iter()
    .find_map(|key| std::env::var(key).ok())
    .map(|value| {
        if value.starts_with("http://") || value.starts_with("https://") {
            value
        } else {
            format!("https://{value}")
        }
    })
}

fn body_string(body: &Value, key: &str) -> Option<String> {
    body.get(key).and_then(|value| match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    })
}

fn body_string_value(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Number(value) => value.to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn percent_decode(value: &str) -> String {
    url::form_urlencoded::parse(format!("x={value}").as_bytes())
        .next()
        .map(|(_, value)| value.into_owned())
        .unwrap_or_default()
}
