use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use hmac::{Hmac, Mac};
use http::{header, Response, StatusCode};
use openauth_core::api::{parse_request_body, ApiRequest, ApiResponse};
use openauth_core::auth::session::{GetSessionInput, SessionAuth};
use openauth_core::context::AuthContext;
use openauth_core::cookies::Cookie;
use openauth_core::crypto::buffer::constant_time_equal;
use openauth_core::db::{
    Create, DbAdapter, DbRecord, DbValue, Delete, FindMany, FindOne, Session, Update, Where,
};
use openauth_core::error::OpenAuthError;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::error::{OAuthErrorBody, OAuthProviderError};

type HmacSha256 = Hmac<Sha256>;

pub(crate) fn json_response<T: Serialize>(
    status: StatusCode,
    body: &T,
) -> Result<ApiResponse, OpenAuthError> {
    let body = serde_json::to_vec(body).map_err(|error| OpenAuthError::Api(error.to_string()))?;
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .map_err(|error| OpenAuthError::Api(error.to_string()))
}

pub(crate) fn no_content() -> Result<ApiResponse, OpenAuthError> {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(b"null".to_vec())
        .map_err(|error| OpenAuthError::Api(error.to_string()))
}

pub(crate) fn error_response(error: OAuthProviderError) -> Result<ApiResponse, OpenAuthError> {
    json_response(
        error.status,
        &OAuthErrorBody {
            error: &error.error,
            error_description: &error.error_description,
        },
    )
}

pub(crate) fn redirect_response(uri: &str) -> Result<ApiResponse, OpenAuthError> {
    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, uri)
        .body(Vec::new())
        .map_err(|error| OpenAuthError::Api(error.to_string()))
}

pub(crate) fn parse_body<T: DeserializeOwned>(request: &ApiRequest) -> Result<T, OpenAuthError> {
    parse_request_body(request)
}

pub(crate) fn parse_query(request: &ApiRequest) -> Vec<(String, String)> {
    request
        .uri()
        .query()
        .map(|query| {
            url::form_urlencoded::parse(query.as_bytes())
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn query_param(request: &ApiRequest, name: &str) -> Option<String> {
    parse_query(request)
        .into_iter()
        .find_map(|(key, value)| (key == name).then_some(value))
}

pub(crate) fn bearer_token(request: &ApiRequest) -> Option<String> {
    request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .and_then(|value| value.strip_prefix("Bearer ").or(Some(value)))
        .map(str::to_owned)
        .filter(|value| !value.is_empty())
}

pub(crate) fn basic_credentials(
    request: &ApiRequest,
) -> Result<Option<(String, String)>, OpenAuthError> {
    let Some(value) = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return Ok(None);
    };
    let Some(encoded) = value.strip_prefix("Basic ") else {
        return Ok(None);
    };
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|error| OpenAuthError::Api(error.to_string()))?;
    let decoded =
        String::from_utf8(decoded).map_err(|error| OpenAuthError::Api(error.to_string()))?;
    let Some((client_id, client_secret)) = decoded.split_once(':') else {
        return Err(
            OAuthProviderError::invalid_client("invalid authorization header format").into(),
        );
    };
    Ok(Some((client_id.to_owned(), client_secret.to_owned())))
}

pub(crate) async fn current_session(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    request: &ApiRequest,
) -> Result<Option<(Session, openauth_core::db::User, Vec<Cookie>)>, OpenAuthError> {
    let cookie_header = request
        .headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let Some(result) = SessionAuth::new(adapter, context)
        .get_session(GetSessionInput::new(cookie_header))
        .await?
    else {
        return Ok(None);
    };
    match (result.session, result.user) {
        (Some(session), Some(user)) => Ok(Some((session, user, result.cookies))),
        _ => Ok(None),
    }
}

pub(crate) fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

pub(crate) fn random_string(length: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

pub(crate) fn random_id(prefix: &str) -> String {
    format!("{prefix}_{}", random_string(24))
}

pub(crate) fn sha256_base64url(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
}

pub(crate) fn hmac_sha256_base64url(value: &str, secret: &str) -> Result<String, OpenAuthError> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|error| OpenAuthError::Crypto(error.to_string()))?;
    mac.update(value.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

pub(crate) fn verify_hash(value: &str, hash: &str) -> bool {
    constant_time_equal(sha256_base64url(value), hash)
}

pub(crate) fn split_scope(scope: Option<&str>) -> Vec<String> {
    scope
        .unwrap_or_default()
        .split_whitespace()
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

pub(crate) fn join_scope(scopes: &[String]) -> String {
    scopes.join(" ")
}

pub(crate) fn validate_url(value: &str) -> bool {
    url::Url::parse(value).is_ok()
}

pub(crate) fn is_loopback_redirect_match(registered: &str, requested: &str) -> bool {
    if registered == requested {
        return true;
    }
    let (Ok(registered), Ok(requested)) = (url::Url::parse(registered), url::Url::parse(requested))
    else {
        return false;
    };
    registered.scheme() == requested.scheme()
        && registered.path() == requested.path()
        && registered.query() == requested.query()
        && registered.host_str() == requested.host_str()
        && is_loopback_host(registered.host_str())
        && is_loopback_host(requested.host_str())
}

fn is_loopback_host(host: Option<&str>) -> bool {
    matches!(host, Some("localhost" | "127.0.0.1" | "::1"))
}

pub(crate) fn create_query(model: &str, data: DbRecord) -> Create {
    data.into_iter()
        .fold(Create::new(model), |query, (field, value)| {
            query.data(field, value)
        })
}

pub(crate) fn find_by_string(model: &str, field: &str, value: &str) -> FindOne {
    FindOne::new(model).where_clause(Where::new(field, DbValue::String(value.to_owned())))
}

pub(crate) fn find_many_by_string(model: &str, field: &str, value: &str) -> FindMany {
    FindMany::new(model).where_clause(Where::new(field, DbValue::String(value.to_owned())))
}

pub(crate) fn update_by_string(model: &str, field: &str, value: &str, data: DbRecord) -> Update {
    data.into_iter().fold(
        Update::new(model).where_clause(Where::new(field, DbValue::String(value.to_owned()))),
        |query, (field, value)| query.data(field, value),
    )
}

pub(crate) fn delete_by_string(model: &str, field: &str, value: &str) -> Delete {
    Delete::new(model).where_clause(Where::new(field, DbValue::String(value.to_owned())))
}

pub(crate) fn string(record: &DbRecord, field: &str) -> Option<String> {
    match record.get(field) {
        Some(DbValue::String(value)) => Some(value.clone()),
        _ => None,
    }
}

pub(crate) fn bool_value(record: &DbRecord, field: &str) -> Option<bool> {
    match record.get(field) {
        Some(DbValue::Boolean(value)) => Some(*value),
        _ => None,
    }
}

pub(crate) fn string_array(record: &DbRecord, field: &str) -> Option<Vec<String>> {
    match record.get(field) {
        Some(DbValue::StringArray(value)) => Some(value.clone()),
        Some(DbValue::String(value)) => Some(split_scope(Some(value))),
        _ => None,
    }
}

pub(crate) fn timestamp(record: &DbRecord, field: &str) -> Option<OffsetDateTime> {
    match record.get(field) {
        Some(DbValue::Timestamp(value)) => Some(*value),
        _ => None,
    }
}

pub(crate) fn json_value(record: &DbRecord, field: &str) -> Option<Value> {
    match record.get(field) {
        Some(DbValue::Json(value)) => Some(value.clone()),
        Some(DbValue::String(value)) => serde_json::from_str(value).ok(),
        _ => None,
    }
}

pub(crate) fn user_from_record(record: DbRecord) -> Result<openauth_core::db::User, OpenAuthError> {
    Ok(openauth_core::db::User {
        id: required_string(&record, "id")?,
        name: required_string(&record, "name")?,
        email: required_string(&record, "email")?,
        email_verified: bool_value(&record, "email_verified").unwrap_or(false),
        image: string(&record, "image"),
        username: string(&record, "username"),
        display_username: string(&record, "display_username"),
        created_at: timestamp(&record, "created_at").ok_or_else(|| missing_field("created_at"))?,
        updated_at: timestamp(&record, "updated_at").ok_or_else(|| missing_field("updated_at"))?,
    })
}

fn required_string(record: &DbRecord, field: &str) -> Result<String, OpenAuthError> {
    string(record, field).ok_or_else(|| missing_field(field))
}

fn missing_field(field: &str) -> OpenAuthError {
    OpenAuthError::Api(format!("missing required field `{field}`"))
}
