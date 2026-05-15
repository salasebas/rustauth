use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use http::{header, HeaderValue, Response, StatusCode};
use openauth_core::api::{ApiRequest, ApiResponse};
use openauth_core::context::AuthContext;
use openauth_core::cookies::{
    parse_cookies, sign_cookie_value, verify_cookie_value, CookieOptions,
};
use openauth_core::crypto::random::generate_random_string;
use openauth_core::db::{DbAdapter, DbRecord, DbValue, FindOne, Session, User, Where};
use openauth_core::error::OpenAuthError;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

pub const OAUTH_CLIENT_MODEL: &str = "oauthApplication";
pub const OAUTH_TOKEN_MODEL: &str = "oauthAccessToken";
pub const LOGIN_PROMPT_COOKIE: &str = "oidc_login_prompt";
pub const CONSENT_PROMPT_COOKIE: &str = "oidc_consent_prompt";

pub fn json_response<T: Serialize>(
    status: StatusCode,
    value: &T,
) -> Result<ApiResponse, OpenAuthError> {
    let body = serde_json::to_vec(value).map_err(|error| OpenAuthError::Api(error.to_string()))?;
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .map_err(|error| OpenAuthError::Api(error.to_string()))
}

pub fn oauth_error(
    status: StatusCode,
    error: &str,
    description: &str,
) -> Result<ApiResponse, OpenAuthError> {
    json_response(
        status,
        &json!({
            "error": error,
            "error_description": description,
        }),
    )
}

pub fn redirect(location: &str) -> Result<ApiResponse, OpenAuthError> {
    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, location)
        .body(Vec::new())
        .map_err(|error| OpenAuthError::Api(error.to_string()))
}

pub fn redirect_error_url(url: &str, error: &str, description: &str) -> String {
    let Ok(mut parsed) = url::Url::parse(url) else {
        let separator = if url.contains('?') { '&' } else { '?' };
        return format!(
            "{url}{separator}error={}&error_description={}",
            percent_encode(error),
            percent_encode(description)
        );
    };
    parsed
        .query_pairs_mut()
        .append_pair("error", error)
        .append_pair("error_description", description);
    parsed.to_string()
}

pub fn with_cors(mut response: ApiResponse) -> Result<ApiResponse, OpenAuthError> {
    let headers = response.headers_mut();
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("Content-Type, Authorization"),
    );
    headers.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static("86400"),
    );
    Ok(response)
}

pub fn adapter(context: &AuthContext) -> Result<std::sync::Arc<dyn DbAdapter>, OpenAuthError> {
    context.adapter().ok_or_else(|| {
        OpenAuthError::InvalidConfig("mcp plugin requires a database adapter".into())
    })
}

pub async fn current_session(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    request: &ApiRequest,
) -> Result<Option<Session>, OpenAuthError> {
    let cookie_header = request
        .headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let Some(cookie) = session_cookie_value(context, cookie_header) else {
        return Ok(None);
    };
    let Some(token) = verify_cookie_value(&cookie, &context.secret)? else {
        return Ok(None);
    };
    let Some(record) = adapter
        .find_one(FindOne::new("session").where_clause(Where::new("token", DbValue::String(token))))
        .await?
    else {
        return Ok(None);
    };
    let session = session_from_record(&record)?;
    if session.expires_at <= OffsetDateTime::now_utc() {
        return Ok(None);
    }
    Ok(Some(session))
}

pub fn session_cookie_value(context: &AuthContext, cookie_header: &str) -> Option<String> {
    let cookies = parse_cookies(cookie_header);
    cookies
        .get(&context.auth_cookies.session_token.name)
        .cloned()
        .or_else(|| {
            cookies
                .get(openauth_core::cookies::strip_secure_cookie_prefix(
                    &context.auth_cookies.session_token.name,
                ))
                .cloned()
        })
}

pub fn request_cookie(request: &ApiRequest, name: &str) -> Option<String> {
    let cookie_header = request.headers().get(header::COOKIE)?.to_str().ok()?;
    parse_cookies(cookie_header).get(name).cloned()
}

pub fn signed_cookie_value(value: &str, secret: &str) -> Result<String, OpenAuthError> {
    sign_cookie_value(value, secret)
}

pub fn verify_signed_cookie(value: &str, secret: &str) -> Result<Option<String>, OpenAuthError> {
    verify_cookie_value(value, secret)
}

pub fn append_cookie(
    response: &mut ApiResponse,
    name: &str,
    value: &str,
    attributes: CookieOptions,
) -> Result<(), OpenAuthError> {
    let mut parts = vec![format!("{name}={value}")];
    if let Some(max_age) = attributes.max_age {
        parts.push(format!("Max-Age={max_age}"));
    }
    if let Some(path) = attributes.path {
        parts.push(format!("Path={path}"));
    }
    if attributes.secure == Some(true) {
        parts.push("Secure".to_owned());
    }
    if attributes.http_only == Some(true) {
        parts.push("HttpOnly".to_owned());
    }
    if let Some(same_site) = attributes.same_site {
        parts.push(format!("SameSite={same_site}"));
    }
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&parts.join("; "))
            .map_err(|error| OpenAuthError::Cookie(error.to_string()))?,
    );
    Ok(())
}

pub fn append_signed_prompt_cookie(
    response: &mut ApiResponse,
    name: &str,
    value: &str,
    secret: &str,
) -> Result<(), OpenAuthError> {
    let value = signed_cookie_value(value, secret)?;
    append_cookie(
        response,
        name,
        &value,
        CookieOptions {
            max_age: Some(600),
            path: Some("/".to_owned()),
            same_site: Some("lax".to_owned()),
            http_only: Some(true),
            ..CookieOptions::default()
        },
    )
}

pub fn expire_prompt_cookie(response: &mut ApiResponse, name: &str) -> Result<(), OpenAuthError> {
    append_cookie(
        response,
        name,
        "",
        CookieOptions {
            max_age: Some(0),
            path: Some("/".to_owned()),
            same_site: Some("lax".to_owned()),
            http_only: Some(true),
            ..CookieOptions::default()
        },
    )
}

pub async fn find_user(
    adapter: &dyn DbAdapter,
    user_id: &str,
) -> Result<Option<User>, OpenAuthError> {
    adapter
        .find_one(
            FindOne::new("user")
                .where_clause(Where::new("id", DbValue::String(user_id.to_owned()))),
        )
        .await?
        .map(|record| user_from_record(&record))
        .transpose()
}

pub async fn find_client(
    adapter: &dyn DbAdapter,
    client_id: &str,
) -> Result<Option<OAuthClient>, OpenAuthError> {
    adapter
        .find_one(FindOne::new(OAUTH_CLIENT_MODEL).where_clause(Where::new(
            "clientId",
            DbValue::String(client_id.to_owned()),
        )))
        .await?
        .map(|record| client_from_record(&record))
        .transpose()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthClient {
    pub name: Option<String>,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_urls: Vec<String>,
    pub client_type: String,
    pub authentication_scheme: String,
    pub disabled: bool,
}

pub fn client_from_record(record: &DbRecord) -> Result<OAuthClient, OpenAuthError> {
    Ok(OAuthClient {
        name: optional_string(record, "name")?,
        client_id: required_string(record, "clientId")?,
        client_secret: optional_string(record, "clientSecret")?,
        redirect_urls: required_string(record, "redirectUrls")?
            .split(',')
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect(),
        client_type: required_string(record, "type")?,
        authentication_scheme: optional_string(record, "authenticationScheme")?
            .unwrap_or_else(|| "client_secret_basic".to_owned()),
        disabled: optional_bool(record, "disabled")?.unwrap_or(false),
    })
}

pub fn record_to_json(record: &DbRecord) -> Result<Value, OpenAuthError> {
    let mut object = serde_json::Map::new();
    for (key, value) in record {
        object.insert(key.clone(), db_value_to_json(value));
    }
    Ok(Value::Object(object))
}

pub fn required_string(record: &DbRecord, field: &str) -> Result<String, OpenAuthError> {
    optional_string(record, field)?.ok_or_else(|| {
        OpenAuthError::Adapter(format!("mcp record is missing string field `{field}`"))
    })
}

pub fn optional_string(record: &DbRecord, field: &str) -> Result<Option<String>, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(Some(value.clone())),
        Some(DbValue::Null) | None => Ok(None),
        _ => Err(OpenAuthError::Adapter(format!(
            "mcp record field `{field}` must be a string"
        ))),
    }
}

pub fn optional_bool(record: &DbRecord, field: &str) -> Result<Option<bool>, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Boolean(value)) => Ok(Some(*value)),
        Some(DbValue::Null) | None => Ok(None),
        _ => Err(OpenAuthError::Adapter(format!(
            "mcp record field `{field}` must be a boolean"
        ))),
    }
}

pub fn optional_timestamp(
    record: &DbRecord,
    field: &str,
) -> Result<Option<OffsetDateTime>, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Timestamp(value)) => Ok(Some(*value)),
        Some(DbValue::Null) | None => Ok(None),
        _ => Err(OpenAuthError::Adapter(format!(
            "mcp record field `{field}` must be a timestamp"
        ))),
    }
}

pub fn required_timestamp(record: &DbRecord, field: &str) -> Result<OffsetDateTime, OpenAuthError> {
    optional_timestamp(record, field)?.ok_or_else(|| {
        OpenAuthError::Adapter(format!("mcp record is missing timestamp field `{field}`"))
    })
}

pub fn pkce_s256(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

pub fn random_token() -> String {
    generate_random_string(32)
}

pub fn string_field(value: &Value, field: &str) -> Option<String> {
    value.get(field).and_then(Value::as_str).map(str::to_owned)
}

fn percent_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn session_from_record(record: &DbRecord) -> Result<Session, OpenAuthError> {
    Ok(Session {
        id: required_string(record, "id")?,
        user_id: required_string(record, "user_id")?,
        expires_at: required_timestamp(record, "expires_at")?,
        token: required_string(record, "token")?,
        ip_address: optional_string(record, "ip_address")?,
        user_agent: optional_string(record, "user_agent")?,
        created_at: required_timestamp(record, "created_at")?,
        updated_at: required_timestamp(record, "updated_at")?,
    })
}

fn user_from_record(record: &DbRecord) -> Result<User, OpenAuthError> {
    Ok(User {
        id: required_string(record, "id")?,
        name: required_string(record, "name")?,
        email: required_string(record, "email")?,
        email_verified: optional_bool(record, "email_verified")?.unwrap_or(false),
        image: optional_string(record, "image")?,
        username: optional_string(record, "username")?,
        display_username: optional_string(record, "display_username")?,
        created_at: required_timestamp(record, "created_at")?,
        updated_at: required_timestamp(record, "updated_at")?,
    })
}

fn db_value_to_json(value: &DbValue) -> Value {
    match value {
        DbValue::String(value) => Value::String(value.clone()),
        DbValue::Number(value) => json!(value),
        DbValue::Boolean(value) => Value::Bool(*value),
        DbValue::Timestamp(value) => Value::String(value.to_string()),
        DbValue::Json(value) => value.clone(),
        DbValue::StringArray(values) => json!(values),
        DbValue::NumberArray(values) => json!(values),
        DbValue::Record(record) => record_to_json(record).unwrap_or(Value::Null),
        DbValue::RecordArray(records) => Value::Array(
            records
                .iter()
                .map(|record| record_to_json(record).unwrap_or(Value::Null))
                .collect(),
        ),
        DbValue::Null => Value::Null,
    }
}
