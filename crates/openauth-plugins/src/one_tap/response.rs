use http::{header, HeaderValue, StatusCode};
use openauth_core::api::{ApiErrorResponse, ApiResponse};
use openauth_core::context::AuthContext;
use openauth_core::cookies::{
    set_cookie_cache, set_session_cookie, Cookie, CookieCachePayload, CookieOptions,
    SessionCookieOptions,
};
use openauth_core::db::{DbAdapter, DbRecord, DbValue, FindOne, Session, User, Where};
use openauth_core::error::OpenAuthError;
use serde::Serialize;
use serde_json::Value;
use time::OffsetDateTime;

#[derive(Debug, Serialize)]
pub(super) struct OneTapSessionBody {
    pub token: String,
    pub user: Value,
}

pub(super) async fn session_response(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    session: Session,
    user: User,
    extra_cookies: Vec<Cookie>,
) -> Result<ApiResponse, OpenAuthError> {
    let mut cookies = session_cookies(context, &session, &user)?;
    let user = user_response_value(adapter, context, &user).await?;
    cookies.extend(extra_cookies);
    json_response(
        StatusCode::OK,
        &OneTapSessionBody {
            token: session.token,
            user,
        },
        cookies,
    )
}

pub(super) fn error_response(
    status: StatusCode,
    code: impl Into<String>,
    message: impl Into<String>,
) -> Result<ApiResponse, OpenAuthError> {
    json_response(
        status,
        &ApiErrorResponse {
            code: code.into(),
            message: message.into(),
            original_message: None,
        },
        Vec::new(),
    )
}

fn json_response<T>(
    status: StatusCode,
    body: &T,
    cookies: Vec<Cookie>,
) -> Result<ApiResponse, OpenAuthError>
where
    T: Serialize,
{
    let body = serde_json::to_vec(body).map_err(|error| OpenAuthError::Api(error.to_string()))?;
    let mut response = http::Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
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

fn session_cookies(
    context: &AuthContext,
    session: &Session,
    user: &User,
) -> Result<Vec<Cookie>, OpenAuthError> {
    let mut cookies = set_session_cookie(
        &context.auth_cookies,
        &context.secret,
        &session.token,
        SessionCookieOptions {
            dont_remember: false,
            overrides: CookieOptions::default(),
        },
    )?;
    if context.options.session.cookie_cache.enabled {
        let max_age = context
            .options
            .session
            .cookie_cache
            .max_age
            .unwrap_or(60 * 5);
        cookies.extend(set_cookie_cache(
            &context.auth_cookies,
            &context.secret,
            &CookieCachePayload {
                session: session.clone(),
                user: user.clone(),
                updated_at: OffsetDateTime::now_utc().unix_timestamp(),
                version: context
                    .options
                    .session
                    .cookie_cache
                    .version
                    .clone()
                    .unwrap_or_else(|| "1".to_owned()),
            },
            context.options.session.cookie_cache.strategy,
            max_age,
        )?);
    }
    Ok(cookies)
}

async fn user_response_value(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    user: &User,
) -> Result<Value, OpenAuthError> {
    if context.options.user.additional_fields.is_empty() {
        return serde_json::to_value(user).map_err(|error| OpenAuthError::Api(error.to_string()));
    }
    let record = adapter
        .find_one(
            FindOne::new("user").where_clause(Where::new("id", DbValue::String(user.id.clone()))),
        )
        .await?;
    let mut value =
        serde_json::to_value(user).map_err(|error| OpenAuthError::Api(error.to_string()))?;
    let Some(object) = value.as_object_mut() else {
        return Err(OpenAuthError::Api(
            "could not serialize user as an object".to_owned(),
        ));
    };
    if let Some(record) = record {
        insert_returned_user_fields(object, context, &record)?;
    }
    Ok(value)
}

fn insert_returned_user_fields(
    object: &mut serde_json::Map<String, Value>,
    context: &AuthContext,
    record: &DbRecord,
) -> Result<(), OpenAuthError> {
    for (name, field) in &context.options.user.additional_fields {
        if !field.returned {
            continue;
        }
        let value = record
            .get(name)
            .or(field.default_value.as_ref())
            .unwrap_or(&DbValue::Null);
        object.insert(name.clone(), db_value_to_json(value)?);
    }
    Ok(())
}

fn db_value_to_json(value: &DbValue) -> Result<Value, OpenAuthError> {
    match value {
        DbValue::String(value) => Ok(Value::String(value.clone())),
        DbValue::Number(value) => Ok(Value::Number((*value).into())),
        DbValue::Boolean(value) => Ok(Value::Bool(*value)),
        DbValue::Timestamp(value) => {
            serde_json::to_value(value).map_err(|error| OpenAuthError::Api(error.to_string()))
        }
        DbValue::Json(value) => Ok(value.clone()),
        DbValue::StringArray(values) => Ok(Value::Array(
            values.iter().cloned().map(Value::String).collect(),
        )),
        DbValue::NumberArray(values) => Ok(Value::Array(
            values
                .iter()
                .map(|value| Value::Number((*value).into()))
                .collect(),
        )),
        DbValue::Record(record) => db_record_to_json(record),
        DbValue::RecordArray(records) => records
            .iter()
            .map(db_record_to_json)
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        DbValue::Null => Ok(Value::Null),
    }
}

fn db_record_to_json(record: &DbRecord) -> Result<Value, OpenAuthError> {
    record
        .iter()
        .map(|(field, value)| db_value_to_json(value).map(|value| (field.clone(), value)))
        .collect::<Result<serde_json::Map<_, _>, _>>()
        .map(Value::Object)
}

fn serialize_cookie(cookie: &Cookie) -> String {
    let mut value = format!("{}={}", cookie.name, cookie.value);
    if let Some(max_age) = cookie.attributes.max_age {
        value.push_str(&format!("; Max-Age={max_age}"));
    }
    if let Some(domain) = &cookie.attributes.domain {
        value.push_str(&format!("; Domain={domain}"));
    }
    if let Some(path) = &cookie.attributes.path {
        value.push_str(&format!("; Path={path}"));
    }
    if cookie.attributes.secure.unwrap_or(false) {
        value.push_str("; Secure");
    }
    if cookie.attributes.http_only.unwrap_or(false) {
        value.push_str("; HttpOnly");
    }
    if let Some(same_site) = &cookie.attributes.same_site {
        value.push_str("; SameSite=");
        value.push_str(same_site);
    }
    if cookie.attributes.partitioned.unwrap_or(false) {
        value.push_str("; Partitioned");
    }
    value
}
