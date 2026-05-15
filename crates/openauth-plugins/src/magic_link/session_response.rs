use openauth_core::context::request_state::{has_request_state, set_current_new_session};
use openauth_core::context::AuthContext;
use openauth_core::cookies::{
    set_cookie_cache, set_session_cookie, Cookie, CookieCachePayload, CookieOptions,
    SessionCookieOptions,
};
use openauth_core::db::{DbAdapter, DbRecord, DbValue, FindOne, Session, User, Where};
use openauth_core::error::OpenAuthError;
use openauth_core::session::CreateSessionInput;
use serde_json::{Map, Value};
use time::OffsetDateTime;

pub(crate) fn session_create_input(
    context: &AuthContext,
    request: &http::Request<Vec<u8>>,
    user_id: String,
    expires_at: OffsetDateTime,
) -> CreateSessionInput {
    let mut input = CreateSessionInput::new(user_id, expires_at)
        .additional_fields(additional_session_create_values(context));
    if let Some(ip_address) = request_ip(request) {
        input = input.ip_address(ip_address);
    }
    if let Some(user_agent) = request_user_agent(request) {
        input = input.user_agent(user_agent);
    }
    input
}

pub(crate) fn record_new_session(session: &Session, user: &User) -> Result<(), OpenAuthError> {
    if has_request_state() {
        set_current_new_session(session.clone(), user.clone())?;
    }
    Ok(())
}

pub(crate) fn session_cookies(
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
        let payload = CookieCachePayload {
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
        };
        cookies.extend(set_cookie_cache(
            &context.auth_cookies,
            &context.secret,
            &payload,
            context.options.session.cookie_cache.strategy,
            context
                .options
                .session
                .cookie_cache
                .max_age
                .unwrap_or(60 * 5),
        )?);
    }
    Ok(cookies)
}

pub(crate) async fn session_response_value(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    session: &Session,
) -> Result<Value, OpenAuthError> {
    let mut value =
        serde_json::to_value(session).map_err(|error| OpenAuthError::Api(error.to_string()))?;
    let Value::Object(object) = &mut value else {
        return Ok(value);
    };
    let record = adapter
        .find_one(
            FindOne::new("session")
                .where_clause(Where::new("token", DbValue::String(session.token.clone()))),
        )
        .await?;
    insert_returned_session_fields(
        object,
        &context.options.session.additional_fields,
        record.as_ref(),
    )?;
    Ok(value)
}

fn additional_session_create_values(context: &AuthContext) -> DbRecord {
    context
        .options
        .session
        .additional_fields
        .iter()
        .map(|(name, field)| {
            (
                name.clone(),
                field.default_value.clone().unwrap_or(DbValue::Null),
            )
        })
        .collect()
}

fn insert_returned_session_fields(
    object: &mut Map<String, Value>,
    fields: &std::collections::BTreeMap<String, openauth_core::options::SessionAdditionalField>,
    record: Option<&DbRecord>,
) -> Result<(), OpenAuthError> {
    for (name, field) in fields {
        if !field.returned {
            continue;
        }
        let value = record
            .and_then(|record| record.get(name))
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
        .collect::<Result<Map<_, _>, _>>()
        .map(Value::Object)
}

fn request_user_agent(request: &http::Request<Vec<u8>>) -> Option<String> {
    request
        .headers()
        .get(http::header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn request_ip(request: &http::Request<Vec<u8>>) -> Option<String> {
    request
        .headers()
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            request
                .headers()
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        })
}
