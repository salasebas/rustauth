use std::sync::Arc;

use http::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use super::shared::{
    current_session, error_response, get_session_openapi_response, json_openapi_response,
    json_response, list_sessions_openapi_response, request_cookie_header, status_openapi_response,
    unauthorized, user_response_value,
};
use crate::api::additional_fields::{insert_returned_fields, json_to_db_value};
use crate::api::{
    create_auth_endpoint, parse_request_body, AsyncAuthEndpoint, AuthEndpointOptions, BodyField,
    BodySchema, JsonSchemaType, OpenApiOperation,
};
use crate::auth::session::{GetSessionInput, SessionAuth};
use crate::context::AuthContext;
use crate::db::{DbAdapter, DbRecord, DbValue, FindOne, Session, Update, Where};
use crate::error::OpenAuthError;
use crate::session::DbSessionStore;

#[derive(Debug, Serialize)]
struct SessionUserBody {
    session: Value,
    user: Value,
}

#[derive(Debug, Deserialize)]
struct RevokeSessionBody {
    token: String,
}

#[derive(Debug, Serialize)]
struct StatusBody {
    status: bool,
}

pub(super) fn get_session_endpoint(
    method: Method,
    adapter: Arc<dyn DbAdapter>,
) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/get-session",
        method,
        AuthEndpointOptions::new()
            .operation_id("getSession")
            .openapi(
                OpenApiOperation::new("getSession")
                    .description("Get the current session")
                    .response("200", get_session_openapi_response()),
            ),
        move |context, request| {
            let adapter = Arc::clone(&adapter);
            Box::pin(async move {
                let cookie_header = request_cookie_header(&request).unwrap_or_default();
                let Some(result) = SessionAuth::new(adapter.as_ref(), context)
                    .get_session(GetSessionInput::new(cookie_header))
                    .await?
                else {
                    return json_response(
                        StatusCode::OK,
                        &Option::<SessionUserBody>::None,
                        Vec::new(),
                    );
                };
                let Some(session) = result.session else {
                    return json_response(
                        StatusCode::OK,
                        &Option::<SessionUserBody>::None,
                        result.cookies,
                    );
                };
                let Some(user) = result.user else {
                    return json_response(
                        StatusCode::OK,
                        &Option::<SessionUserBody>::None,
                        result.cookies,
                    );
                };
                json_response(
                    StatusCode::OK,
                    &SessionUserBody {
                        session: session_response_value(adapter.as_ref(), context, &session)
                            .await?,
                        user: user_response_value(adapter.as_ref(), context, &user).await?,
                    },
                    result.cookies,
                )
            })
        },
    )
}

pub(super) fn list_sessions_endpoint(adapter: Arc<dyn DbAdapter>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/list-sessions",
        Method::GET,
        AuthEndpointOptions::new()
            .operation_id("listUserSessions")
            .openapi(
                OpenApiOperation::new("listUserSessions")
                    .description("List all active sessions for the user")
                    .response("200", list_sessions_openapi_response()),
            ),
        move |context, request| {
            let adapter = Arc::clone(&adapter);
            Box::pin(async move {
                let Some((_, user, cookies)) =
                    current_session(adapter.as_ref(), context, &request).await?
                else {
                    return unauthorized();
                };
                let sessions = DbSessionStore::new(adapter.as_ref())
                    .list_user_sessions(&user.id)
                    .await?;
                json_response(StatusCode::OK, &sessions, cookies)
            })
        },
    )
}

pub(super) fn revoke_session_endpoint(adapter: Arc<dyn DbAdapter>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/revoke-session",
        Method::POST,
        AuthEndpointOptions::new()
            .body_schema(revoke_session_body_schema())
            .openapi(
                OpenApiOperation::new("revokeSession")
                    .description("Revoke a single session")
                    .response(
                        "200",
                        status_openapi_response(
                            "Indicates if the session was revoked successfully",
                        ),
                    ),
            ),
        move |context, request| {
            let adapter = Arc::clone(&adapter);
            Box::pin(async move {
                let body: RevokeSessionBody = parse_request_body(&request)?;
                let Some((_, user, cookies)) =
                    current_session(adapter.as_ref(), context, &request).await?
                else {
                    return unauthorized();
                };
                let store = DbSessionStore::new(adapter.as_ref());
                if let Some(session) = store.find_session(&body.token).await? {
                    if session.user_id == user.id {
                        store.delete_session(&body.token).await?;
                    }
                }
                json_response(StatusCode::OK, &StatusBody { status: true }, cookies)
            })
        },
    )
}

pub(super) fn revoke_sessions_endpoint(adapter: Arc<dyn DbAdapter>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/revoke-sessions",
        Method::POST,
        AuthEndpointOptions::new().openapi(
            OpenApiOperation::new("revokeSessions")
                .description("Revoke all sessions for the user")
                .response(
                    "200",
                    status_openapi_response("Indicates if all sessions were revoked successfully"),
                ),
        ),
        move |context, request| {
            let adapter = Arc::clone(&adapter);
            Box::pin(async move {
                let Some((_, user, cookies)) =
                    current_session(adapter.as_ref(), context, &request).await?
                else {
                    return unauthorized();
                };
                DbSessionStore::new(adapter.as_ref())
                    .delete_user_sessions(&user.id)
                    .await?;
                json_response(StatusCode::OK, &StatusBody { status: true }, cookies)
            })
        },
    )
}

pub(super) fn revoke_other_sessions_endpoint(adapter: Arc<dyn DbAdapter>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/revoke-other-sessions",
        Method::POST,
        AuthEndpointOptions::new().openapi(
            OpenApiOperation::new("revokeOtherSessions")
                .description("Revoke all other sessions for the user except the current one")
                .response(
                    "200",
                    status_openapi_response(
                        "Indicates if all other sessions were revoked successfully",
                    ),
                ),
        ),
        move |context, request| {
            let adapter = Arc::clone(&adapter);
            Box::pin(async move {
                let Some((current_session, user, cookies)) =
                    current_session(adapter.as_ref(), context, &request).await?
                else {
                    return unauthorized();
                };
                let store = DbSessionStore::new(adapter.as_ref());
                let sessions = store.list_user_sessions(&user.id).await?;
                for session in sessions {
                    if session.token != current_session.token {
                        store.delete_session(&session.token).await?;
                    }
                }
                json_response(StatusCode::OK, &StatusBody { status: true }, cookies)
            })
        },
    )
}

pub(super) fn update_session_endpoint(adapter: Arc<dyn DbAdapter>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/update-session",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("updateSession")
            .openapi(
                OpenApiOperation::new("updateSession")
                    .description("Update the current session")
                    .request_body(update_session_request_body())
                    .response("200", update_session_response()),
            ),
        move |context, request| {
            let adapter = Arc::clone(&adapter);
            Box::pin(async move {
                let Some((current, _user, cookies)) =
                    current_session(adapter.as_ref(), context, &request).await?
                else {
                    return unauthorized();
                };
                let body: Value = parse_request_body(&request)?;
                let Some(fields) = body.as_object() else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "BODY_MUST_BE_AN_OBJECT",
                        "Body must be an object",
                    );
                };

                let mut update = Update::new("session")
                    .where_clause(Where::new("token", DbValue::String(current.token.clone())));
                for (name, value) in fields {
                    if is_core_session_field(name) {
                        continue;
                    }
                    let Some(field) = context.options.session.additional_fields.get(name) else {
                        continue;
                    };
                    if !field.input {
                        return error_response(
                            StatusCode::BAD_REQUEST,
                            "INVALID_REQUEST_BODY",
                            "field is not accepted as input",
                        );
                    }
                    let Ok(value) = json_to_db_value(name, &field.field_type, value) else {
                        return error_response(
                            StatusCode::BAD_REQUEST,
                            "INVALID_REQUEST_BODY",
                            "invalid session field value",
                        );
                    };
                    update = update.data(name, value);
                }

                if update.data.is_empty() {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "NO_FIELDS_TO_UPDATE",
                        "No fields to update",
                    );
                }

                update = update.data("updated_at", DbValue::Timestamp(OffsetDateTime::now_utc()));
                let Some(record) = adapter.update(update).await? else {
                    return unauthorized();
                };
                let session = session_value_from_record(context, &record, &current)?;
                json_response(
                    StatusCode::OK,
                    &serde_json::json!({ "session": session }),
                    cookies,
                )
            })
        },
    )
}

fn revoke_session_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("token", JsonSchemaType::String).description("The token to revoke")
    ])
}

async fn session_response_value(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    session: &Session,
) -> Result<Value, OpenAuthError> {
    if context.options.session.additional_fields.is_empty() {
        return serde_json::to_value(session)
            .map_err(|error| OpenAuthError::Api(error.to_string()));
    }
    let record = adapter
        .find_one(
            FindOne::new("session")
                .where_clause(Where::new("token", DbValue::String(session.token.clone()))),
        )
        .await?;
    match record {
        Some(record) => session_value_from_record(context, &record, session),
        None => {
            serde_json::to_value(session).map_err(|error| OpenAuthError::Api(error.to_string()))
        }
    }
}

fn session_value_from_record(
    context: &AuthContext,
    record: &DbRecord,
    session: &Session,
) -> Result<Value, OpenAuthError> {
    let mut value =
        serde_json::to_value(session).map_err(|error| OpenAuthError::Api(error.to_string()))?;
    let Some(object) = value.as_object_mut() else {
        return Err(OpenAuthError::Api(
            "could not serialize session as an object".to_owned(),
        ));
    };
    insert_returned_fields(object, &context.options.session.additional_fields, record)?;
    Ok(value)
}

fn is_core_session_field(name: &str) -> bool {
    matches!(
        name,
        "id" | "user_id"
            | "userId"
            | "expires_at"
            | "expiresAt"
            | "token"
            | "ip_address"
            | "ipAddress"
            | "user_agent"
            | "userAgent"
            | "created_at"
            | "createdAt"
            | "updated_at"
            | "updatedAt"
    )
}

fn update_session_request_body() -> Value {
    serde_json::json!({
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "additionalProperties": true
                },
            },
        },
    })
}

fn update_session_response() -> Value {
    json_openapi_response(
        "Success",
        serde_json::json!({
            "type": "object",
            "properties": {
                "session": {
                    "type": "object",
                    "$ref": "#/components/schemas/Session",
                },
            },
        }),
    )
}
