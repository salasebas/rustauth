use std::sync::Arc;

use http::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::shared::{
    error_response, get_session_openapi_response, json_openapi_response, json_response,
    list_sessions_openapi_response, query_param, request_cookie_header, sensitive_session,
    status_openapi_response, unauthorized, user_response_value,
};
use crate::api::output::{session_output_value, session_value_from_record};
use crate::api::services::session as session_service;
use crate::api::services::session::{
    CurrentSessionInput, UpdateSessionError, UpdateSessionErrorOrOpenAuth,
};
use crate::api::{
    create_auth_endpoint, parse_request_body, AsyncAuthEndpoint, AuthEndpointOptions, BodyField,
    BodySchema, JsonSchemaType, OpenApiOperation,
};
use crate::context::request_state::{
    has_request_state, set_current_session, set_current_session_user,
};
use crate::db::DbAdapter;
use crate::error::OpenAuthError;

#[derive(Debug, Serialize)]
struct SessionUserBody {
    session: Value,
    user: Value,
    #[serde(rename = "needsRefresh", skip_serializing_if = "Option::is_none")]
    needs_refresh: Option<bool>,
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
                let is_post = *request.method() == Method::POST;
                if is_post && !context.options.session.defer_session_refresh {
                    return error_response(
                        StatusCode::METHOD_NOT_ALLOWED,
                        "METHOD_NOT_ALLOWED",
                        "POST /get-session requires defer_session_refresh",
                    );
                }
                let cookie_header = request_cookie_header(&request).unwrap_or_default();
                let deferred_get = context.options.session.defer_session_refresh && !is_post;
                let Some(result) = session_service::current_session(
                    adapter.as_ref(),
                    context,
                    CurrentSessionInput {
                        cookie_header,
                        disable_cookie_cache: query_bool(&request, "disableCookieCache"),
                        disable_refresh: query_bool(&request, "disableRefresh"),
                        defer_refresh: deferred_get,
                    },
                )
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
                let needs_refresh = result.needs_refresh;
                if has_request_state() {
                    set_current_session(session.clone(), user.clone())?;
                    set_current_session_user(serde_json::to_value(&user).map_err(|error| {
                        OpenAuthError::Serialization {
                            context: "serializing current session user",
                            message: error.to_string(),
                        }
                    })?)?;
                }
                json_response(
                    StatusCode::OK,
                    &SessionUserBody {
                        session: session_output_value(adapter.as_ref(), context, &session).await?,
                        user: user_response_value(adapter.as_ref(), context, &user).await?,
                        needs_refresh: deferred_get.then_some(needs_refresh),
                    },
                    result.cookies,
                )
            })
        },
    )
}

fn query_bool(request: &crate::api::ApiRequest, name: &str) -> bool {
    query_param(request, name)
        .map(|value| matches!(value.to_ascii_lowercase().as_str(), "true" | "1"))
        .unwrap_or(false)
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
                    sensitive_session(adapter.as_ref(), context, &request).await?
                else {
                    return unauthorized();
                };
                let sessions =
                    session_service::list_sessions(adapter.as_ref(), context, &user).await?;
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
                    sensitive_session(adapter.as_ref(), context, &request).await?
                else {
                    return unauthorized();
                };
                session_service::revoke_session(adapter.as_ref(), context, &user, &body.token)
                    .await?;
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
                    sensitive_session(adapter.as_ref(), context, &request).await?
                else {
                    return unauthorized();
                };
                session_service::revoke_sessions(adapter.as_ref(), context, &user).await?;
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
                    sensitive_session(adapter.as_ref(), context, &request).await?
                else {
                    return unauthorized();
                };
                session_service::revoke_other_sessions(
                    adapter.as_ref(),
                    context,
                    &current_session,
                    &user,
                )
                .await?;
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
                    sensitive_session(adapter.as_ref(), context, &request).await?
                else {
                    return unauthorized();
                };
                let body: Value = parse_request_body(&request)?;
                let record = match session_service::update_session(
                    adapter.as_ref(),
                    context,
                    &current,
                    body,
                )
                .await
                {
                    Ok(record) => record,
                    Err(error) => return update_session_error_response(error),
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

fn update_session_error_response(
    error: UpdateSessionErrorOrOpenAuth,
) -> Result<crate::api::ApiResponse, OpenAuthError> {
    match error {
        UpdateSessionErrorOrOpenAuth::OpenAuth(error) => Err(error),
        UpdateSessionErrorOrOpenAuth::Service(error) => match error {
            UpdateSessionError::BodyMustBeObject => error_response(
                StatusCode::BAD_REQUEST,
                "BODY_MUST_BE_AN_OBJECT",
                "Body must be an object",
            ),
            UpdateSessionError::FieldNotInput => error_response(
                StatusCode::BAD_REQUEST,
                "INVALID_REQUEST_BODY",
                "field is not accepted as input",
            ),
            UpdateSessionError::InvalidFieldValue => error_response(
                StatusCode::BAD_REQUEST,
                "INVALID_REQUEST_BODY",
                "invalid session field value",
            ),
            UpdateSessionError::NoFieldsToUpdate => error_response(
                StatusCode::BAD_REQUEST,
                "NO_FIELDS_TO_UPDATE",
                "No fields to update",
            ),
            UpdateSessionError::SessionNotFound => unauthorized(),
        },
    }
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
