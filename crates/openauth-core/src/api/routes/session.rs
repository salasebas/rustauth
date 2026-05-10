use std::sync::Arc;

use http::{Method, StatusCode};
use serde::{Deserialize, Serialize};

use super::shared::{
    current_session, get_session_openapi_response, json_response, list_sessions_openapi_response,
    request_cookie_header, status_openapi_response, unauthorized,
};
use crate::api::{
    create_auth_endpoint, parse_request_body, AsyncAuthEndpoint, AuthEndpointOptions, BodyField,
    BodySchema, JsonSchemaType, OpenApiOperation,
};
use crate::auth::session::{GetSessionInput, SessionAuth};
use crate::db::{DbAdapter, Session, User};
use crate::session::DbSessionStore;

#[derive(Debug, Serialize)]
struct SessionUserBody {
    session: Session,
    user: User,
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
                    &SessionUserBody { session, user },
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

fn revoke_session_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("token", JsonSchemaType::String).description("The token to revoke")
    ])
}
