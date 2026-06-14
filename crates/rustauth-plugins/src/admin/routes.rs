use http::Method;
use rustauth_core::api::{
    create_auth_endpoint, ApiResponse, AsyncAuthEndpoint, AuthEndpointOptions,
};
use rustauth_core::context::AuthContext;
use rustauth_core::error::RustAuthError;
use serde_json::json;

use super::handlers;
use super::openapi::{
    create_user_schema, list_user_parameters, object_response, ref_response, ref_schema, schema,
    set_role_schema, success_response, user_id_body, EndpointDoc,
};
use super::options::AdminOptions;

pub fn set_role(options: AdminOptions) -> AsyncAuthEndpoint {
    endpoint(
        doc(
            "/admin/set-role",
            Method::POST,
            "setUserRole",
            "Set the role of a user. Requires the `user:set-role` admin permission.",
            Some(set_role_schema()),
            vec![],
            object_response("User role updated", &[("user", ref_schema("User"))]),
        ),
        move |ctx, req| {
            let options = options.clone();
            async move { handlers::users::set_role(options, &ctx, req).await }
        },
    )
}

pub fn get_user(options: AdminOptions) -> AsyncAuthEndpoint {
    endpoint(
        doc(
            "/admin/get-user",
            Method::GET,
            "getUser",
            "Get a user by id. Requires the `user:get` admin permission.",
            None,
            vec![super::openapi::query_parameter(
                "id",
                "string",
                true,
                "The user id.",
            )],
            ref_response("User returned", "User"),
        ),
        move |ctx, req| {
            let options = options.clone();
            async move { handlers::users::get_user(options, &ctx, req).await }
        },
    )
}

pub fn create_user(options: AdminOptions) -> AsyncAuthEndpoint {
    endpoint(
        doc(
            "/admin/create-user",
            Method::POST,
            "createUser",
            "Create a user, optionally with a credential password, role, and custom fields. Requires `user:create`.",
            Some(create_user_schema()),
            vec![],
            object_response("User created", &[("user", ref_schema("User"))]),
        ),
        move |ctx, req| {
            let options = options.clone();
            async move { handlers::users::create_user(options, &ctx, req).await }
        },
    )
}

pub fn update_user(options: AdminOptions) -> AsyncAuthEndpoint {
    endpoint(
        doc(
            "/admin/update-user",
            Method::POST,
            "adminUpdateUser",
            "Update admin-managed user fields. Role updates additionally require `user:set-role`.",
            Some(schema(&[
                ("userId", "string", true, "The user id to update."),
                ("data", "object", true, "The fields to update."),
            ])),
            vec![],
            ref_response("User updated", "User"),
        ),
        move |ctx, req| {
            let options = options.clone();
            async move { handlers::users::update_user(options, &ctx, req).await }
        },
    )
}

pub fn list_users(options: AdminOptions) -> AsyncAuthEndpoint {
    endpoint(
        doc(
            "/admin/list-users",
            Method::GET,
            "listUsers",
            "List users with optional search, filter, pagination, and sorting. Requires `user:list`.",
            None,
            list_user_parameters(),
            object_response(
                "Users listed",
                &[
                    (
                        "users",
                        json!({ "type": "array", "items": ref_schema("User") }),
                    ),
                    ("total", json!({ "type": "number" })),
                    ("limit", json!({ "type": "number", "nullable": true })),
                    ("offset", json!({ "type": "number", "nullable": true })),
                ],
            ),
        ),
        move |ctx, req| {
            let options = options.clone();
            async move { handlers::users::list_users(options, &ctx, req).await }
        },
    )
}

pub fn list_user_sessions(options: AdminOptions) -> AsyncAuthEndpoint {
    endpoint(
        doc(
            "/admin/list-user-sessions",
            Method::POST,
            "adminListUserSessions",
            "List active sessions for a user. Requires `session:list`.",
            Some(user_id_body()),
            vec![],
            object_response(
                "User sessions listed",
                &[(
                    "sessions",
                    json!({ "type": "array", "items": ref_schema("Session") }),
                )],
            ),
        ),
        move |ctx, req| {
            let options = options.clone();
            async move { handlers::sessions::list_user_sessions(options, &ctx, req).await }
        },
    )
}

pub fn ban_user(options: AdminOptions) -> AsyncAuthEndpoint {
    endpoint(
        doc(
            "/admin/ban-user",
            Method::POST,
            "banUser",
            "Ban a user and revoke their sessions. Requires `user:ban`.",
            Some(schema(&[
                ("userId", "string", true, "The user id to ban."),
                ("banReason", "string", false, "Optional reason for the ban."),
                (
                    "banExpiresIn",
                    "number",
                    false,
                    "Optional ban duration in seconds.",
                ),
            ])),
            vec![],
            object_response("User banned", &[("user", ref_schema("User"))]),
        ),
        move |ctx, req| {
            let options = options.clone();
            async move { handlers::users::ban_user(options, &ctx, req).await }
        },
    )
}

pub fn unban_user(options: AdminOptions) -> AsyncAuthEndpoint {
    endpoint(
        doc(
            "/admin/unban-user",
            Method::POST,
            "unbanUser",
            "Unban a user. Requires `user:ban`.",
            Some(user_id_body()),
            vec![],
            object_response("User unbanned", &[("user", ref_schema("User"))]),
        ),
        move |ctx, req| {
            let options = options.clone();
            async move { handlers::users::unban_user(options, &ctx, req).await }
        },
    )
}

pub fn impersonate_user(options: AdminOptions) -> AsyncAuthEndpoint {
    endpoint(
        doc(
            "/admin/impersonate-user",
            Method::POST,
            "impersonateUser",
            "Create an impersonation session for another user. Requires `user:impersonate`.",
            Some(user_id_body()),
            vec![],
            object_response(
                "Impersonation session created",
                &[
                    ("session", ref_schema("Session")),
                    ("user", ref_schema("User")),
                ],
            ),
        ),
        move |ctx, req| {
            let options = options.clone();
            async move { handlers::sessions::impersonate_user(options, &ctx, req).await }
        },
    )
}

pub fn stop_impersonating() -> AsyncAuthEndpoint {
    endpoint(
        doc(
            "/admin/stop-impersonating",
            Method::POST,
            "stopImpersonating",
            "Stop impersonating and restore the original admin session.",
            None,
            vec![],
            object_response(
                "Admin session restored",
                &[
                    ("session", ref_schema("Session")),
                    ("user", ref_schema("User")),
                ],
            ),
        ),
        |ctx, req| async move { handlers::sessions::stop_impersonating(&ctx, req).await },
    )
}

pub fn revoke_user_session(options: AdminOptions) -> AsyncAuthEndpoint {
    endpoint(
        doc(
            "/admin/revoke-user-session",
            Method::POST,
            "revokeUserSession",
            "Revoke one user session by token. Requires `session:revoke`.",
            Some(schema(&[(
                "sessionToken",
                "string",
                true,
                "The session token to revoke.",
            )])),
            vec![],
            success_response("Session revoked"),
        ),
        move |ctx, req| {
            let options = options.clone();
            async move { handlers::sessions::revoke_user_session(options, &ctx, req).await }
        },
    )
}

pub fn revoke_user_sessions(options: AdminOptions) -> AsyncAuthEndpoint {
    endpoint(
        doc(
            "/admin/revoke-user-sessions",
            Method::POST,
            "revokeUserSessions",
            "Revoke all sessions for a user. Requires `session:revoke`.",
            Some(user_id_body()),
            vec![],
            success_response("Sessions revoked"),
        ),
        move |ctx, req| {
            let options = options.clone();
            async move { handlers::sessions::revoke_user_sessions(options, &ctx, req).await }
        },
    )
}

pub fn remove_user(options: AdminOptions) -> AsyncAuthEndpoint {
    endpoint(
        doc(
            "/admin/remove-user",
            Method::POST,
            "removeUser",
            "Delete a user, their accounts, and their sessions. Requires `user:delete`.",
            Some(user_id_body()),
            vec![],
            success_response("User removed"),
        ),
        move |ctx, req| {
            let options = options.clone();
            async move { handlers::users::remove_user(options, &ctx, req).await }
        },
    )
}

pub fn set_user_password(options: AdminOptions) -> AsyncAuthEndpoint {
    endpoint(
        doc(
            "/admin/set-user-password",
            Method::POST,
            "setUserPassword",
            "Set or replace a user's credential password. Requires `user:set-password`.",
            Some(schema(&[
                ("userId", "string", true, "The user id."),
                ("newPassword", "string", true, "The new password."),
            ])),
            vec![],
            object_response("Password set", &[("status", json!({ "type": "boolean" }))]),
        ),
        move |ctx, req| {
            let options = options.clone();
            async move { handlers::users::set_user_password(options, &ctx, req).await }
        },
    )
}

pub fn has_permission_endpoint(options: AdminOptions) -> AsyncAuthEndpoint {
    endpoint(
        doc(
            "/admin/has-permission",
            Method::POST,
            "adminHasPermission",
            "Check whether a user id or role has the requested permissions.",
            Some(schema(&[
                ("userId", "string", false, "Optional user id to check."),
                ("role", "string", false, "Optional role to check."),
                (
                    "permissions",
                    "object",
                    false,
                    "Permissions grouped by resource. Also accepts the `permission` alias; the endpoint rejects an empty set.",
                ),
            ])),
            vec![],
            object_response(
                "Permission check result",
                &[
                    ("error", json!({ "type": "string", "nullable": true })),
                    ("success", json!({ "type": "boolean" })),
                ],
            ),
        ),
        move |ctx, req| {
            let options = options.clone();
            async move { handlers::permissions::has_permission_endpoint(options, &ctx, req).await }
        },
    )
}

fn endpoint<F, Fut>(doc: EndpointDoc, handler: F) -> AsyncAuthEndpoint
where
    F: Fn(AuthContext, rustauth_core::api::ApiRequest) -> Fut + Send + Sync + Clone + 'static,
    Fut: std::future::Future<Output = Result<ApiResponse, RustAuthError>> + Send + 'static,
{
    let operation = doc.operation();
    let mut options = AuthEndpointOptions::new()
        .operation_id(doc.operation_id)
        .openapi(operation);
    if let Some(body_schema) = doc.body_schema() {
        options = options
            .allowed_media_types(["application/json", "application/x-www-form-urlencoded"])
            .body_schema(body_schema);
    }
    create_auth_endpoint(doc.path, doc.method, options, handler)
}

fn doc(
    path: &'static str,
    method: Method,
    operation_id: &'static str,
    description: &'static str,
    request_schema: Option<serde_json::Value>,
    parameters: Vec<serde_json::Value>,
    response_200: serde_json::Value,
) -> EndpointDoc {
    EndpointDoc {
        path,
        method,
        operation_id,
        description,
        request_schema,
        parameters,
        response_200,
    }
}
