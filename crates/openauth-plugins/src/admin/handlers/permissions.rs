use http::StatusCode;
use openauth_core::api::{parse_request_body, ApiRequest, ApiResponse};
use openauth_core::context::AuthContext;
use openauth_core::error::OpenAuthError;
use serde_json::json;

use crate::admin::access::has_permission;
use crate::admin::errors;
use crate::admin::models::HasPermissionBody;
use crate::admin::options::AdminOptions;
use crate::admin::response;
use crate::admin::store::AdminStore;

use super::{current_admin, require_adapter};

pub async fn has_permission_endpoint(
    options: AdminOptions,
    context: &AuthContext,
    request: ApiRequest,
) -> Result<ApiResponse, OpenAuthError> {
    let body = parse_request_body::<HasPermissionBody>(&request)?;
    if body.permissions.is_empty() {
        return errors::error_response(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "invalid permission check. no permission(s) were passed.",
        );
    }

    let current = current_admin(context, &request).await?;
    let user = if let Some((_session, user)) = current {
        Some(user)
    } else if let Some(role) = body.role.as_ref() {
        Some(crate::admin::AdminUser {
            id: body.user_id.clone().unwrap_or_default(),
            name: String::new(),
            email: String::new(),
            email_verified: false,
            image: None,
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
            role: Some(role.clone()),
            banned: false,
            ban_reason: None,
            ban_expires: None,
        })
    } else if let Some(user_id) = body.user_id.as_ref().filter(|value| !value.is_empty()) {
        let adapter = require_adapter(context)?;
        let user = AdminStore::new(adapter.as_ref())
            .find_user_by_id(user_id)
            .await?;
        if user.is_none() {
            return errors::error_response(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "user not found",
            );
        }
        user
    } else {
        None
    };

    let Some(user) = user else {
        return errors::error_response(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "user id or role is required",
        );
    };
    let success = has_permission(
        Some(&user.id),
        user.role.as_deref(),
        &options,
        &body.permissions,
    );
    response::json(
        StatusCode::OK,
        &json!({ "error": null, "success": success }),
    )
}
