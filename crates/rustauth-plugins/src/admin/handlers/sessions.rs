use http::StatusCode;
use rustauth_core::api::{parse_request_body, ApiRequest, ApiResponse};
use rustauth_core::context::AuthContext;
use rustauth_core::error::RustAuthError;
use serde_json::json;
use time::OffsetDateTime;

use crate::admin::access::has_permission;
use crate::admin::cookies::{
    cookie_header, expire_admin_cookie, read_admin_cookie, read_dont_remember_cookie,
    session_cookie, session_cookie_with_dont_remember, set_admin_cookie,
};
use crate::admin::errors;
use crate::admin::models::{RevokeSessionBody, UserIdBody};
use crate::admin::options::AdminOptions;
use crate::admin::response;
use crate::admin::store::AdminStore;

use super::{current_admin, permission, require_adapter};

pub async fn list_user_sessions(
    options: AdminOptions,
    context: &AuthContext,
    request: ApiRequest,
) -> Result<ApiResponse, RustAuthError> {
    let Some((_session, admin)) = current_admin(context, &request).await? else {
        return errors::unauthorized();
    };
    if !has_permission(
        Some(&admin.id),
        admin.role.as_deref(),
        &options,
        &permission("session", "list"),
    ) {
        return errors::forbidden(errors::not_allowed_to_list_sessions());
    }
    let body = parse_request_body::<UserIdBody>(&request)?;
    let adapter = require_adapter(context)?;
    let sessions = AdminStore::new(adapter.as_ref())
        .list_user_sessions(&body.user_id)
        .await?;
    response::json(StatusCode::OK, &json!({ "sessions": sessions }))
}

pub async fn impersonate_user(
    options: AdminOptions,
    context: &AuthContext,
    request: ApiRequest,
) -> Result<ApiResponse, RustAuthError> {
    let Some((admin_session, admin)) = current_admin(context, &request).await? else {
        return errors::unauthorized();
    };
    if !has_permission(
        Some(&admin.id),
        admin.role.as_deref(),
        &options,
        &permission("user", "impersonate"),
    ) {
        return errors::forbidden(errors::not_allowed_to_impersonate_users());
    }
    let body = parse_request_body::<UserIdBody>(&request)?;
    let adapter = require_adapter(context)?;
    let store = AdminStore::new(adapter.as_ref());
    let Some(target) = store.find_user_by_id(&body.user_id).await? else {
        return errors::not_found_user();
    };
    if target_is_admin(&target, &options)
        && !options.allow_impersonating_admins
        && !has_permission(
            Some(&admin.id),
            admin.role.as_deref(),
            &options,
            &permission("user", "impersonate-admins"),
        )
    {
        return errors::forbidden(errors::cannot_impersonate_admins());
    }
    if target.banned {
        return errors::forbidden(errors::banned_user(&options.banned_user_message));
    }
    let expires_at = OffsetDateTime::now_utc() + options.impersonation_session_duration;
    let session = store
        .create_session(&target.id, expires_at, Some(admin.id.clone()))
        .await?;
    let header = cookie_header(&request);
    let dont_remember = read_dont_remember_cookie(context, &header)?;
    let mut cookies = vec![set_admin_cookie(
        context,
        &admin_session.token,
        dont_remember.as_deref(),
    )?];
    cookies.extend(session_cookie(context, &session.token)?);
    response::json_with_cookies(
        StatusCode::OK,
        &json!({ "session": session, "user": target }),
        cookies,
    )
}

pub async fn stop_impersonating(
    context: &AuthContext,
    request: ApiRequest,
) -> Result<ApiResponse, RustAuthError> {
    let Some((session, _user)) = current_admin(context, &request).await? else {
        return errors::unauthorized();
    };
    let Some(impersonated_by) = session.impersonated_by.as_deref() else {
        return errors::error_response(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "You are not impersonating anyone",
        );
    };
    let adapter = require_adapter(context)?;
    let store = AdminStore::new(adapter.as_ref());
    let header = cookie_header(&request);
    let Some((admin_token, dont_remember)) = read_admin_cookie(context, &header)? else {
        return errors::error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ADMIN_SESSION_NOT_FOUND",
            "Failed to find admin session",
        );
    };
    let Some((admin_session, admin_user)) = store.find_session(&admin_token).await? else {
        return errors::error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ADMIN_SESSION_NOT_FOUND",
            "Failed to find admin session",
        );
    };
    if admin_session.user_id != impersonated_by {
        return errors::error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ADMIN_SESSION_NOT_FOUND",
            "Failed to find admin session",
        );
    }
    store.delete_session(&session.token).await?;
    let mut cookies =
        session_cookie_with_dont_remember(context, &admin_session.token, dont_remember.is_some())?;
    cookies.push(expire_admin_cookie(context));
    response::json_with_cookies(
        StatusCode::OK,
        &json!({ "session": admin_session, "user": admin_user }),
        cookies,
    )
}

pub async fn revoke_user_session(
    options: AdminOptions,
    context: &AuthContext,
    request: ApiRequest,
) -> Result<ApiResponse, RustAuthError> {
    let Some((_session, admin)) = current_admin(context, &request).await? else {
        return errors::unauthorized();
    };
    if !has_permission(
        Some(&admin.id),
        admin.role.as_deref(),
        &options,
        &permission("session", "revoke"),
    ) {
        return errors::forbidden(errors::not_allowed_to_revoke_sessions());
    }
    let body = parse_request_body::<RevokeSessionBody>(&request)?;
    let adapter = require_adapter(context)?;
    AdminStore::new(adapter.as_ref())
        .delete_session(&body.session_token)
        .await?;
    response::json(StatusCode::OK, &json!({ "success": true }))
}

pub async fn revoke_user_sessions(
    options: AdminOptions,
    context: &AuthContext,
    request: ApiRequest,
) -> Result<ApiResponse, RustAuthError> {
    let Some((_session, admin)) = current_admin(context, &request).await? else {
        return errors::unauthorized();
    };
    if !has_permission(
        Some(&admin.id),
        admin.role.as_deref(),
        &options,
        &permission("session", "revoke"),
    ) {
        return errors::forbidden(errors::not_allowed_to_revoke_sessions());
    }
    let body = parse_request_body::<UserIdBody>(&request)?;
    let adapter = require_adapter(context)?;
    AdminStore::new(adapter.as_ref())
        .delete_user_sessions(&body.user_id)
        .await?;
    response::json(StatusCode::OK, &json!({ "success": true }))
}

fn target_is_admin(user: &crate::admin::AdminUser, options: &AdminOptions) -> bool {
    options.admin_user_ids.iter().any(|id| id == &user.id)
        || user.role.as_deref().is_some_and(|roles| {
            roles.split(',').any(|role| {
                options
                    .admin_roles
                    .iter()
                    .any(|admin_role| admin_role.trim() == role.trim())
            })
        })
}
