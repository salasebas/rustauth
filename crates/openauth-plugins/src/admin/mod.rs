//! Server-side admin plugin.

mod access;
mod cookies;
mod errors;
mod handlers;
mod models;
mod openapi;
mod options;
mod response;
mod routes;
mod schema;
mod store;

pub use access::{has_permission, PermissionMap, Role};
pub use errors::ADMIN_ERROR_CODES;
pub use models::{AdminSession, AdminUser};
pub use options::{AdminOptions, AdminSchemaOptions};

use openauth_core::error::OpenAuthError;
use openauth_core::plugin::{
    AuthPlugin, PluginAfterHookAction, PluginDatabaseBeforeAction, PluginDatabaseBeforeInput,
    PluginDatabaseHook, PluginInitOutput,
};
use serde_json::Value;
use time::OffsetDateTime;

pub mod access_control {
    pub use super::access::{
        default_access_control, default_roles, default_statements, has_permission, PermissionMap,
        Role,
    };
}

pub const UPSTREAM_PLUGIN_ID: &str = "admin";

#[must_use]
pub fn admin() -> AuthPlugin {
    admin_with(AdminOptions::default())
}

#[must_use]
pub fn admin_with(options: AdminOptions) -> AuthPlugin {
    let options = options.with_defaults();
    let init_options = options.clone();

    AuthPlugin::new(UPSTREAM_PLUGIN_ID)
        .with_version(crate::VERSION)
        .with_options(options.to_json())
        .with_init(move |_context| {
            init_options
                .validate()
                .map_err(OpenAuthError::InvalidConfig)?;
            Ok(PluginInitOutput::default())
        })
        .with_schema(schema::user_role_field(&options.schema))
        .with_schema(schema::user_banned_field(&options.schema))
        .with_schema(schema::user_ban_reason_field(&options.schema))
        .with_schema(schema::user_ban_expires_field(&options.schema))
        .with_schema(schema::session_impersonated_by_field(&options.schema))
        .with_database_hook(default_role_hook(options.default_role.clone()))
        .with_database_hook(banned_session_hook(options.banned_user_message.clone()))
        .with_async_after_hook("/list-sessions", filter_impersonated_sessions_hook)
        .with_endpoint(routes::set_role(options.clone()))
        .with_endpoint(routes::get_user(options.clone()))
        .with_endpoint(routes::create_user(options.clone()))
        .with_endpoint(routes::update_user(options.clone()))
        .with_endpoint(routes::list_users(options.clone()))
        .with_endpoint(routes::list_user_sessions(options.clone()))
        .with_endpoint(routes::ban_user(options.clone()))
        .with_endpoint(routes::unban_user(options.clone()))
        .with_endpoint(routes::impersonate_user(options.clone()))
        .with_endpoint(routes::stop_impersonating())
        .with_endpoint(routes::revoke_user_session(options.clone()))
        .with_endpoint(routes::revoke_user_sessions(options.clone()))
        .with_endpoint(routes::remove_user(options.clone()))
        .with_endpoint(routes::set_user_password(options.clone()))
        .with_endpoint(routes::has_permission_endpoint(options.clone()))
        .with_error_code(errors::failed_to_create_user())
        .with_error_code(errors::user_already_exists())
        .with_error_code(errors::user_already_exists_use_another_email())
        .with_error_code(errors::cannot_ban_yourself())
        .with_error_code(errors::not_allowed_to_change_role())
        .with_error_code(errors::not_allowed_to_create_users())
        .with_error_code(errors::not_allowed_to_list_users())
        .with_error_code(errors::not_allowed_to_list_sessions())
        .with_error_code(errors::not_allowed_to_ban_users())
        .with_error_code(errors::not_allowed_to_impersonate_users())
        .with_error_code(errors::not_allowed_to_revoke_sessions())
        .with_error_code(errors::not_allowed_to_delete_users())
        .with_error_code(errors::not_allowed_to_set_password())
        .with_error_code(errors::banned_user(&options.banned_user_message))
        .with_error_code(errors::not_allowed_to_get_user())
        .with_error_code(errors::no_data_to_update())
        .with_error_code(errors::not_allowed_to_update_users())
        .with_error_code(errors::cannot_remove_yourself())
        .with_error_code(errors::not_allowed_to_set_unknown_role())
        .with_error_code(errors::cannot_impersonate_admins())
        .with_error_code(errors::invalid_role_type())
}

fn default_role_hook(default_role: String) -> PluginDatabaseHook {
    PluginDatabaseHook::before_create("admin_default_user_role", move |_context, mut query| {
        if query.model == "user" && !query.data.contains_key("role") {
            query.data.insert(
                "role".to_owned(),
                openauth_core::db::DbValue::String(default_role.clone()),
            );
        }
        Ok(PluginDatabaseBeforeAction::Continue(
            PluginDatabaseBeforeInput::Create(query),
        ))
    })
}

fn banned_session_hook(message: String) -> PluginDatabaseHook {
    PluginDatabaseHook::before_create_async(
        "admin_block_banned_user_session",
        move |context, query| {
            let message = message.clone();
            Box::pin(async move {
                if query.model != "session" {
                    return Ok(PluginDatabaseBeforeAction::Continue(
                        PluginDatabaseBeforeInput::Create(query),
                    ));
                }
                let Some(openauth_core::db::DbValue::String(user_id)) = query.data.get("user_id")
                else {
                    return Ok(PluginDatabaseBeforeAction::Continue(
                        PluginDatabaseBeforeInput::Create(query),
                    ));
                };
                let store = store::AdminStore::new(context.adapter);
                let Some(user) = store.find_user_by_id(user_id).await? else {
                    return Ok(PluginDatabaseBeforeAction::Continue(
                        PluginDatabaseBeforeInput::Create(query),
                    ));
                };
                if !user.banned {
                    return Ok(PluginDatabaseBeforeAction::Continue(
                        PluginDatabaseBeforeInput::Create(query),
                    ));
                }
                if user
                    .ban_expires
                    .is_some_and(|expires| expires < OffsetDateTime::now_utc())
                {
                    store.unban_user(user_id).await?;
                    return Ok(PluginDatabaseBeforeAction::Continue(
                        PluginDatabaseBeforeInput::Create(query),
                    ));
                }
                if context.request_path.as_deref().is_some_and(|path| {
                    path.starts_with("/callback") || path.starts_with("/oauth2/callback")
                }) {
                    return Ok(PluginDatabaseBeforeAction::Cancel(OpenAuthError::Api(
                        format!("BANNED_USER: {message}"),
                    )));
                }
                Ok(PluginDatabaseBeforeAction::Cancel(OpenAuthError::Api(
                    format!("BANNED_USER: {message}"),
                )))
            })
        },
    )
}

fn filter_impersonated_sessions_hook<'a>(
    context: &'a openauth_core::context::AuthContext,
    _request: &'a openauth_core::api::ApiRequest,
    response: openauth_core::api::ApiResponse,
) -> openauth_core::plugin::PluginAfterHookFuture<'a> {
    Box::pin(async move {
        let Some(adapter) = context.adapter() else {
            return Ok(PluginAfterHookAction::Continue(response));
        };
        let (parts, body) = response.into_parts();
        let Ok(Value::Array(sessions)) = serde_json::from_slice::<Value>(&body) else {
            return Ok(PluginAfterHookAction::Continue(http::Response::from_parts(
                parts, body,
            )));
        };
        let store = store::AdminStore::new(adapter.as_ref());
        let mut filtered = Vec::new();
        for session in sessions {
            let Some(token) = session.get("token").and_then(Value::as_str) else {
                filtered.push(session);
                continue;
            };
            match store.find_session(token).await? {
                Some((admin_session, _)) if admin_session.impersonated_by.is_none() => {
                    filtered.push(session);
                }
                None => filtered.push(session),
                Some(_) => {}
            }
        }
        let body = serde_json::to_vec(&filtered).map_err(|error| {
            OpenAuthError::Api(format!("failed to serialize filtered sessions: {error}"))
        })?;
        Ok(PluginAfterHookAction::Continue(http::Response::from_parts(
            parts, body,
        )))
    })
}
