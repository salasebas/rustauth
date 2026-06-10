//! Last login method plugin.

mod config;
mod cookie;
mod persistence;
mod resolve;
mod schema;

use openauth_core::plugin::{AuthPlugin, PluginAfterHookAction};

pub use config::{
    LastLoginMethodOptions, DEFAULT_COOKIE_MAX_AGE, DEFAULT_COOKIE_NAME,
    DEFAULT_DATABASE_FIELD_NAME,
};
pub use resolve::{default_login_method, LoginMethodContext};

pub const UPSTREAM_PLUGIN_ID: &str = "last-login-method";

#[must_use]
pub fn last_login_method() -> AuthPlugin {
    last_login_method_with(LastLoginMethodOptions::default())
}

#[must_use]
pub fn last_login_method_with(options: LastLoginMethodOptions) -> AuthPlugin {
    let hook_options = options.clone();
    let init_options = options;
    AuthPlugin::new(UPSTREAM_PLUGIN_ID)
        .with_version(crate::VERSION)
        .with_init(move |_context| Ok(schema::init_output(&init_options)))
        .with_async_after_hook("*", move |context, request, response| {
            let options = hook_options.clone();
            Box::pin(async move {
                let response =
                    cookie::set_last_login_method_cookie(context, request, response, &options)?;
                if let Err(error) =
                    persistence::persist_last_login_method(context, request, &options).await
                {
                    let message = error.to_string();
                    context
                        .logger
                        .error("Failed to update last_login_method", &[message.as_str()]);
                }
                Ok(PluginAfterHookAction::Continue(response))
            })
        })
}
