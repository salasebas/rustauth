//! Last login method plugin.

mod config;
mod cookie;
mod resolve;
mod schema;

use openauth_core::plugin::AuthPlugin;

pub use config::{
    LastLoginMethodOptions, DEFAULT_COOKIE_MAX_AGE, DEFAULT_COOKIE_NAME,
    DEFAULT_DATABASE_FIELD_NAME,
};
pub use resolve::{default_login_method, LoginMethodContext};

pub const UPSTREAM_PLUGIN_ID: &str = "last-login-method";

pub fn last_login_method(options: LastLoginMethodOptions) -> AuthPlugin {
    let response_options = options.clone();
    let mut plugin = AuthPlugin::new(UPSTREAM_PLUGIN_ID)
        .with_version(crate::VERSION)
        .with_on_response(move |context, request, response| {
            cookie::set_last_login_method_cookie(context, request, response, &response_options)
        });

    if let Some(contribution) = schema::schema_contribution(&options) {
        plugin = plugin.with_schema(contribution);
    }

    plugin
}
