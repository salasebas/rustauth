//! One-time token plugin.

mod endpoints;
mod hashing;
mod headers;
mod options;

pub use hashing::default_key_hasher;
pub use options::{GenerateToken, HashToken, OneTimeTokenOptions, OneTimeTokenSession, StoreToken};

use openauth_core::plugin::AuthPlugin;
use openauth_core::plugin::PluginAfterHookAction;

pub const UPSTREAM_PLUGIN_ID: &str = "one-time-token";

pub fn one_time_token() -> AuthPlugin {
    one_time_token_with_options(OneTimeTokenOptions::default())
}

pub fn one_time_token_with_options(options: OneTimeTokenOptions) -> AuthPlugin {
    AuthPlugin::new(UPSTREAM_PLUGIN_ID)
        .with_version(crate::VERSION)
        .with_endpoint(endpoints::generate_endpoint(options.clone()))
        .with_endpoint(endpoints::verify_endpoint(options.clone()))
        .with_async_after_hook("*", move |context, _request, response| {
            let options = options.clone();
            Box::pin(async move {
                headers::set_ott_header_on_new_session(context, response, &options)
                    .await
                    .map(PluginAfterHookAction::Continue)
            })
        })
}
