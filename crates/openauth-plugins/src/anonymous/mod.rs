//! Anonymous authentication plugin.

mod cookies;
mod endpoints;
mod errors;
mod fields;
mod hooks;
mod model;
mod options;
mod response;
mod schema;

pub use errors::{AnonymousError, ANONYMOUS_ERROR_CODES};
pub use hooks::AnonymousLinkAccount;
pub use model::{AnonymousSession, AnonymousUser, LinkedSession};
pub use options::AnonymousOptions;

use openauth_core::plugin::AuthPlugin;
use openauth_core::{
    db::{DbFieldType, DbValue},
    options::UserAdditionalField,
    plugin::PluginInitOutput,
};

pub const UPSTREAM_PLUGIN_ID: &str = "anonymous";

pub fn anonymous(options: AnonymousOptions) -> AuthPlugin {
    let init_options = options.clone();
    let mut plugin = AuthPlugin::new(UPSTREAM_PLUGIN_ID)
        .with_version(env!("CARGO_PKG_VERSION"))
        .with_schema(schema::user_is_anonymous_schema(
            options.field_name.as_deref(),
        ))
        .with_init(move |_| {
            Ok(PluginInitOutput::new().user_additional_field(
                "is_anonymous",
                UserAdditionalField::new(DbFieldType::Boolean)
                    .optional()
                    .generated()
                    .default_value(DbValue::Boolean(false))
                    .db_name(init_options.storage_field_name()),
            ))
        })
        .with_endpoint(endpoints::sign_in_anonymous_endpoint(options.clone()))
        .with_endpoint(endpoints::delete_anonymous_user_endpoint(options.clone()));

    for code in errors::error_codes() {
        plugin = plugin.with_error_code(code);
    }
    hooks::attach_link_hooks(plugin, options)
}
