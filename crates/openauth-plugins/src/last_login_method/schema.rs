use openauth_core::options::UserAdditionalField;
use openauth_core::plugin::PluginInitOutput;

use super::config::{LastLoginMethodOptions, DEFAULT_DATABASE_FIELD_NAME};

pub fn init_output(options: &LastLoginMethodOptions) -> PluginInitOutput {
    if !options.store_in_database {
        return PluginInitOutput::new();
    }

    PluginInitOutput::new().user_additional_field(
        DEFAULT_DATABASE_FIELD_NAME,
        UserAdditionalField::new(openauth_core::db::DbFieldType::String)
            .optional()
            .generated()
            .db_name(options.effective_database_field_name()),
    )
}
