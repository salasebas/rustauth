use openauth_core::db::{DbField, DbFieldType};
use openauth_core::options::UserAdditionalField;
use openauth_core::plugin::{PluginInitOutput, PluginSchemaContribution};

use super::config::{LastLoginMethodOptions, DEFAULT_DATABASE_FIELD_NAME};

pub fn init_output(options: &LastLoginMethodOptions) -> PluginInitOutput {
    if !options.store_in_database {
        return PluginInitOutput::new();
    }

    PluginInitOutput::new()
        .schema(PluginSchemaContribution::field(
            "user",
            DEFAULT_DATABASE_FIELD_NAME,
            DbField::new(options.effective_database_field_name(), DbFieldType::String)
                .optional()
                .generated(),
        ))
        .user_additional_field(
            DEFAULT_DATABASE_FIELD_NAME,
            UserAdditionalField::new(DbFieldType::String)
                .optional()
                .generated(),
        )
}
