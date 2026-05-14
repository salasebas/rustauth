use openauth_core::db::{DbField, DbFieldType};
use openauth_core::plugin::PluginSchemaContribution;

use super::config::{LastLoginMethodOptions, DEFAULT_DATABASE_FIELD_NAME};

pub fn schema_contribution(options: &LastLoginMethodOptions) -> Option<PluginSchemaContribution> {
    options.store_in_database.then(|| {
        PluginSchemaContribution::field(
            "user",
            DEFAULT_DATABASE_FIELD_NAME,
            DbField::new(options.effective_database_field_name(), DbFieldType::String)
                .optional()
                .generated(),
        )
    })
}
