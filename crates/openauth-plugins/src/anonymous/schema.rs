use openauth_core::db::{DbField, DbFieldType};
use openauth_core::plugin::PluginSchemaContribution;

pub fn user_is_anonymous_schema(field_name: Option<&str>) -> PluginSchemaContribution {
    PluginSchemaContribution::field(
        "user",
        "is_anonymous",
        DbField::new(field_name.unwrap_or("is_anonymous"), DbFieldType::Boolean)
            .optional()
            .generated(),
    )
}
