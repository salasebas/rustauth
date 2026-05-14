use openauth_core::db::{DbField, DbFieldType};
use openauth_core::plugin::PluginSchemaContribution;

pub fn username_field() -> PluginSchemaContribution {
    PluginSchemaContribution::field(
        "user",
        "username",
        DbField::new("username", DbFieldType::String)
            .optional()
            .unique(),
    )
}

pub fn display_username_field() -> PluginSchemaContribution {
    PluginSchemaContribution::field(
        "user",
        "display_username",
        DbField::new("display_username", DbFieldType::String).optional(),
    )
}
