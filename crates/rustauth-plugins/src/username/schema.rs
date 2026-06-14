use rustauth_core::db::{DbField, DbFieldType, TableOptions};
use rustauth_core::plugin::PluginSchemaContribution;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UsernameSchemaOptions {
    pub user: TableOptions,
}

pub fn username_field(options: &UsernameSchemaOptions) -> PluginSchemaContribution {
    PluginSchemaContribution::field(
        "user",
        "username",
        DbField::new(
            options
                .user
                .field_names
                .get("username")
                .cloned()
                .unwrap_or_else(|| "username".to_owned()),
            DbFieldType::String,
        )
        .optional()
        .unique(),
    )
}

pub fn display_username_field(options: &UsernameSchemaOptions) -> PluginSchemaContribution {
    PluginSchemaContribution::field(
        "user",
        "display_username",
        DbField::new(
            options
                .user
                .field_names
                .get("displayUsername")
                .cloned()
                .unwrap_or_else(|| "display_username".to_owned()),
            DbFieldType::String,
        )
        .optional(),
    )
}
