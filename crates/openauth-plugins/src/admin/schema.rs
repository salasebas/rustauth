use openauth_core::db::{DbField, DbFieldType};
use openauth_core::plugin::PluginSchemaContribution;

use super::options::AdminSchemaOptions;

pub fn user_role_field(schema: &AdminSchemaOptions) -> PluginSchemaContribution {
    PluginSchemaContribution::field(
        "user",
        "role",
        DbField::new(&schema.user_role_field, DbFieldType::String)
            .optional()
            .generated(),
    )
}

pub fn user_banned_field(schema: &AdminSchemaOptions) -> PluginSchemaContribution {
    PluginSchemaContribution::field(
        "user",
        "banned",
        DbField::new(&schema.user_banned_field, DbFieldType::Boolean)
            .optional()
            .generated(),
    )
}

pub fn user_ban_reason_field(schema: &AdminSchemaOptions) -> PluginSchemaContribution {
    PluginSchemaContribution::field(
        "user",
        "ban_reason",
        DbField::new(&schema.user_ban_reason_field, DbFieldType::String)
            .optional()
            .generated(),
    )
}

pub fn user_ban_expires_field(schema: &AdminSchemaOptions) -> PluginSchemaContribution {
    PluginSchemaContribution::field(
        "user",
        "ban_expires",
        DbField::new(&schema.user_ban_expires_field, DbFieldType::Timestamp)
            .optional()
            .generated(),
    )
}

pub fn session_impersonated_by_field(schema: &AdminSchemaOptions) -> PluginSchemaContribution {
    PluginSchemaContribution::field(
        "session",
        "impersonated_by",
        DbField::new(&schema.session_impersonated_by_field, DbFieldType::String).optional(),
    )
}
