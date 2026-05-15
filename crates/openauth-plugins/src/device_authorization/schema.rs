use indexmap::IndexMap;
use openauth_core::db::{DbField, DbFieldType, DbTable};
use openauth_core::plugin::PluginSchemaContribution;

use super::options::{DeviceAuthorizationSchemaFields, DeviceAuthorizationSchemaOptions};

pub const DEVICE_CODE_MODEL: &str = "deviceCode";

pub fn device_code_table(options: &DeviceAuthorizationSchemaOptions) -> PluginSchemaContribution {
    PluginSchemaContribution::table(
        DEVICE_CODE_MODEL,
        DbTable {
            name: options
                .table_name
                .clone()
                .unwrap_or_else(|| "device_codes".to_owned()),
            order: Some(10),
            fields: fields(&options.fields),
        },
    )
}

fn fields(options: &DeviceAuthorizationSchemaFields) -> IndexMap<String, DbField> {
    [
        (
            "id",
            DbField::new(field_name(&options.id, "id"), DbFieldType::String),
        ),
        (
            "deviceCode",
            DbField::new(
                field_name(&options.device_code, "deviceCode"),
                DbFieldType::String,
            )
            .unique(),
        ),
        (
            "userCode",
            DbField::new(
                field_name(&options.user_code, "userCode"),
                DbFieldType::String,
            )
            .unique()
            .indexed(),
        ),
        (
            "userId",
            DbField::new(field_name(&options.user_id, "userId"), DbFieldType::String)
                .optional()
                .indexed(),
        ),
        (
            "expiresAt",
            DbField::new(
                field_name(&options.expires_at, "expiresAt"),
                DbFieldType::Timestamp,
            ),
        ),
        (
            "status",
            DbField::new(field_name(&options.status, "status"), DbFieldType::String),
        ),
        (
            "lastPolledAt",
            DbField::new(
                field_name(&options.last_polled_at, "lastPolledAt"),
                DbFieldType::Timestamp,
            )
            .optional(),
        ),
        (
            "pollingInterval",
            DbField::new(
                field_name(&options.polling_interval, "pollingInterval"),
                DbFieldType::Number,
            )
            .optional(),
        ),
        (
            "clientId",
            DbField::new(
                field_name(&options.client_id, "clientId"),
                DbFieldType::String,
            )
            .optional(),
        ),
        (
            "scope",
            DbField::new(field_name(&options.scope, "scope"), DbFieldType::String).optional(),
        ),
        (
            "createdAt",
            DbField::new(
                field_name(&options.created_at, "createdAt"),
                DbFieldType::Timestamp,
            )
            .generated(),
        ),
        (
            "updatedAt",
            DbField::new(
                field_name(&options.updated_at, "updatedAt"),
                DbFieldType::Timestamp,
            )
            .generated(),
        ),
    ]
    .into_iter()
    .map(|(name, field)| (name.to_owned(), field))
    .collect()
}

fn field_name<'a>(configured: &'a Option<String>, default: &'static str) -> &'a str {
    configured.as_deref().unwrap_or(default)
}
