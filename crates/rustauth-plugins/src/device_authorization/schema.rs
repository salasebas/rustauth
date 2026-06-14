use indexmap::IndexMap;
use rustauth_core::db::{DbField, DbFieldType, DbTable};
use rustauth_core::plugin::PluginSchemaContribution;

use super::options::{DeviceAuthorizationSchemaFields, DeviceAuthorizationSchemaOptions};

pub const DEVICE_CODE_MODEL: &str = "device_code";

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
            "device_code",
            DbField::new(
                field_name(&options.device_code, DEFAULT_DEVICE_CODE),
                DbFieldType::String,
            )
            .unique(),
        ),
        (
            "user_code",
            DbField::new(
                field_name(&options.user_code, DEFAULT_USER_CODE),
                DbFieldType::String,
            )
            .unique()
            .indexed(),
        ),
        (
            "user_id",
            DbField::new(
                field_name(&options.user_id, DEFAULT_USER_ID),
                DbFieldType::String,
            )
            .optional()
            .indexed(),
        ),
        (
            "expires_at",
            DbField::new(
                field_name(&options.expires_at, DEFAULT_EXPIRES_AT),
                DbFieldType::Timestamp,
            ),
        ),
        (
            "status",
            DbField::new(field_name(&options.status, "status"), DbFieldType::String),
        ),
        (
            "last_polled_at",
            DbField::new(
                field_name(&options.last_polled_at, DEFAULT_LAST_POLLED_AT),
                DbFieldType::Timestamp,
            )
            .optional(),
        ),
        (
            "polling_interval",
            DbField::new(
                field_name(&options.polling_interval, DEFAULT_POLLING_INTERVAL),
                DbFieldType::Number,
            )
            .optional(),
        ),
        (
            "client_id",
            DbField::new(
                field_name(&options.client_id, DEFAULT_CLIENT_ID),
                DbFieldType::String,
            )
            .optional(),
        ),
        (
            "scope",
            DbField::new(field_name(&options.scope, "scope"), DbFieldType::String).optional(),
        ),
        (
            "created_at",
            DbField::new(
                field_name(&options.created_at, DEFAULT_CREATED_AT),
                DbFieldType::Timestamp,
            )
            .generated(),
        ),
        (
            "updated_at",
            DbField::new(
                field_name(&options.updated_at, DEFAULT_UPDATED_AT),
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

const DEFAULT_DEVICE_CODE: &str = "device_code";
const DEFAULT_USER_CODE: &str = "user_code";
const DEFAULT_USER_ID: &str = "user_id";
const DEFAULT_EXPIRES_AT: &str = "expires_at";
const DEFAULT_LAST_POLLED_AT: &str = "last_polled_at";
const DEFAULT_POLLING_INTERVAL: &str = "polling_interval";
const DEFAULT_CLIENT_ID: &str = "client_id";
const DEFAULT_CREATED_AT: &str = "created_at";
const DEFAULT_UPDATED_AT: &str = "updated_at";
