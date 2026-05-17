use indexmap::IndexMap;
use openauth_core::db::{DbField, DbFieldType, DbTable, TableOptions};
use openauth_core::plugin::PluginSchemaContribution;

use super::{API_KEY_MODEL, API_KEY_TABLE};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApiKeySchemaOptions {
    pub table: TableOptions,
}

pub fn schema_contribution(options: &ApiKeySchemaOptions) -> PluginSchemaContribution {
    PluginSchemaContribution::table(
        API_KEY_MODEL,
        table(
            &options.table,
            [
                ("id", DbField::new("id", DbFieldType::String)),
                (
                    "config_id",
                    DbField::new("config_id", DbFieldType::String).indexed(),
                ),
                ("name", DbField::new("name", DbFieldType::String).optional()),
                (
                    "start",
                    DbField::new("start", DbFieldType::String).optional(),
                ),
                (
                    "prefix",
                    DbField::new("prefix", DbFieldType::String).optional(),
                ),
                ("key", DbField::new("key", DbFieldType::String).indexed()),
                (
                    "reference_id",
                    DbField::new("reference_id", DbFieldType::String).indexed(),
                ),
                (
                    "refill_interval",
                    DbField::new("refill_interval", DbFieldType::Number).optional(),
                ),
                (
                    "refill_amount",
                    DbField::new("refill_amount", DbFieldType::Number).optional(),
                ),
                (
                    "last_refill_at",
                    DbField::new("last_refill_at", DbFieldType::Timestamp).optional(),
                ),
                ("enabled", DbField::new("enabled", DbFieldType::Boolean)),
                (
                    "rate_limit_enabled",
                    DbField::new("rate_limit_enabled", DbFieldType::Boolean),
                ),
                (
                    "rate_limit_time_window",
                    DbField::new("rate_limit_time_window", DbFieldType::Number).optional(),
                ),
                (
                    "rate_limit_max",
                    DbField::new("rate_limit_max", DbFieldType::Number).optional(),
                ),
                (
                    "request_count",
                    DbField::new("request_count", DbFieldType::Number),
                ),
                (
                    "remaining",
                    DbField::new("remaining", DbFieldType::Number).optional(),
                ),
                (
                    "last_request",
                    DbField::new("last_request", DbFieldType::Timestamp).optional(),
                ),
                (
                    "expires_at",
                    DbField::new("expires_at", DbFieldType::Timestamp).optional(),
                ),
                (
                    "created_at",
                    DbField::new("created_at", DbFieldType::Timestamp),
                ),
                (
                    "updated_at",
                    DbField::new("updated_at", DbFieldType::Timestamp),
                ),
                (
                    "metadata",
                    DbField::new("metadata", DbFieldType::Json).optional(),
                ),
                (
                    "permissions",
                    DbField::new("permissions", DbFieldType::Json).optional(),
                ),
            ],
        ),
    )
}

fn table<const N: usize>(options: &TableOptions, fields: [(&str, DbField); N]) -> DbTable {
    let mut fields = fields
        .into_iter()
        .map(|(logical_name, mut field)| {
            if let Some(db_name) = options.field_names.get(logical_name) {
                field.name = db_name.clone();
            }
            (logical_name.to_owned(), field)
        })
        .collect::<IndexMap<_, _>>();
    fields.extend(options.additional_fields.clone());
    DbTable {
        name: options
            .name
            .clone()
            .unwrap_or_else(|| API_KEY_TABLE.to_owned()),
        fields,
        order: Some(30),
    }
}
