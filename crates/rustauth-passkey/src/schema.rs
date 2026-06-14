use indexmap::IndexMap;
use rustauth_core::db::{DbField, DbFieldType, DbTable, ForeignKey, OnDelete};
use rustauth_core::plugin::PluginSchemaContribution;

use crate::options::PasskeyOptions;

pub fn contributions(options: &PasskeyOptions) -> Vec<PluginSchemaContribution> {
    vec![PluginSchemaContribution::table(
        "passkey",
        passkey_table(options),
    )]
}

fn passkey_table(options: &PasskeyOptions) -> DbTable {
    let mut fields = IndexMap::new();
    fields.insert("id".to_owned(), DbField::new("id", DbFieldType::String));
    fields.insert(
        "name".to_owned(),
        field(options, "name", DbFieldType::String).optional(),
    );
    fields.insert(
        "public_key".to_owned(),
        field(options, "public_key", DbFieldType::String),
    );
    fields.insert(
        "user_id".to_owned(),
        field(options, "user_id", DbFieldType::String)
            .indexed()
            .references(ForeignKey::new("users", "id", OnDelete::Cascade)),
    );
    fields.insert(
        "credential_id".to_owned(),
        field(options, "credential_id", DbFieldType::String)
            .indexed()
            .unique(),
    );
    fields.insert(
        "counter".to_owned(),
        field(options, "counter", DbFieldType::Number),
    );
    fields.insert(
        "device_type".to_owned(),
        field(options, "device_type", DbFieldType::String),
    );
    fields.insert(
        "backed_up".to_owned(),
        field(options, "backed_up", DbFieldType::Boolean),
    );
    fields.insert(
        "transports".to_owned(),
        field(options, "transports", DbFieldType::String).optional(),
    );
    fields.insert(
        "created_at".to_owned(),
        field(options, "created_at", DbFieldType::Timestamp)
            .optional()
            .generated(),
    );
    fields.insert(
        "aaguid".to_owned(),
        field(options, "aaguid", DbFieldType::String).optional(),
    );
    fields.insert(
        "webauthn_credential".to_owned(),
        field(options, "webauthn_credential", DbFieldType::Json).hidden(),
    );

    DbTable {
        name: options
            .schema
            .table_name_or(&options.passkey_table)
            .to_owned(),
        fields,
        order: Some(20),
    }
}

fn field(options: &PasskeyOptions, logical_name: &str, field_type: DbFieldType) -> DbField {
    DbField::new(
        options.schema.field_name_or(logical_name, logical_name),
        field_type,
    )
}
