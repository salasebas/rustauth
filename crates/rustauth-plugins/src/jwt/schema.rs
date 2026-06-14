use indexmap::IndexMap;
use rustauth_core::db::{DbField, DbFieldType, DbTable, TableOptions};
use rustauth_core::plugin::PluginSchemaContribution;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JwtSchemaOptions {
    pub jwks: TableOptions,
}

pub(crate) fn jwks_schema(options: &JwtSchemaOptions) -> PluginSchemaContribution {
    let mut fields = IndexMap::new();
    fields.insert(
        "id".to_owned(),
        field(options, "id", DbField::new("id", DbFieldType::String)),
    );
    fields.insert(
        "public_key".to_owned(),
        field(
            options,
            "public_key",
            DbField::new("public_key", DbFieldType::String),
        ),
    );
    fields.insert(
        "private_key".to_owned(),
        field(
            options,
            "private_key",
            DbField::new("private_key", DbFieldType::String),
        ),
    );
    fields.insert(
        "created_at".to_owned(),
        field(
            options,
            "created_at",
            DbField::new("created_at", DbFieldType::Timestamp),
        ),
    );
    fields.insert(
        "expires_at".to_owned(),
        field(
            options,
            "expires_at",
            DbField::new("expires_at", DbFieldType::Timestamp).optional(),
        ),
    );
    fields.insert(
        "alg".to_owned(),
        field(
            options,
            "alg",
            DbField::new("alg", DbFieldType::String).optional(),
        ),
    );
    fields.insert(
        "crv".to_owned(),
        field(
            options,
            "crv",
            DbField::new("crv", DbFieldType::String).optional(),
        ),
    );

    PluginSchemaContribution::table(
        "jwks",
        DbTable {
            name: options
                .jwks
                .name
                .clone()
                .unwrap_or_else(|| "jwks".to_owned()),
            fields,
            order: None,
        },
    )
}

fn field(options: &JwtSchemaOptions, logical_name: &str, mut field: DbField) -> DbField {
    if let Some(db_name) = options.jwks.field_names.get(logical_name) {
        field.name = db_name.clone();
    }
    field
}
