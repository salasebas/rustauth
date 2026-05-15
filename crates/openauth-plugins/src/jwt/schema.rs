use indexmap::IndexMap;
use openauth_core::db::{DbField, DbFieldType, DbTable};
use openauth_core::plugin::PluginSchemaContribution;

pub(crate) fn jwks_schema() -> PluginSchemaContribution {
    let mut fields = IndexMap::new();
    fields.insert("id".to_owned(), DbField::new("id", DbFieldType::String));
    fields.insert(
        "public_key".to_owned(),
        DbField::new("public_key", DbFieldType::String),
    );
    fields.insert(
        "private_key".to_owned(),
        DbField::new("private_key", DbFieldType::String),
    );
    fields.insert(
        "created_at".to_owned(),
        DbField::new("created_at", DbFieldType::Timestamp),
    );
    fields.insert(
        "expires_at".to_owned(),
        DbField::new("expires_at", DbFieldType::Timestamp).optional(),
    );
    fields.insert(
        "alg".to_owned(),
        DbField::new("alg", DbFieldType::String).optional(),
    );
    fields.insert(
        "crv".to_owned(),
        DbField::new("crv", DbFieldType::String).optional(),
    );

    PluginSchemaContribution::table(
        "jwks",
        DbTable {
            name: "jwks".to_owned(),
            fields,
            order: None,
        },
    )
}
