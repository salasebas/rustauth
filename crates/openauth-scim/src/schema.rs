//! SCIM database schema contributions.

use indexmap::IndexMap;
use openauth_core::db::{DbField, DbFieldType, DbTable, ForeignKey, OnDelete};
use openauth_core::plugin::PluginSchemaContribution;

pub const SCIM_PROVIDER_MODEL: &str = "scimProvider";

pub fn contributions() -> Vec<PluginSchemaContribution> {
    vec![PluginSchemaContribution::table(
        SCIM_PROVIDER_MODEL,
        scim_provider_table(),
    )]
}

fn scim_provider_table() -> DbTable {
    let mut fields = IndexMap::new();
    fields.insert("id".to_owned(), DbField::new("id", DbFieldType::String));
    fields.insert(
        "providerId".to_owned(),
        DbField::new("provider_id", DbFieldType::String).unique(),
    );
    fields.insert(
        "scimToken".to_owned(),
        DbField::new("scim_token", DbFieldType::String)
            .unique()
            .hidden(),
    );
    fields.insert(
        "organizationId".to_owned(),
        DbField::new("organization_id", DbFieldType::String)
            .optional()
            .indexed(),
    );
    fields.insert(
        "userId".to_owned(),
        DbField::new("user_id", DbFieldType::String)
            .optional()
            .indexed()
            .references(ForeignKey::new("users", "id", OnDelete::Cascade)),
    );

    DbTable {
        name: "scim_providers".to_owned(),
        fields,
        order: Some(30),
    }
}
