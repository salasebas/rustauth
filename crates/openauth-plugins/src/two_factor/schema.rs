use indexmap::IndexMap;
use openauth_core::db::{DbField, DbFieldType, DbTable, ForeignKey, OnDelete};
use openauth_core::plugin::PluginSchemaContribution;

pub fn contributions(table_name: &str) -> Vec<PluginSchemaContribution> {
    vec![
        PluginSchemaContribution::field(
            "user",
            "two_factor_enabled",
            DbField::new("two_factor_enabled", DbFieldType::Boolean)
                .optional()
                .generated(),
        ),
        PluginSchemaContribution::table("twoFactor", two_factor_table(table_name)),
    ]
}

fn two_factor_table(name: &str) -> DbTable {
    let mut fields = IndexMap::new();
    fields.insert("id".to_owned(), DbField::new("id", DbFieldType::String));
    fields.insert(
        "secret".to_owned(),
        DbField::new("secret", DbFieldType::String)
            .indexed()
            .hidden(),
    );
    fields.insert(
        "backup_codes".to_owned(),
        DbField::new("backup_codes", DbFieldType::String).hidden(),
    );
    fields.insert(
        "user_id".to_owned(),
        DbField::new("user_id", DbFieldType::String)
            .indexed()
            .hidden()
            .references(ForeignKey::new("users", "id", OnDelete::Cascade)),
    );
    fields.insert(
        "verified".to_owned(),
        DbField::new("verified", DbFieldType::Boolean)
            .optional()
            .generated(),
    );
    DbTable {
        name: name.to_owned(),
        fields,
        order: Some(20),
    }
}
