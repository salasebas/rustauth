use indexmap::IndexMap;
use rustauth_core::db::{DbField, DbFieldType, DbTable, ForeignKey, OnDelete};
use rustauth_core::plugin::PluginSchemaContribution;

use crate::options::SsoOptions;

pub const SSO_PROVIDER_MODEL: &str = "sso_provider";

pub fn contributions(options: &SsoOptions) -> Vec<PluginSchemaContribution> {
    vec![PluginSchemaContribution::table(
        options.model_name.clone(),
        provider_table(options),
    )]
}

fn provider_table(options: &SsoOptions) -> DbTable {
    let mut fields = IndexMap::new();
    fields.insert("id".to_owned(), DbField::new("id", DbFieldType::String));
    fields.insert(
        "issuer".to_owned(),
        DbField::new("issuer", DbFieldType::String),
    );
    fields.insert(
        "oidc_config".to_owned(),
        DbField::new("oidc_config", DbFieldType::String)
            .optional()
            .hidden(),
    );
    fields.insert(
        "saml_config".to_owned(),
        DbField::new("saml_config", DbFieldType::String)
            .optional()
            .hidden(),
    );
    fields.insert(
        "user_id".to_owned(),
        DbField::new("user_id", DbFieldType::String)
            .indexed()
            .references(ForeignKey::new("users", "id", OnDelete::Cascade)),
    );
    fields.insert(
        "provider_id".to_owned(),
        DbField::new("provider_id", DbFieldType::String).unique(),
    );
    fields.insert(
        "organization_id".to_owned(),
        DbField::new("organization_id", DbFieldType::String)
            .optional()
            .indexed(),
    );
    fields.insert(
        "domain".to_owned(),
        DbField::new("domain", DbFieldType::String).indexed(),
    );
    if options.domain_verification.enabled {
        fields.insert(
            "domain_verified".to_owned(),
            DbField::new("domain_verified", DbFieldType::Boolean).optional(),
        );
    }
    fields.insert(
        "created_at".to_owned(),
        DbField::new("created_at", DbFieldType::Timestamp)
            .optional()
            .generated(),
    );
    fields.insert(
        "updated_at".to_owned(),
        DbField::new("updated_at", DbFieldType::Timestamp)
            .optional()
            .generated(),
    );

    DbTable {
        name: options.provider_table.clone(),
        fields,
        order: Some(30),
    }
}
