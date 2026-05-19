use indexmap::IndexMap;
use openauth_core::db::{DbField, DbFieldType, DbTable, ForeignKey, OnDelete};
use openauth_core::plugin::PluginSchemaContribution;

use crate::options::SsoOptions;

pub const SSO_PROVIDER_MODEL: &str = "ssoProvider";

pub fn contributions(options: &SsoOptions) -> Vec<PluginSchemaContribution> {
    vec![PluginSchemaContribution::table(
        SSO_PROVIDER_MODEL,
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
        "oidcConfig".to_owned(),
        DbField::new("oidc_config", DbFieldType::String)
            .optional()
            .hidden(),
    );
    fields.insert(
        "samlConfig".to_owned(),
        DbField::new("saml_config", DbFieldType::String)
            .optional()
            .hidden(),
    );
    fields.insert(
        "userId".to_owned(),
        DbField::new("user_id", DbFieldType::String)
            .indexed()
            .references(ForeignKey::new("users", "id", OnDelete::Cascade)),
    );
    fields.insert(
        "providerId".to_owned(),
        DbField::new("provider_id", DbFieldType::String).unique(),
    );
    fields.insert(
        "organizationId".to_owned(),
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
            "domainVerified".to_owned(),
            DbField::new("domain_verified", DbFieldType::Boolean).optional(),
        );
    }
    fields.insert(
        "createdAt".to_owned(),
        DbField::new("created_at", DbFieldType::Timestamp)
            .optional()
            .generated(),
    );
    fields.insert(
        "updatedAt".to_owned(),
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
