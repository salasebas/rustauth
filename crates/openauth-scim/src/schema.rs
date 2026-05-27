//! SCIM database schema contributions.

use indexmap::IndexMap;
use openauth_core::db::{DbField, DbFieldType, DbTable, ForeignKey, OnDelete};
use openauth_core::plugin::PluginSchemaContribution;

pub const SCIM_PROVIDER_MODEL: &str = "scimProvider";
pub const SCIM_USER_PROFILE_MODEL: &str = "scimUserProfile";
pub const SCIM_GROUP_PROFILE_MODEL: &str = "scimGroupProfile";

pub fn contributions() -> Vec<PluginSchemaContribution> {
    vec![
        PluginSchemaContribution::table(SCIM_PROVIDER_MODEL, scim_provider_table()),
        PluginSchemaContribution::table(SCIM_USER_PROFILE_MODEL, scim_user_profile_table()),
        PluginSchemaContribution::table(SCIM_GROUP_PROFILE_MODEL, scim_group_profile_table()),
    ]
}

fn scim_provider_table() -> DbTable {
    let mut fields = IndexMap::new();
    fields.insert("id".to_owned(), DbField::new("id", DbFieldType::String));
    // Globally unique provider id, matching Better Auth: one SCIM connection row per
    // logical IdP integration. Use distinct ids (for example `okta` vs `okta-org-a`)
    // when you need separate tokens or scopes; organization scope lives on the row.
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

fn scim_user_profile_table() -> DbTable {
    let mut fields = IndexMap::new();
    fields.insert("id".to_owned(), DbField::new("id", DbFieldType::String));
    fields.insert(
        "providerId".to_owned(),
        DbField::new("provider_id", DbFieldType::String).indexed(),
    );
    fields.insert(
        "userId".to_owned(),
        DbField::new("user_id", DbFieldType::String)
            .indexed()
            .references(ForeignKey::new("users", "id", OnDelete::Cascade)),
    );
    fields.insert(
        "externalId".to_owned(),
        DbField::new("external_id", DbFieldType::String).optional(),
    );
    fields.insert(
        "attributes".to_owned(),
        DbField::new("attributes", DbFieldType::Json).optional(),
    );
    fields.insert(
        "version".to_owned(),
        DbField::new("version", DbFieldType::String).optional(),
    );
    fields.insert(
        "createdAt".to_owned(),
        DbField::new("created_at", DbFieldType::Timestamp).generated(),
    );
    fields.insert(
        "updatedAt".to_owned(),
        DbField::new("updated_at", DbFieldType::Timestamp).generated(),
    );

    DbTable {
        name: "scim_user_profiles".to_owned(),
        fields,
        order: Some(31),
    }
}

fn scim_group_profile_table() -> DbTable {
    let mut fields = IndexMap::new();
    fields.insert("id".to_owned(), DbField::new("id", DbFieldType::String));
    fields.insert(
        "providerId".to_owned(),
        DbField::new("provider_id", DbFieldType::String).indexed(),
    );
    fields.insert(
        "organizationId".to_owned(),
        DbField::new("organization_id", DbFieldType::String).indexed(),
    );
    fields.insert(
        "teamId".to_owned(),
        DbField::new("team_id", DbFieldType::String).indexed(),
    );
    fields.insert(
        "externalId".to_owned(),
        DbField::new("external_id", DbFieldType::String).optional(),
    );
    fields.insert(
        "attributes".to_owned(),
        DbField::new("attributes", DbFieldType::Json).optional(),
    );
    fields.insert(
        "version".to_owned(),
        DbField::new("version", DbFieldType::String).optional(),
    );
    fields.insert(
        "createdAt".to_owned(),
        DbField::new("created_at", DbFieldType::Timestamp).generated(),
    );
    fields.insert(
        "updatedAt".to_owned(),
        DbField::new("updated_at", DbFieldType::Timestamp).generated(),
    );

    DbTable {
        name: "scim_group_profiles".to_owned(),
        fields,
        order: Some(32),
    }
}
