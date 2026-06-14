use indexmap::IndexMap;
use rustauth_core::db::{DbField, DbFieldType, DbTable, ForeignKey, OnDelete, TableOptions};
use rustauth_core::plugin::PluginSchemaContribution;

use super::OrganizationOptions;

pub fn schema_contributions(options: &OrganizationOptions) -> Vec<PluginSchemaContribution> {
    let mut contributions = vec![
        PluginSchemaContribution::table(
            "organization",
            table(
                &options.schema.organization,
                "organizations",
                Some(20),
                [
                    ("id", DbField::new("id", DbFieldType::String)),
                    ("name", DbField::new("name", DbFieldType::String)),
                    (
                        "slug",
                        DbField::new("slug", DbFieldType::String).unique().indexed(),
                    ),
                    ("logo", DbField::new("logo", DbFieldType::String).optional()),
                    (
                        "metadata",
                        DbField::new("metadata", DbFieldType::Json).optional(),
                    ),
                    (
                        "created_at",
                        DbField::new("created_at", DbFieldType::Timestamp),
                    ),
                    (
                        "updated_at",
                        DbField::new("updated_at", DbFieldType::Timestamp).optional(),
                    ),
                ],
            ),
        ),
        PluginSchemaContribution::table(
            "member",
            table(
                &options.schema.member,
                "members",
                Some(21),
                [
                    ("id", DbField::new("id", DbFieldType::String)),
                    (
                        "organization_id",
                        DbField::new("organization_id", DbFieldType::String)
                            .indexed()
                            .references(ForeignKey::new(
                                table_name(&options.schema.organization, "organizations"),
                                "id",
                                OnDelete::Cascade,
                            )),
                    ),
                    (
                        "user_id",
                        DbField::new("user_id", DbFieldType::String)
                            .indexed()
                            .references(ForeignKey::new("users", "id", OnDelete::Cascade)),
                    ),
                    ("role", DbField::new("role", DbFieldType::String)),
                    (
                        "created_at",
                        DbField::new("created_at", DbFieldType::Timestamp),
                    ),
                ],
            ),
        ),
        PluginSchemaContribution::table(
            "invitation",
            table(
                &options.schema.invitation,
                "invitations",
                Some(22),
                [
                    ("id", DbField::new("id", DbFieldType::String)),
                    (
                        "organization_id",
                        DbField::new("organization_id", DbFieldType::String)
                            .indexed()
                            .references(ForeignKey::new(
                                table_name(&options.schema.organization, "organizations"),
                                "id",
                                OnDelete::Cascade,
                            )),
                    ),
                    (
                        "email",
                        DbField::new("email", DbFieldType::String).indexed(),
                    ),
                    ("role", DbField::new("role", DbFieldType::String)),
                    (
                        "status",
                        DbField::new("status", DbFieldType::String).indexed(),
                    ),
                    (
                        "expires_at",
                        DbField::new("expires_at", DbFieldType::Timestamp),
                    ),
                    (
                        "created_at",
                        DbField::new("created_at", DbFieldType::Timestamp),
                    ),
                    (
                        "inviter_id",
                        DbField::new("inviter_id", DbFieldType::String)
                            .indexed()
                            .references(ForeignKey::new("users", "id", OnDelete::Cascade)),
                    ),
                    (
                        "team_id",
                        DbField::new("team_id", DbFieldType::String).optional(),
                    ),
                ],
            ),
        ),
    ];
    if options.teams.enabled {
        contributions.extend(team_schema_contributions(options));
    }
    if options.dynamic_access_control.enabled {
        contributions.push(organization_role_schema_contribution(options));
    }
    contributions
}

fn team_schema_contributions(options: &OrganizationOptions) -> Vec<PluginSchemaContribution> {
    vec![
        PluginSchemaContribution::table(
            "team",
            table(
                &options.schema.team,
                "teams",
                Some(23),
                [
                    ("id", DbField::new("id", DbFieldType::String)),
                    ("name", DbField::new("name", DbFieldType::String)),
                    (
                        "organization_id",
                        DbField::new("organization_id", DbFieldType::String)
                            .indexed()
                            .references(ForeignKey::new(
                                table_name(&options.schema.organization, "organizations"),
                                "id",
                                OnDelete::Cascade,
                            )),
                    ),
                    (
                        "created_at",
                        DbField::new("created_at", DbFieldType::Timestamp),
                    ),
                    (
                        "updated_at",
                        DbField::new("updated_at", DbFieldType::Timestamp).optional(),
                    ),
                ],
            ),
        ),
        PluginSchemaContribution::table(
            "team_member",
            table(
                &options.schema.team_member,
                "team_members",
                Some(24),
                [
                    ("id", DbField::new("id", DbFieldType::String)),
                    (
                        "team_id",
                        DbField::new("team_id", DbFieldType::String)
                            .indexed()
                            .references(ForeignKey::new(
                                table_name(&options.schema.team, "teams"),
                                "id",
                                OnDelete::Cascade,
                            )),
                    ),
                    (
                        "user_id",
                        DbField::new("user_id", DbFieldType::String)
                            .indexed()
                            .references(ForeignKey::new("users", "id", OnDelete::Cascade)),
                    ),
                    (
                        "created_at",
                        DbField::new("created_at", DbFieldType::Timestamp),
                    ),
                ],
            ),
        ),
    ]
}

fn organization_role_schema_contribution(
    options: &OrganizationOptions,
) -> PluginSchemaContribution {
    PluginSchemaContribution::table(
        "organization_role",
        table(
            &options.schema.organization_role,
            "organization_roles",
            Some(25),
            [
                ("id", DbField::new("id", DbFieldType::String)),
                (
                    "organization_id",
                    DbField::new("organization_id", DbFieldType::String)
                        .indexed()
                        .references(ForeignKey::new(
                            table_name(&options.schema.organization, "organizations"),
                            "id",
                            OnDelete::Cascade,
                        )),
                ),
                ("role", DbField::new("role", DbFieldType::String).indexed()),
                ("permission", DbField::new("permission", DbFieldType::Json)),
                (
                    "created_at",
                    DbField::new("created_at", DbFieldType::Timestamp),
                ),
                (
                    "updated_at",
                    DbField::new("updated_at", DbFieldType::Timestamp).optional(),
                ),
            ],
        ),
    )
}

fn table<const N: usize>(
    options: &TableOptions,
    name: &str,
    order: Option<u16>,
    fields: [(&str, DbField); N],
) -> DbTable {
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
        name: table_name(options, name),
        fields,
        order,
    }
}

fn table_name(options: &TableOptions, default_name: &str) -> String {
    options
        .name
        .clone()
        .unwrap_or_else(|| default_name.to_owned())
}
