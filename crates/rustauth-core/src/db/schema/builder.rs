use indexmap::IndexMap;

use super::{
    AuthSchemaOptions, DbField, DbFieldType, DbSchema, DbTable, ForeignKey, OnDelete,
    RateLimitStorage, TableOptions,
};

/// Build RustAuth's core database schema metadata.
pub fn auth_schema(options: AuthSchemaOptions) -> DbSchema {
    let mut schema = DbSchema::default();
    let user_table_name = table_name(&options.user, "users");
    let id_field = options.id_policy.field();

    schema.insert(
        "user",
        table(
            &options.user,
            "users",
            Some(1),
            [
                ("id", options.id_policy.field()),
                ("name", field(&options.user, "name", DbFieldType::String)),
                (
                    "email",
                    field(&options.user, "email", DbFieldType::String).unique(),
                ),
                (
                    "email_verified",
                    field(&options.user, "email_verified", DbFieldType::Boolean).generated(),
                ),
                (
                    "image",
                    field(&options.user, "image", DbFieldType::String).optional(),
                ),
                (
                    "created_at",
                    field(&options.user, "created_at", DbFieldType::Timestamp).generated(),
                ),
                (
                    "updated_at",
                    field(&options.user, "updated_at", DbFieldType::Timestamp).generated(),
                ),
            ],
        ),
    );

    if !options.has_secondary_storage || options.store_session_in_database {
        schema.insert(
            "session",
            table(
                &options.session,
                "sessions",
                Some(2),
                [
                    ("id", options.id_policy.field()),
                    (
                        "expires_at",
                        field(&options.session, "expires_at", DbFieldType::Timestamp),
                    ),
                    (
                        "token",
                        field(&options.session, "token", DbFieldType::String).unique(),
                    ),
                    (
                        "created_at",
                        field(&options.session, "created_at", DbFieldType::Timestamp).generated(),
                    ),
                    (
                        "updated_at",
                        field(&options.session, "updated_at", DbFieldType::Timestamp).generated(),
                    ),
                    (
                        "ip_address",
                        field(&options.session, "ip_address", DbFieldType::String).optional(),
                    ),
                    (
                        "user_agent",
                        field(&options.session, "user_agent", DbFieldType::String).optional(),
                    ),
                    (
                        "user_id",
                        id_reference_field(&options.session, "user_id", &id_field)
                            .indexed()
                            .references(ForeignKey::new(
                                user_table_name.clone(),
                                "id",
                                OnDelete::Cascade,
                            )),
                    ),
                ],
            ),
        );
    }

    schema.insert(
        "account",
        table(
            &options.account,
            "accounts",
            Some(3),
            [
                ("id", options.id_policy.field()),
                (
                    "account_id",
                    field(&options.account, "account_id", DbFieldType::String),
                ),
                (
                    "provider_id",
                    field(&options.account, "provider_id", DbFieldType::String),
                ),
                (
                    "user_id",
                    id_reference_field(&options.account, "user_id", &id_field)
                        .indexed()
                        .references(ForeignKey::new(user_table_name, "id", OnDelete::Cascade)),
                ),
                (
                    "access_token",
                    field(&options.account, "access_token", DbFieldType::String)
                        .optional()
                        .hidden(),
                ),
                (
                    "refresh_token",
                    field(&options.account, "refresh_token", DbFieldType::String)
                        .optional()
                        .hidden(),
                ),
                (
                    "id_token",
                    field(&options.account, "id_token", DbFieldType::String)
                        .optional()
                        .hidden(),
                ),
                (
                    "access_token_expires_at",
                    field(
                        &options.account,
                        "access_token_expires_at",
                        DbFieldType::Timestamp,
                    )
                    .optional()
                    .hidden(),
                ),
                (
                    "refresh_token_expires_at",
                    field(
                        &options.account,
                        "refresh_token_expires_at",
                        DbFieldType::Timestamp,
                    )
                    .optional()
                    .hidden(),
                ),
                (
                    "scope",
                    field(&options.account, "scope", DbFieldType::String).optional(),
                ),
                (
                    "password",
                    field(&options.account, "password", DbFieldType::String)
                        .optional()
                        .hidden(),
                ),
                (
                    "created_at",
                    field(&options.account, "created_at", DbFieldType::Timestamp).generated(),
                ),
                (
                    "updated_at",
                    field(&options.account, "updated_at", DbFieldType::Timestamp).generated(),
                ),
            ],
        ),
    );

    if !options.has_secondary_storage || options.store_verification_in_database {
        schema.insert(
            "verification",
            table(
                &options.verification,
                "verifications",
                Some(4),
                [
                    ("id", options.id_policy.field()),
                    (
                        "identifier",
                        field(&options.verification, "identifier", DbFieldType::String).indexed(),
                    ),
                    (
                        "value",
                        field(&options.verification, "value", DbFieldType::String),
                    ),
                    (
                        "expires_at",
                        field(&options.verification, "expires_at", DbFieldType::Timestamp),
                    ),
                    (
                        "created_at",
                        field(&options.verification, "created_at", DbFieldType::Timestamp)
                            .generated(),
                    ),
                    (
                        "updated_at",
                        field(&options.verification, "updated_at", DbFieldType::Timestamp)
                            .generated(),
                    ),
                ],
            ),
        );
    }

    if options.rate_limit_storage == RateLimitStorage::Database {
        schema.insert(
            "rate_limit",
            table(
                &options.rate_limit,
                "rate_limits",
                None,
                [
                    (
                        "key",
                        field(&options.rate_limit, "key", DbFieldType::String).unique(),
                    ),
                    (
                        "count",
                        field(&options.rate_limit, "count", DbFieldType::Number),
                    ),
                    (
                        "last_request",
                        field(&options.rate_limit, "last_request", DbFieldType::Number),
                    ),
                ],
            ),
        );
    }

    schema
}

fn table<const N: usize>(
    options: &TableOptions,
    default_name: &str,
    order: Option<u16>,
    fields: [(&str, DbField); N],
) -> DbTable {
    let mut mapped_fields = fields
        .into_iter()
        .map(|(logical_name, field)| (logical_name.to_owned(), field))
        .collect::<IndexMap<_, _>>();
    mapped_fields.extend(options.additional_fields.clone());

    DbTable {
        name: table_name(options, default_name),
        fields: mapped_fields,
        order,
    }
}

fn table_name(options: &TableOptions, default_name: &str) -> String {
    options
        .name
        .clone()
        .unwrap_or_else(|| default_name.to_owned())
}

fn field(options: &TableOptions, logical_name: &str, field_type: DbFieldType) -> DbField {
    DbField::new(options.field_name(logical_name), field_type)
}

fn id_reference_field(options: &TableOptions, logical_name: &str, id_field: &DbField) -> DbField {
    let mut field = field(options, logical_name, id_field.field_type.clone());
    field.generated_id = id_field.generated_id;
    field
}
