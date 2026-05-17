use indexmap::IndexMap;
use openauth_core::db::{DbField, DbFieldType, DbTable, ForeignKey, OnDelete};
use openauth_core::plugin::PluginSchemaContribution;

pub const OAUTH_CLIENT_MODEL: &str = "oauth_client";
pub const OAUTH_REFRESH_TOKEN_MODEL: &str = "oauth_refresh_token";
pub const OAUTH_ACCESS_TOKEN_MODEL: &str = "oauth_access_token";
pub const OAUTH_CONSENT_MODEL: &str = "oauth_consent";

/// Database schema contributions for the OAuth provider plugin.
pub fn oauth_provider_schema() -> Vec<PluginSchemaContribution> {
    vec![
        PluginSchemaContribution::table(
            OAUTH_CLIENT_MODEL,
            table(
                "oauth_clients",
                Some(20),
                [
                    ("id", field("id", DbFieldType::String)),
                    (
                        "client_id",
                        field("client_id", DbFieldType::String).unique(),
                    ),
                    (
                        "client_secret",
                        field("client_secret", DbFieldType::String)
                            .optional()
                            .hidden(),
                    ),
                    (
                        "client_secret_expires_at",
                        field("client_secret_expires_at", DbFieldType::Timestamp)
                            .optional()
                            .hidden(),
                    ),
                    (
                        "disabled",
                        field("disabled", DbFieldType::Boolean).optional(),
                    ),
                    (
                        "skip_consent",
                        field("skip_consent", DbFieldType::Boolean).optional(),
                    ),
                    (
                        "enable_end_session",
                        field("enable_end_session", DbFieldType::Boolean).optional(),
                    ),
                    (
                        "subject_type",
                        field("subject_type", DbFieldType::String).optional(),
                    ),
                    (
                        "scopes",
                        field("scopes", DbFieldType::StringArray).optional(),
                    ),
                    (
                        "user_id",
                        field("user_id", DbFieldType::String)
                            .optional()
                            .indexed()
                            .references(ForeignKey::new("users", "id", OnDelete::SetNull)),
                    ),
                    (
                        "created_at",
                        field("created_at", DbFieldType::Timestamp).generated(),
                    ),
                    (
                        "updated_at",
                        field("updated_at", DbFieldType::Timestamp).generated(),
                    ),
                    ("name", field("name", DbFieldType::String).optional()),
                    ("uri", field("uri", DbFieldType::String).optional()),
                    ("icon", field("icon", DbFieldType::String).optional()),
                    (
                        "contacts",
                        field("contacts", DbFieldType::StringArray).optional(),
                    ),
                    ("tos", field("tos", DbFieldType::String).optional()),
                    ("policy", field("policy", DbFieldType::String).optional()),
                    (
                        "software_id",
                        field("software_id", DbFieldType::String).optional(),
                    ),
                    (
                        "software_version",
                        field("software_version", DbFieldType::String).optional(),
                    ),
                    (
                        "software_statement",
                        field("software_statement", DbFieldType::String).optional(),
                    ),
                    (
                        "redirect_uris",
                        field("redirect_uris", DbFieldType::StringArray),
                    ),
                    (
                        "post_logout_redirect_uris",
                        field("post_logout_redirect_uris", DbFieldType::StringArray).optional(),
                    ),
                    (
                        "token_endpoint_auth_method",
                        field("token_endpoint_auth_method", DbFieldType::String).optional(),
                    ),
                    (
                        "grant_types",
                        field("grant_types", DbFieldType::StringArray).optional(),
                    ),
                    (
                        "response_types",
                        field("response_types", DbFieldType::StringArray).optional(),
                    ),
                    ("public", field("public", DbFieldType::Boolean).optional()),
                    ("type", field("type", DbFieldType::String).optional()),
                    (
                        "require_pkce",
                        field("require_pkce", DbFieldType::Boolean).optional(),
                    ),
                    (
                        "reference_id",
                        field("reference_id", DbFieldType::String)
                            .optional()
                            .indexed(),
                    ),
                    ("metadata", field("metadata", DbFieldType::Json).optional()),
                ],
            ),
        ),
        PluginSchemaContribution::table(
            OAUTH_REFRESH_TOKEN_MODEL,
            table(
                "oauth_refresh_tokens",
                Some(21),
                [
                    ("id", field("id", DbFieldType::String)),
                    (
                        "token",
                        field("token", DbFieldType::String).indexed().hidden(),
                    ),
                    (
                        "client_id",
                        field("client_id", DbFieldType::String)
                            .indexed()
                            .references(ForeignKey::new(
                                "oauth_clients",
                                "client_id",
                                OnDelete::Cascade,
                            )),
                    ),
                    (
                        "session_id",
                        field("session_id", DbFieldType::String)
                            .optional()
                            .references(ForeignKey::new("sessions", "id", OnDelete::SetNull)),
                    ),
                    (
                        "user_id",
                        field("user_id", DbFieldType::String)
                            .indexed()
                            .references(ForeignKey::new("users", "id", OnDelete::Cascade)),
                    ),
                    (
                        "reference_id",
                        field("reference_id", DbFieldType::String).optional(),
                    ),
                    ("expires_at", field("expires_at", DbFieldType::Timestamp)),
                    (
                        "created_at",
                        field("created_at", DbFieldType::Timestamp).generated(),
                    ),
                    (
                        "revoked",
                        field("revoked", DbFieldType::Timestamp).optional(),
                    ),
                    (
                        "auth_time",
                        field("auth_time", DbFieldType::Timestamp).optional(),
                    ),
                    ("scopes", field("scopes", DbFieldType::StringArray)),
                ],
            ),
        ),
        PluginSchemaContribution::table(
            OAUTH_ACCESS_TOKEN_MODEL,
            table(
                "oauth_access_tokens",
                Some(22),
                [
                    ("id", field("id", DbFieldType::String)),
                    (
                        "token",
                        field("token", DbFieldType::String).unique().hidden(),
                    ),
                    (
                        "client_id",
                        field("client_id", DbFieldType::String)
                            .indexed()
                            .references(ForeignKey::new(
                                "oauth_clients",
                                "client_id",
                                OnDelete::Cascade,
                            )),
                    ),
                    (
                        "session_id",
                        field("session_id", DbFieldType::String)
                            .optional()
                            .references(ForeignKey::new("sessions", "id", OnDelete::SetNull)),
                    ),
                    (
                        "user_id",
                        field("user_id", DbFieldType::String)
                            .optional()
                            .indexed()
                            .references(ForeignKey::new("users", "id", OnDelete::SetNull)),
                    ),
                    (
                        "reference_id",
                        field("reference_id", DbFieldType::String).optional(),
                    ),
                    (
                        "refresh_id",
                        field("refresh_id", DbFieldType::String)
                            .optional()
                            .references(ForeignKey::new(
                                "oauth_refresh_tokens",
                                "id",
                                OnDelete::Cascade,
                            )),
                    ),
                    ("expires_at", field("expires_at", DbFieldType::Timestamp)),
                    (
                        "created_at",
                        field("created_at", DbFieldType::Timestamp).generated(),
                    ),
                    ("scopes", field("scopes", DbFieldType::StringArray)),
                ],
            ),
        ),
        PluginSchemaContribution::table(
            OAUTH_CONSENT_MODEL,
            table(
                "oauth_consents",
                Some(23),
                [
                    ("id", field("id", DbFieldType::String)),
                    (
                        "client_id",
                        field("client_id", DbFieldType::String)
                            .indexed()
                            .references(ForeignKey::new(
                                "oauth_clients",
                                "client_id",
                                OnDelete::Cascade,
                            )),
                    ),
                    (
                        "user_id",
                        field("user_id", DbFieldType::String)
                            .optional()
                            .indexed()
                            .references(ForeignKey::new("users", "id", OnDelete::Cascade)),
                    ),
                    (
                        "reference_id",
                        field("reference_id", DbFieldType::String).optional(),
                    ),
                    ("scopes", field("scopes", DbFieldType::StringArray)),
                    (
                        "created_at",
                        field("created_at", DbFieldType::Timestamp).generated(),
                    ),
                    (
                        "updated_at",
                        field("updated_at", DbFieldType::Timestamp).generated(),
                    ),
                ],
            ),
        ),
    ]
}

fn table<const N: usize>(name: &str, order: Option<u16>, fields: [(&str, DbField); N]) -> DbTable {
    DbTable {
        name: name.to_owned(),
        fields: fields
            .into_iter()
            .map(|(logical_name, field)| (logical_name.to_owned(), field))
            .collect::<IndexMap<_, _>>(),
        order,
    }
}

fn field(name: &str, field_type: DbFieldType) -> DbField {
    DbField::new(name, field_type)
}
