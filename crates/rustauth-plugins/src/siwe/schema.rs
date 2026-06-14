use indexmap::IndexMap;
use rustauth_core::db::{DbField, DbFieldType, DbTable, ForeignKey, OnDelete};
use rustauth_core::plugin::PluginSchemaContribution;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SiweSchemaOptions {
    table_name: Option<String>,
    field_names: IndexMap<String, String>,
}

impl SiweSchemaOptions {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn table_name(mut self, table_name: impl Into<String>) -> Self {
        self.table_name = Some(table_name.into());
        self
    }

    #[must_use]
    pub fn field_name(
        mut self,
        logical_name: impl Into<String>,
        db_name: impl Into<String>,
    ) -> Self {
        self.field_names.insert(
            normalize_logical_field(&logical_name.into()),
            db_name.into(),
        );
        self
    }

    fn table_name_or_default(&self) -> String {
        self.table_name
            .clone()
            .unwrap_or_else(|| "wallet_addresses".to_owned())
    }

    fn field_name_or_default(&self, logical_name: &str) -> String {
        self.field_names
            .get(logical_name)
            .cloned()
            .unwrap_or_else(|| logical_name.to_owned())
    }

    pub(crate) fn metadata(&self) -> serde_json::Value {
        let mut fields = serde_json::Map::new();
        for logical_name in ["user_id", "address", "chain_id", "is_primary", "created_at"] {
            if let Some(db_name) = self.field_names.get(logical_name) {
                fields.insert(
                    metadata_field_key(logical_name),
                    serde_json::Value::String(db_name.clone()),
                );
            }
        }
        serde_json::json!({
            "walletAddress": {
                "modelName": self.table_name_or_default(),
                "fields": fields,
            }
        })
    }
}

fn normalize_logical_field(logical_name: &str) -> String {
    match logical_name {
        "userId" => "user_id".to_owned(),
        "chainId" => "chain_id".to_owned(),
        "isPrimary" => "is_primary".to_owned(),
        "createdAt" => "created_at".to_owned(),
        other => other.to_owned(),
    }
}

fn metadata_field_key(logical_name: &str) -> String {
    match logical_name {
        "user_id" => "userId".to_owned(),
        "chain_id" => "chainId".to_owned(),
        "is_primary" => "isPrimary".to_owned(),
        "created_at" => "createdAt".to_owned(),
        other => other.to_owned(),
    }
}

pub(crate) fn wallet_address_schema(options: &SiweSchemaOptions) -> PluginSchemaContribution {
    let mut fields = IndexMap::new();
    fields.insert(
        "id".to_owned(),
        DbField::new("id", DbFieldType::String).generated(),
    );
    fields.insert(
        "user_id".to_owned(),
        DbField::new(
            options.field_name_or_default("user_id"),
            DbFieldType::String,
        )
        .indexed()
        .references(ForeignKey::new("users", "id", OnDelete::Cascade)),
    );
    fields.insert(
        "address".to_owned(),
        DbField::new(
            options.field_name_or_default("address"),
            DbFieldType::String,
        ),
    );
    fields.insert(
        "chain_id".to_owned(),
        DbField::new(
            options.field_name_or_default("chain_id"),
            DbFieldType::Number,
        ),
    );
    fields.insert(
        "is_primary".to_owned(),
        DbField::new(
            options.field_name_or_default("is_primary"),
            DbFieldType::Boolean,
        ),
    );
    fields.insert(
        "created_at".to_owned(),
        DbField::new(
            options.field_name_or_default("created_at"),
            DbFieldType::Timestamp,
        )
        .generated(),
    );

    PluginSchemaContribution::table(
        "wallet_address",
        DbTable {
            name: options.table_name_or_default(),
            fields,
            order: Some(20),
        },
    )
}
