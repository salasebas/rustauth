use indexmap::IndexMap;
use openauth_core::db::{DbField, DbFieldType, DbTable, ForeignKey, OnDelete};
use openauth_core::plugin::PluginSchemaContribution;

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
        self.field_names.insert(logical_name.into(), db_name.into());
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
        for logical_name in ["userId", "address", "chainId", "isPrimary", "createdAt"] {
            if let Some(db_name) = self.field_names.get(logical_name) {
                fields.insert(
                    logical_name.to_owned(),
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

pub(crate) fn wallet_address_schema(options: &SiweSchemaOptions) -> PluginSchemaContribution {
    let mut fields = IndexMap::new();
    fields.insert(
        "id".to_owned(),
        DbField::new("id", DbFieldType::String).generated(),
    );
    fields.insert(
        "userId".to_owned(),
        DbField::new(options.field_name_or_default("userId"), DbFieldType::String)
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
        "chainId".to_owned(),
        DbField::new(
            options.field_name_or_default("chainId"),
            DbFieldType::Number,
        ),
    );
    fields.insert(
        "isPrimary".to_owned(),
        DbField::new(
            options.field_name_or_default("isPrimary"),
            DbFieldType::Boolean,
        ),
    );
    fields.insert(
        "createdAt".to_owned(),
        DbField::new(
            options.field_name_or_default("createdAt"),
            DbFieldType::Timestamp,
        )
        .generated(),
    );

    PluginSchemaContribution::table(
        "walletAddress",
        DbTable {
            name: options.table_name_or_default(),
            fields,
            order: Some(20),
        },
    )
}
