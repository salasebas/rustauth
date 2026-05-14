use serde::{Deserialize, Serialize};

/// Database adapter capability metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterCapabilities {
    pub adapter_id: String,
    pub adapter_name: Option<String>,
    pub supports_numeric_ids: bool,
    pub supports_uuid_ids: bool,
    pub supports_json: bool,
    pub supports_dates: bool,
    pub supports_booleans: bool,
    pub supports_arrays: bool,
    pub supports_joins: bool,
    pub supports_transactions: bool,
    pub disable_id_generation: bool,
}

impl AdapterCapabilities {
    pub fn new(adapter_id: impl Into<String>) -> Self {
        Self {
            adapter_id: adapter_id.into(),
            adapter_name: None,
            supports_numeric_ids: true,
            supports_uuid_ids: false,
            supports_json: false,
            supports_dates: true,
            supports_booleans: true,
            supports_arrays: false,
            supports_joins: false,
            supports_transactions: false,
            disable_id_generation: false,
        }
    }

    pub fn named(mut self, adapter_name: impl Into<String>) -> Self {
        self.adapter_name = Some(adapter_name.into());
        self
    }

    pub fn without_numeric_ids(mut self) -> Self {
        self.supports_numeric_ids = false;
        self
    }

    pub fn with_uuid_ids(mut self) -> Self {
        self.supports_uuid_ids = true;
        self
    }

    pub fn with_json(mut self) -> Self {
        self.supports_json = true;
        self
    }

    pub fn without_dates(mut self) -> Self {
        self.supports_dates = false;
        self
    }

    pub fn without_booleans(mut self) -> Self {
        self.supports_booleans = false;
        self
    }

    pub fn with_arrays(mut self) -> Self {
        self.supports_arrays = true;
        self
    }

    pub fn with_joins(mut self) -> Self {
        self.supports_joins = true;
        self
    }

    pub fn with_transactions(mut self) -> Self {
        self.supports_transactions = true;
        self
    }

    pub fn without_id_generation(mut self) -> Self {
        self.disable_id_generation = true;
        self
    }
}

/// Schema file content produced by an adapter or migration generator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaCreation {
    pub path: String,
    pub code: String,
    pub append: bool,
    pub overwrite: bool,
}

impl SchemaCreation {
    pub fn new(path: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            code: code.into(),
            append: false,
            overwrite: false,
        }
    }

    pub fn append(mut self) -> Self {
        self.append = true;
        self
    }

    pub fn overwrite(mut self) -> Self {
        self.overwrite = true;
        self
    }
}
