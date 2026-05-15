use std::collections::BTreeMap;

use crate::db::{DbFieldType, DbValue};

use super::cookies::CookieCacheOptions;

/// Session configuration.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SessionOptions {
    pub expires_in: Option<u64>,
    pub update_age: Option<u64>,
    pub fresh_age: Option<u64>,
    pub cookie_cache: CookieCacheOptions,
    pub additional_fields: BTreeMap<String, SessionAdditionalField>,
}

/// Runtime metadata for custom session fields accepted by `/update-session`.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionAdditionalField {
    pub field_type: DbFieldType,
    pub required: bool,
    pub input: bool,
    pub returned: bool,
    pub default_value: Option<DbValue>,
    pub db_name: Option<String>,
}

impl SessionAdditionalField {
    pub fn new(field_type: DbFieldType) -> Self {
        Self {
            field_type,
            required: true,
            input: true,
            returned: true,
            default_value: None,
            db_name: None,
        }
    }

    #[must_use]
    pub fn optional(mut self) -> Self {
        self.required = false;
        self
    }

    #[must_use]
    pub fn generated(mut self) -> Self {
        self.input = false;
        self
    }

    #[must_use]
    pub fn hidden(mut self) -> Self {
        self.returned = false;
        self
    }

    #[must_use]
    pub fn default_value(mut self, value: DbValue) -> Self {
        self.default_value = Some(value);
        self
    }

    #[must_use]
    pub fn db_name(mut self, db_name: impl Into<String>) -> Self {
        self.db_name = Some(db_name.into());
        self
    }
}
