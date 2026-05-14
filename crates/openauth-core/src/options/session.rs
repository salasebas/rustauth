use std::collections::BTreeMap;

use crate::db::DbFieldType;

use super::cookies::CookieCacheOptions;

/// Session configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionOptions {
    pub expires_in: Option<u64>,
    pub update_age: Option<u64>,
    pub fresh_age: Option<u64>,
    pub cookie_cache: CookieCacheOptions,
    pub additional_fields: BTreeMap<String, SessionAdditionalField>,
}

/// Runtime metadata for custom session fields accepted by `/update-session`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAdditionalField {
    pub field_type: DbFieldType,
    pub input: bool,
    pub returned: bool,
}

impl SessionAdditionalField {
    pub fn new(field_type: DbFieldType) -> Self {
        Self {
            field_type,
            input: true,
            returned: true,
        }
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
}
