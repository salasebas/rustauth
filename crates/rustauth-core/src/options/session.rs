use std::collections::BTreeMap;

use time::Duration;

use crate::db::{DbFieldType, DbValue};

use super::cookies::CookieCacheOptions;
use super::model_schema::ModelSchemaOptions;

/// Session configuration.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SessionOptions {
    pub schema: ModelSchemaOptions,
    pub expires_in: Option<Duration>,
    pub update_age: Option<Duration>,
    pub fresh_age: Option<Duration>,
    pub disable_session_refresh: bool,
    pub defer_session_refresh: bool,
    pub store_session_in_database: bool,
    pub preserve_session_in_database: bool,
    pub cookie_cache: CookieCacheOptions,
    pub additional_fields: BTreeMap<String, SessionAdditionalField>,
}

impl SessionOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn builder() -> Self {
        Self::new()
    }

    #[must_use]
    pub fn schema(mut self, schema: ModelSchemaOptions) -> Self {
        self.schema = schema;
        self
    }

    #[must_use]
    pub fn expires_in(mut self, expires_in: Duration) -> Self {
        self.expires_in = Some(expires_in);
        self
    }

    #[must_use]
    pub fn update_age(mut self, update_age: Duration) -> Self {
        self.update_age = Some(update_age);
        self
    }

    #[must_use]
    pub fn fresh_age(mut self, fresh_age: Duration) -> Self {
        self.fresh_age = Some(fresh_age);
        self
    }

    #[must_use]
    pub fn disable_session_refresh(mut self, disabled: bool) -> Self {
        self.disable_session_refresh = disabled;
        self
    }

    #[must_use]
    pub fn defer_session_refresh(mut self, deferred: bool) -> Self {
        self.defer_session_refresh = deferred;
        self
    }

    #[must_use]
    pub fn store_session_in_database(mut self, enabled: bool) -> Self {
        self.store_session_in_database = enabled;
        self
    }

    #[must_use]
    pub fn preserve_session_in_database(mut self, enabled: bool) -> Self {
        self.preserve_session_in_database = enabled;
        self
    }

    #[must_use]
    pub fn cookie_cache(mut self, cookie_cache: CookieCacheOptions) -> Self {
        self.cookie_cache = cookie_cache;
        self
    }

    #[must_use]
    pub fn additional_field(
        mut self,
        name: impl Into<String>,
        field: SessionAdditionalField,
    ) -> Self {
        self.additional_fields.insert(name.into(), field);
        self
    }
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
