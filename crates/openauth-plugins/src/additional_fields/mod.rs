//! Additional fields plugin.

use std::collections::BTreeMap;

use openauth_core::db::{DbField, DbFieldType, DbValue};
use openauth_core::options::{SessionAdditionalField, UserAdditionalField};
use openauth_core::plugin::{AuthPlugin, PluginInitOutput, PluginSchemaContribution};

pub const UPSTREAM_PLUGIN_ID: &str = "additional-fields";

#[derive(Debug, Clone, Default, PartialEq)]
pub struct AdditionalFieldsOptions {
    pub user: BTreeMap<String, AdditionalField>,
    pub session: BTreeMap<String, AdditionalField>,
}

impl AdditionalFieldsOptions {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn user_field(mut self, name: impl Into<String>, field: AdditionalField) -> Self {
        self.user.insert(name.into(), field);
        self
    }

    #[must_use]
    pub fn session_field(mut self, name: impl Into<String>, field: AdditionalField) -> Self {
        self.session.insert(name.into(), field);
        self
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AdditionalField {
    pub field_type: DbFieldType,
    pub required: bool,
    pub input: bool,
    pub returned: bool,
    pub unique: bool,
    pub index: bool,
    pub default_value: Option<DbValue>,
    pub db_name: Option<String>,
}

impl AdditionalField {
    pub fn new(field_type: DbFieldType) -> Self {
        Self {
            field_type,
            required: true,
            input: true,
            returned: true,
            unique: false,
            index: false,
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
    pub fn unique(mut self) -> Self {
        self.unique = true;
        self
    }

    #[must_use]
    pub fn indexed(mut self) -> Self {
        self.index = true;
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

pub fn additional_fields(options: AdditionalFieldsOptions) -> AuthPlugin {
    AuthPlugin::new(UPSTREAM_PLUGIN_ID).with_init(move |_context| {
        let mut output = PluginInitOutput::new();
        for (name, field) in &options.user {
            output = output
                .schema(PluginSchemaContribution::field(
                    "user",
                    name.clone(),
                    field.schema_field(name),
                ))
                .user_additional_field(name.clone(), field.user_runtime_field());
        }
        for (name, field) in &options.session {
            output = output
                .schema(PluginSchemaContribution::field(
                    "session",
                    name.clone(),
                    field.schema_field(name),
                ))
                .session_additional_field(name.clone(), field.session_runtime_field());
        }
        Ok(output)
    })
}

impl AdditionalField {
    fn schema_field(&self, logical_name: &str) -> DbField {
        let mut field = DbField::new(
            self.db_name
                .clone()
                .unwrap_or_else(|| logical_name.to_owned()),
            self.field_type.clone(),
        );
        if !self.required {
            field = field.optional();
        }
        if self.unique {
            field = field.unique();
        }
        if self.index {
            field = field.indexed();
        }
        if !self.returned {
            field = field.hidden();
        }
        if !self.input {
            field = field.generated();
        }
        field
    }

    fn user_runtime_field(&self) -> UserAdditionalField {
        let mut field = UserAdditionalField::new(self.field_type.clone());
        field.required = self.required;
        field.input = self.input;
        field.returned = self.returned;
        field.default_value = self.default_value.clone();
        field.db_name = self.db_name.clone();
        field
    }

    fn session_runtime_field(&self) -> SessionAdditionalField {
        let mut field = SessionAdditionalField::new(self.field_type.clone());
        field.required = self.required;
        field.input = self.input;
        field.returned = self.returned;
        field.default_value = self.default_value.clone();
        field.db_name = self.db_name.clone();
        field
    }
}
