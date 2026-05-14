use std::collections::BTreeMap;

use crate::db::{DbFieldType, DbValue};

/// User lifecycle configuration.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct UserOptions {
    pub change_email: ChangeEmailOptions,
    pub delete_user: DeleteUserOptions,
    pub additional_fields: BTreeMap<String, UserAdditionalField>,
}

/// Runtime metadata for custom user fields accepted by user-writing endpoints.
#[derive(Debug, Clone, PartialEq)]
pub struct UserAdditionalField {
    pub field_type: DbFieldType,
    pub required: bool,
    pub input: bool,
    pub returned: bool,
    pub default_value: Option<DbValue>,
}

impl UserAdditionalField {
    pub fn new(field_type: DbFieldType) -> Self {
        Self {
            field_type,
            required: true,
            input: true,
            returned: true,
            default_value: None,
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
}

/// Email change behavior.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangeEmailOptions {
    pub enabled: bool,
    pub update_email_without_verification: bool,
}

/// User deletion behavior.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeleteUserOptions {
    pub enabled: bool,
}
