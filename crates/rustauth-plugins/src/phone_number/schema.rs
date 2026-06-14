use rustauth_core::db::{DbField, DbFieldType, TableOptions};
use rustauth_core::plugin::PluginSchemaContribution;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PhoneNumberSchemaOptions {
    pub user: TableOptions,
}

pub(crate) const PHONE_NUMBER_FIELD: &str = "phone_number";
pub(crate) const PHONE_NUMBER_VERIFIED_FIELD: &str = "phone_number_verified";

pub(crate) fn phone_number_field(options: &PhoneNumberSchemaOptions) -> PluginSchemaContribution {
    PluginSchemaContribution::field(
        "user",
        PHONE_NUMBER_FIELD,
        DbField::new(
            options
                .user
                .field_names
                .get("phoneNumber")
                .or_else(|| options.user.field_names.get("phone_number"))
                .cloned()
                .unwrap_or_else(|| "phone_number".to_owned()),
            DbFieldType::String,
        )
        .optional()
        .unique(),
    )
}

pub(crate) fn phone_number_verified_field(
    options: &PhoneNumberSchemaOptions,
) -> PluginSchemaContribution {
    PluginSchemaContribution::field(
        "user",
        PHONE_NUMBER_VERIFIED_FIELD,
        DbField::new(
            options
                .user
                .field_names
                .get("phoneNumberVerified")
                .or_else(|| options.user.field_names.get("phone_number_verified"))
                .cloned()
                .unwrap_or_else(|| "phone_number_verified".to_owned()),
            DbFieldType::Boolean,
        )
        .optional(),
    )
}
