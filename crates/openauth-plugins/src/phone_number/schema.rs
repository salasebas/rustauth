use openauth_core::db::{DbField, DbFieldType};
use openauth_core::plugin::PluginSchemaContribution;

pub(crate) const PHONE_NUMBER_FIELD: &str = "phone_number";
pub(crate) const PHONE_NUMBER_VERIFIED_FIELD: &str = "phone_number_verified";

pub(crate) fn phone_number_field() -> PluginSchemaContribution {
    PluginSchemaContribution::field(
        "user",
        PHONE_NUMBER_FIELD,
        DbField::new(PHONE_NUMBER_FIELD, DbFieldType::String)
            .optional()
            .unique(),
    )
}

pub(crate) fn phone_number_verified_field() -> PluginSchemaContribution {
    PluginSchemaContribution::field(
        "user",
        PHONE_NUMBER_VERIFIED_FIELD,
        DbField::new(PHONE_NUMBER_VERIFIED_FIELD, DbFieldType::Boolean).optional(),
    )
}
