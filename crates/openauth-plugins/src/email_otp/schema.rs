use openauth_core::api::{BodyField, BodySchema, JsonSchemaType};

use super::endpoints::{
    CHANGE_EMAIL_PATH, CHECK_PATH, REQUEST_CHANGE_EMAIL_PATH, RESET_PASSWORD_PATH, SEND_PATH,
    SIGN_IN_PATH, VERIFY_EMAIL_PATH,
};

pub(super) fn common_schema(path: &str) -> BodySchema {
    match path {
        SEND_PATH => BodySchema::object([
            BodyField::new("email", JsonSchemaType::String),
            BodyField::new("type", JsonSchemaType::String),
        ]),
        CHECK_PATH => BodySchema::object([
            BodyField::new("email", JsonSchemaType::String),
            BodyField::new("type", JsonSchemaType::String),
            BodyField::new("otp", JsonSchemaType::String),
        ]),
        VERIFY_EMAIL_PATH => BodySchema::object([
            BodyField::new("email", JsonSchemaType::String),
            BodyField::new("otp", JsonSchemaType::String),
        ]),
        SIGN_IN_PATH => BodySchema::object([
            BodyField::new("email", JsonSchemaType::String),
            BodyField::new("otp", JsonSchemaType::String),
            BodyField::optional("name", JsonSchemaType::String),
            BodyField::optional("image", JsonSchemaType::String),
        ]),
        RESET_PASSWORD_PATH => BodySchema::object([
            BodyField::new("email", JsonSchemaType::String),
            BodyField::new("otp", JsonSchemaType::String),
            BodyField::new("password", JsonSchemaType::String),
        ]),
        REQUEST_CHANGE_EMAIL_PATH => BodySchema::object([
            BodyField::new("newEmail", JsonSchemaType::String),
            BodyField::optional("otp", JsonSchemaType::String),
        ]),
        CHANGE_EMAIL_PATH => BodySchema::object([
            BodyField::new("newEmail", JsonSchemaType::String),
            BodyField::new("otp", JsonSchemaType::String),
        ]),
        _ => BodySchema::object([BodyField::new("email", JsonSchemaType::String)]),
    }
}
