use openauth_core::api::{BodyField, BodySchema, JsonSchemaType};

pub fn provider_id_body_schema() -> BodySchema {
    BodySchema::object([BodyField::new("providerId", JsonSchemaType::String)])
}

pub fn register_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("providerId", JsonSchemaType::String),
        BodyField::new("issuer", JsonSchemaType::String).format("uri"),
        BodyField::new("domain", JsonSchemaType::String),
        BodyField::optional("organizationId", JsonSchemaType::String),
        BodyField::optional("oidcConfig", JsonSchemaType::Object),
        BodyField::optional("samlConfig", JsonSchemaType::Object),
    ])
}

pub fn update_provider_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("providerId", JsonSchemaType::String),
        BodyField::optional("issuer", JsonSchemaType::String).format("uri"),
        BodyField::optional("domain", JsonSchemaType::String),
        BodyField::optional("organizationId", JsonSchemaType::String),
        BodyField::optional("oidcConfig", JsonSchemaType::Object),
        BodyField::optional("samlConfig", JsonSchemaType::Object),
    ])
}

pub fn sign_in_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::optional("email", JsonSchemaType::String).format("email"),
        BodyField::optional("domain", JsonSchemaType::String),
        BodyField::optional("providerId", JsonSchemaType::String),
        BodyField::optional("organizationSlug", JsonSchemaType::String),
        BodyField::optional("callbackURL", JsonSchemaType::String).format("uri"),
        BodyField::optional("errorCallbackURL", JsonSchemaType::String).format("uri"),
        BodyField::optional("newUserCallbackURL", JsonSchemaType::String).format("uri"),
        BodyField::optional("loginHint", JsonSchemaType::String),
        BodyField::optional("scopes", JsonSchemaType::Array),
        BodyField::optional("providerType", JsonSchemaType::String),
        BodyField::optional("requestSignUp", JsonSchemaType::Boolean),
    ])
}

pub fn saml_acs_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::optional("SAMLResponse", JsonSchemaType::String),
        BodyField::optional("RelayState", JsonSchemaType::String),
    ])
}

pub fn saml_slo_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::optional("SAMLRequest", JsonSchemaType::String),
        BodyField::optional("SAMLResponse", JsonSchemaType::String),
        BodyField::optional("RelayState", JsonSchemaType::String),
    ])
}

pub fn saml_logout_body_schema() -> BodySchema {
    BodySchema::object([BodyField::optional("callbackURL", JsonSchemaType::String).format("uri")])
}
