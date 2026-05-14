use openauth_core::api::{AuthEndpointOptions, BodyField, BodySchema, JsonSchemaType};
use openauth_core::db::User;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub(super) struct PasswordBody {
    pub(super) password: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct EnableBody {
    pub(super) password: Option<String>,
    pub(super) issuer: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct CodeBody {
    pub(super) code: String,
    #[serde(default, alias = "trustDevice")]
    pub(super) trust_device: Option<bool>,
    #[serde(default, alias = "disableSession")]
    pub(super) disable_session: Option<bool>,
}

#[derive(Deserialize)]
pub(super) struct ViewBackupCodesBody {
    #[serde(alias = "userId")]
    pub(super) user_id: String,
}

#[derive(Serialize)]
pub(super) struct StatusBody {
    pub(super) status: bool,
}

#[derive(Serialize)]
pub(super) struct TokenUserBody {
    pub(super) token: String,
    pub(super) user: User,
}

#[derive(Serialize)]
pub(super) struct EnableBodyResponse {
    #[serde(rename = "totpURI")]
    pub(super) totp_uri: String,
    #[serde(rename = "backupCodes")]
    pub(super) backup_codes: Vec<String>,
}

#[derive(Serialize)]
pub(super) struct BackupCodesBody {
    pub(super) status: bool,
    #[serde(rename = "backupCodes")]
    pub(super) backup_codes: Vec<String>,
}

pub(super) fn body_options(schema: BodySchema) -> AuthEndpointOptions {
    AuthEndpointOptions::new()
        .allowed_media_types(["application/json"])
        .body_schema(schema)
}

pub(super) fn password_schema() -> BodySchema {
    BodySchema::object([BodyField::optional("password", JsonSchemaType::String)])
}

pub(super) fn password_issuer_schema() -> BodySchema {
    BodySchema::object([
        BodyField::optional("password", JsonSchemaType::String),
        BodyField::optional("issuer", JsonSchemaType::String),
    ])
}

pub(super) fn code_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("code", JsonSchemaType::String),
        BodyField::optional("trustDevice", JsonSchemaType::Boolean),
        BodyField::optional("disableSession", JsonSchemaType::Boolean),
    ])
}

pub(super) fn optional_trust_schema() -> BodySchema {
    BodySchema::object([BodyField::optional("trustDevice", JsonSchemaType::Boolean)])
}

pub(super) fn view_backup_codes_schema() -> BodySchema {
    BodySchema::object([BodyField::new("userId", JsonSchemaType::String)])
}
