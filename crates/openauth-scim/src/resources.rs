//! SCIM resource mapping.

use openauth_core::db::{Account, User};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::mappings::resource_url;
use crate::metadata::SCIM_USER_SCHEMA_ID;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimUserResource {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    pub meta: ScimResourceMeta,
    #[serde(rename = "userName")]
    pub user_name: String,
    pub name: ScimUserResourceName,
    #[serde(rename = "displayName")]
    pub display_name: String,
    pub active: bool,
    pub emails: Vec<ScimUserResourceEmail>,
    pub schemas: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScimUserResourceName {
    pub formatted: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScimUserResourceEmail {
    pub primary: bool,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimResourceMeta {
    pub resource_type: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    pub location: String,
}

pub fn user_resource(base_url: &str, user: &User, account: Option<&Account>) -> ScimUserResource {
    ScimUserResource {
        id: user.id.clone(),
        external_id: account.map(|account| account.account_id.clone()),
        meta: ScimResourceMeta {
            resource_type: "User".to_owned(),
            created: user.created_at,
            last_modified: user.updated_at,
            location: resource_url(base_url, &format!("/scim/v2/Users/{}", user.id)),
        },
        user_name: user.email.clone(),
        name: ScimUserResourceName {
            formatted: user.name.clone(),
        },
        display_name: user.name.clone(),
        active: true,
        emails: vec![ScimUserResourceEmail {
            primary: true,
            value: user.email.clone(),
        }],
        schemas: vec![SCIM_USER_SCHEMA_ID.to_owned()],
    }
}
