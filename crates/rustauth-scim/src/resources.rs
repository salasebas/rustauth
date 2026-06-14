//! SCIM resource mapping.

use std::collections::BTreeMap;

use rustauth_core::db::{Account, User};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::mappings::resource_url;
use crate::metadata::{SCIM_GROUP_SCHEMA_ID, SCIM_USER_SCHEMA_ID};

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
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub groups: Vec<ScimUserResourceGroup>,
    pub schemas: Vec<String>,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty", default)]
    pub additional_fields: BTreeMap<String, serde_json::Value>,
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
pub struct ScimUserResourceGroup {
    pub value: String,
    #[serde(rename = "$ref")]
    pub ref_: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimGroupResource {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    pub meta: ScimResourceMeta,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub members: Vec<ScimGroupResourceMember>,
    pub schemas: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScimGroupResourceMember {
    pub value: String,
    #[serde(rename = "$ref")]
    pub ref_: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
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
            version: Some(resource_version(user.updated_at)),
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
        groups: Vec::new(),
        schemas: vec![SCIM_USER_SCHEMA_ID.to_owned()],
        additional_fields: BTreeMap::new(),
    }
}

pub fn group_resource(
    base_url: &str,
    group_id: &str,
    external_id: Option<String>,
    display_name: String,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    members: Vec<ScimGroupResourceMember>,
) -> ScimGroupResource {
    ScimGroupResource {
        id: group_id.to_owned(),
        external_id,
        meta: ScimResourceMeta {
            resource_type: "Group".to_owned(),
            created: created_at,
            last_modified: updated_at,
            location: resource_url(base_url, &format!("/scim/v2/Groups/{group_id}")),
            version: Some(resource_version(updated_at)),
        },
        display_name,
        members,
        schemas: vec![SCIM_GROUP_SCHEMA_ID.to_owned()],
    }
}

pub fn group_member_resource(
    base_url: &str,
    user_id: &str,
    display: Option<String>,
) -> ScimGroupResourceMember {
    ScimGroupResourceMember {
        value: user_id.to_owned(),
        ref_: resource_url(base_url, &format!("/scim/v2/Users/{user_id}")),
        display,
    }
}

pub fn resource_version(updated_at: OffsetDateTime) -> String {
    format!(r#"W/"{}""#, updated_at.unix_timestamp_nanos())
}
