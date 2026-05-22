//! SCIM metadata resources.

use serde::{Deserialize, Serialize};

use crate::errors::ScimError;
use crate::mappings::resource_url;

pub const LIST_RESPONSE_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
pub const SCIM_USER_SCHEMA_ID: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const SCIM_SCHEMA_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Schema";
const SCIM_RESOURCE_TYPE_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:ResourceType";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceProviderConfig {
    pub patch: Supported,
    pub bulk: Supported,
    pub filter: Supported,
    #[serde(rename = "changePassword")]
    pub change_password: Supported,
    pub sort: Supported,
    pub etag: Supported,
    #[serde(rename = "authenticationSchemes")]
    pub authentication_schemes: Vec<AuthenticationScheme>,
    pub schemas: Vec<String>,
    pub meta: ServiceProviderMeta,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Supported {
    pub supported: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticationScheme {
    pub name: String,
    pub description: String,
    #[serde(rename = "specUri")]
    pub spec_uri: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub primary: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceProviderMeta {
    #[serde(rename = "resourceType")]
    pub resource_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListResponse<T> {
    pub schemas: Vec<String>,
    #[serde(rename = "totalResults")]
    pub total_results: usize,
    #[serde(rename = "startIndex")]
    pub start_index: usize,
    #[serde(rename = "itemsPerPage")]
    pub items_per_page: usize,
    #[serde(rename = "Resources")]
    pub resources: Vec<T>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScimSchema {
    pub id: String,
    pub schemas: Vec<String>,
    pub name: String,
    pub description: String,
    pub attributes: Vec<ScimSchemaAttribute>,
    pub meta: ScimMeta,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimSchemaAttribute {
    pub name: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub multi_valued: bool,
    pub description: String,
    pub required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub case_exact: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mutability: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub returned: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uniqueness: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub sub_attributes: Vec<ScimSchemaAttribute>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimMeta {
    pub resource_type: String,
    pub location: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceType {
    pub schemas: Vec<String>,
    pub id: String,
    pub name: String,
    pub endpoint: String,
    pub description: String,
    pub schema: String,
    pub meta: ScimMeta,
}

pub fn service_provider_config() -> ServiceProviderConfig {
    ServiceProviderConfig {
        patch: Supported { supported: true },
        bulk: Supported { supported: false },
        filter: Supported { supported: true },
        change_password: Supported { supported: false },
        sort: Supported { supported: false },
        etag: Supported { supported: false },
        authentication_schemes: vec![AuthenticationScheme {
            name: "OAuth Bearer Token".to_owned(),
            description:
                "Authentication scheme using the Authorization header with a bearer token tied to an organization."
                    .to_owned(),
            spec_uri: "http://www.rfc-editor.org/info/rfc6750".to_owned(),
            type_: "oauthbearertoken".to_owned(),
            primary: true,
        }],
        schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig".to_owned()],
        meta: ServiceProviderMeta {
            resource_type: "ServiceProviderConfig".to_owned(),
        },
    }
}

pub fn schemas(base_url: &str) -> ListResponse<ScimSchema> {
    let resources = vec![user_schema(base_url)];
    list_response(resources)
}

pub fn schema(base_url: &str, schema_id: &str) -> Result<ScimSchema, ScimError> {
    if schema_id == SCIM_USER_SCHEMA_ID {
        Ok(user_schema(base_url))
    } else {
        Err(ScimError::not_found("Schema not found"))
    }
}

pub fn resource_types(base_url: &str) -> ListResponse<ResourceType> {
    let resources = vec![user_resource_type(base_url)];
    list_response(resources)
}

pub fn resource_type(base_url: &str, resource_type_id: &str) -> Result<ResourceType, ScimError> {
    if resource_type_id == "User" {
        Ok(user_resource_type(base_url))
    } else {
        Err(ScimError::not_found("Resource type not found"))
    }
}

fn list_response<T>(resources: Vec<T>) -> ListResponse<T> {
    ListResponse {
        schemas: vec![LIST_RESPONSE_SCHEMA.to_owned()],
        total_results: resources.len(),
        start_index: 1,
        items_per_page: resources.len(),
        resources,
    }
}

fn user_schema(base_url: &str) -> ScimSchema {
    ScimSchema {
        id: SCIM_USER_SCHEMA_ID.to_owned(),
        schemas: vec![SCIM_SCHEMA_SCHEMA.to_owned()],
        name: "User".to_owned(),
        description: "User Account".to_owned(),
        attributes: user_attributes(),
        meta: ScimMeta {
            resource_type: "Schema".to_owned(),
            location: resource_url(
                base_url,
                "/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User",
            ),
        },
    }
}

fn user_resource_type(base_url: &str) -> ResourceType {
    ResourceType {
        schemas: vec![SCIM_RESOURCE_TYPE_SCHEMA.to_owned()],
        id: "User".to_owned(),
        name: "User".to_owned(),
        endpoint: "/Users".to_owned(),
        description: "User Account".to_owned(),
        schema: SCIM_USER_SCHEMA_ID.to_owned(),
        meta: ScimMeta {
            resource_type: "ResourceType".to_owned(),
            location: resource_url(base_url, "/scim/v2/ResourceTypes/User"),
        },
    }
}

fn user_attributes() -> Vec<ScimSchemaAttribute> {
    vec![
        attr("id", "string", false, "Unique opaque identifier for the User", false)
            .case_exact(true)
            .read_only()
            .uniqueness("server"),
        attr(
            "userName",
            "string",
            false,
            "Unique identifier for the User, typically used by the user to directly authenticate to the service provider",
            true,
        )
        .case_exact(false)
        .read_write()
        .uniqueness("server"),
        attr(
            "displayName",
            "string",
            false,
            "The name of the User, suitable for display to end-users.  The name SHOULD be the full name of the User being described, if known.",
            false,
        )
        .case_exact(true)
        .read_only()
        .uniqueness("none"),
        attr(
            "active",
            "boolean",
            false,
            "A Boolean value indicating the User's administrative status.",
            false,
        )
        .read_only(),
        attr("name", "complex", false, "The components of the user's real name.", false)
            .sub_attributes(vec![
                attr("formatted", "string", false, "The full name, including all middlenames, titles, and suffixes as appropriate, formatted for display(e.g., 'Ms. Barbara J Jensen, III').", false)
                    .case_exact(false)
                    .read_write()
                    .uniqueness("none"),
                attr("familyName", "string", false, "The family name of the User, or last name in most Western languages (e.g., 'Jensen' given the fullname 'Ms. Barbara J Jensen, III').", false)
                    .case_exact(false)
                    .read_write()
                    .uniqueness("none"),
                attr("givenName", "string", false, "The given name of the User, or first name in most Western languages (e.g., 'Barbara' given the full name 'Ms. Barbara J Jensen, III').", false)
                    .case_exact(false)
                    .read_write()
                    .uniqueness("none"),
            ]),
        attr("emails", "complex", true, "Email addresses for the user.  The value SHOULD be canonicalized by the service provider, e.g., 'bjensen@example.com' instead of 'bjensen@EXAMPLE.COM'. Canonical type values of 'work', 'home', and 'other'.", false)
            .read_write()
            .uniqueness("none")
            .sub_attributes(vec![
                attr("value", "string", false, "Email addresses for the user.  The value SHOULD be canonicalized by the service provider, e.g., 'bjensen@example.com' instead of 'bjensen@EXAMPLE.COM'. Canonical type values of 'work', 'home', and 'other'.", false)
                    .case_exact(false)
                    .read_write()
                    .uniqueness("server"),
                attr("primary", "boolean", false, "A Boolean value indicating the 'primary' or preferred attribute value for this attribute, e.g., the preferred mailing address or primary email address.  The primary attribute value 'true' MUST appear no more than once.", false)
                    .read_write(),
            ]),
    ]
}

fn attr(
    name: &str,
    type_: &str,
    multi_valued: bool,
    description: &str,
    required: bool,
) -> ScimSchemaAttribute {
    ScimSchemaAttribute {
        name: name.to_owned(),
        type_: type_.to_owned(),
        multi_valued,
        description: description.to_owned(),
        required,
        case_exact: None,
        mutability: None,
        returned: None,
        uniqueness: None,
        sub_attributes: Vec::new(),
    }
}

impl ScimSchemaAttribute {
    fn case_exact(mut self, value: bool) -> Self {
        self.case_exact = Some(value);
        self
    }

    fn read_only(mut self) -> Self {
        self.mutability = Some("readOnly".to_owned());
        self.returned = Some("default".to_owned());
        self
    }

    fn read_write(mut self) -> Self {
        self.mutability = Some("readWrite".to_owned());
        self.returned = Some("default".to_owned());
        self
    }

    fn uniqueness(mut self, value: &str) -> Self {
        self.uniqueness = Some(value.to_owned());
        self
    }

    fn sub_attributes(mut self, sub_attributes: Vec<ScimSchemaAttribute>) -> Self {
        self.sub_attributes = sub_attributes;
        self
    }
}
