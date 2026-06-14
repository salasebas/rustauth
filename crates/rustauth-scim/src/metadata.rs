//! SCIM metadata resources.

use serde::{Deserialize, Serialize};

use crate::errors::ScimError;
use crate::mappings::resource_url;

pub const LIST_RESPONSE_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
pub const SCIM_BULK_MAX_OPERATIONS: usize = 1000;
pub const SCIM_BULK_MAX_PAYLOAD_SIZE: usize = 1_048_576;
pub const SCIM_FILTER_MAX_RESULTS: usize = 200;
pub const SCIM_USER_SCHEMA_ID: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub const SCIM_GROUP_SCHEMA_ID: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
pub const SCIM_ENTERPRISE_USER_SCHEMA_ID: &str =
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
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
    #[serde(
        rename = "maxOperations",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub max_operations: Option<usize>,
    #[serde(
        rename = "maxPayloadSize",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub max_payload_size: Option<usize>,
    #[serde(
        rename = "maxResults",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub max_results: Option<usize>,
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
    #[serde(
        rename = "referenceTypes",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub reference_types: Vec<String>,
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
    #[serde(
        rename = "schemaExtensions",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub schema_extensions: Vec<ResourceTypeSchemaExtension>,
    pub meta: ScimMeta,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceTypeSchemaExtension {
    pub schema: String,
    pub required: bool,
}

pub fn service_provider_config() -> ServiceProviderConfig {
    ServiceProviderConfig {
        patch: Supported::new(true),
        bulk: Supported::new(true)
            .max_operations(SCIM_BULK_MAX_OPERATIONS)
            .max_payload_size(SCIM_BULK_MAX_PAYLOAD_SIZE),
        filter: Supported::new(true).max_results(SCIM_FILTER_MAX_RESULTS),
        change_password: Supported::new(false),
        sort: Supported::new(true),
        etag: Supported::new(true),
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
    let resources = vec![
        user_schema(base_url),
        group_schema(base_url),
        enterprise_user_schema(base_url),
    ];
    list_response(resources)
}

pub fn schema(base_url: &str, schema_id: &str) -> Result<ScimSchema, ScimError> {
    match schema_id {
        SCIM_USER_SCHEMA_ID => Ok(user_schema(base_url)),
        SCIM_GROUP_SCHEMA_ID => Ok(group_schema(base_url)),
        SCIM_ENTERPRISE_USER_SCHEMA_ID => Ok(enterprise_user_schema(base_url)),
        _ => Err(ScimError::not_found("Schema not found")),
    }
}

pub fn resource_types(base_url: &str) -> ListResponse<ResourceType> {
    let resources = vec![user_resource_type(base_url), group_resource_type(base_url)];
    list_response(resources)
}

pub fn resource_type(base_url: &str, resource_type_id: &str) -> Result<ResourceType, ScimError> {
    match resource_type_id {
        "User" => Ok(user_resource_type(base_url)),
        "Group" => Ok(group_resource_type(base_url)),
        _ => Err(ScimError::not_found("Resource type not found")),
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

fn group_schema(base_url: &str) -> ScimSchema {
    ScimSchema {
        id: SCIM_GROUP_SCHEMA_ID.to_owned(),
        schemas: vec![SCIM_SCHEMA_SCHEMA.to_owned()],
        name: "Group".to_owned(),
        description: "Group".to_owned(),
        attributes: group_attributes(),
        meta: ScimMeta {
            resource_type: "Schema".to_owned(),
            location: resource_url(
                base_url,
                "/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:Group",
            ),
        },
    }
}

fn enterprise_user_schema(base_url: &str) -> ScimSchema {
    ScimSchema {
        id: SCIM_ENTERPRISE_USER_SCHEMA_ID.to_owned(),
        schemas: vec![SCIM_SCHEMA_SCHEMA.to_owned()],
        name: "EnterpriseUser".to_owned(),
        description: "Enterprise User".to_owned(),
        attributes: enterprise_user_attributes(),
        meta: ScimMeta {
            resource_type: "Schema".to_owned(),
            location: resource_url(
                base_url,
                "/scim/v2/Schemas/urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
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
        schema_extensions: vec![ResourceTypeSchemaExtension {
            schema: SCIM_ENTERPRISE_USER_SCHEMA_ID.to_owned(),
            required: false,
        }],
        meta: ScimMeta {
            resource_type: "ResourceType".to_owned(),
            location: resource_url(base_url, "/scim/v2/ResourceTypes/User"),
        },
    }
}

fn group_resource_type(base_url: &str) -> ResourceType {
    ResourceType {
        schemas: vec![SCIM_RESOURCE_TYPE_SCHEMA.to_owned()],
        id: "Group".to_owned(),
        name: "Group".to_owned(),
        endpoint: "/Groups".to_owned(),
        description: "Group".to_owned(),
        schema: SCIM_GROUP_SCHEMA_ID.to_owned(),
        schema_extensions: Vec::new(),
        meta: ScimMeta {
            resource_type: "ResourceType".to_owned(),
            location: resource_url(base_url, "/scim/v2/ResourceTypes/Group"),
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
                attr("type", "string", false, "A label indicating the attribute's function.", false)
                    .case_exact(false)
                    .read_write()
                    .uniqueness("none"),
                attr("display", "string", false, "A human-readable name, primarily used for display purposes.", false)
                    .case_exact(false)
                    .read_only()
                    .uniqueness("none"),
                attr("primary", "boolean", false, "A Boolean value indicating the 'primary' or preferred attribute value for this attribute, e.g., the preferred mailing address or primary email address.  The primary attribute value 'true' MUST appear no more than once.", false)
                    .read_write(),
            ]),
        simple_user_string("nickName", "The casual way to address the user in real life."),
        attr("profileUrl", "reference", false, "A fully qualified URL pointing to a page representing the user's online profile.", false)
            .case_exact(false)
            .read_write()
            .uniqueness("none")
            .reference_types(vec!["external"]),
        simple_user_string("title", "The user's title, such as Vice President."),
        simple_user_string("userType", "Used to identify the relationship between the organization and the user."),
        simple_user_string("preferredLanguage", "Indicates the user's preferred written or spoken language."),
        simple_user_string("locale", "Used to indicate the user's default location for purposes of localizing items."),
        simple_user_string("timezone", "The user's time zone in the Olson time zone database format."),
        multi_valued_string("phoneNumbers", "Phone numbers for the user."),
        multi_valued_string("ims", "Instant messaging addresses for the user."),
        attr("photos", "complex", true, "URLs of photos of the user.", false)
            .read_write()
            .uniqueness("none")
            .sub_attributes(multi_valued_common_sub_attributes("reference")),
        attr("addresses", "complex", true, "A physical mailing address for the user.", false)
            .read_write()
            .uniqueness("none")
            .sub_attributes(vec![
                attr("formatted", "string", false, "The full mailing address, formatted for display or use with a mailing label.", false).case_exact(false).read_write().uniqueness("none"),
                attr("streetAddress", "string", false, "The full street address component.", false).case_exact(false).read_write().uniqueness("none"),
                attr("locality", "string", false, "The city or locality component.", false).case_exact(false).read_write().uniqueness("none"),
                attr("region", "string", false, "The state or region component.", false).case_exact(false).read_write().uniqueness("none"),
                attr("postalCode", "string", false, "The zip code or postal code component.", false).case_exact(false).read_write().uniqueness("none"),
                attr("country", "string", false, "The country name component.", false).case_exact(false).read_write().uniqueness("none"),
                attr("type", "string", false, "A label indicating the attribute's function.", false).case_exact(false).read_write().uniqueness("none"),
                attr("primary", "boolean", false, "A Boolean value indicating the preferred attribute value.", false).read_write(),
            ]),
        attr("groups", "complex", true, "A list of groups to which the user belongs.", false)
            .read_only()
            .uniqueness("none")
            .sub_attributes(vec![
                attr("value", "string", false, "The identifier of the user's group.", false).case_exact(true).read_only().uniqueness("none"),
                attr("$ref", "reference", false, "The URI of the corresponding Group resource.", false).case_exact(false).read_only().uniqueness("none").reference_types(vec!["Group"]),
                attr("display", "string", false, "A human-readable name for the Group.", false).case_exact(false).read_only().uniqueness("none"),
            ]),
        multi_valued_string("entitlements", "A list of entitlements for the user."),
        multi_valued_string("roles", "A list of roles for the user."),
        attr("x509Certificates", "complex", true, "A list of certificates issued to the user.", false)
            .read_write()
            .uniqueness("none")
            .sub_attributes(vec![
                attr("value", "binary", false, "The value of an X.509 certificate.", false).case_exact(false).read_write().uniqueness("none"),
                attr("type", "string", false, "A label indicating the attribute's function.", false).case_exact(false).read_write().uniqueness("none"),
                attr("display", "string", false, "A human-readable name, primarily used for display purposes.", false).case_exact(false).read_only().uniqueness("none"),
                attr("primary", "boolean", false, "A Boolean value indicating the preferred attribute value.", false).read_write(),
            ]),
    ]
}

fn group_attributes() -> Vec<ScimSchemaAttribute> {
    vec![
        attr(
            "id",
            "string",
            false,
            "Unique identifier for the Group",
            false,
        )
        .case_exact(true)
        .read_only()
        .uniqueness("server"),
        attr(
            "displayName",
            "string",
            false,
            "A human-readable name for the Group.",
            true,
        )
        .case_exact(false)
        .read_write()
        .uniqueness("server"),
        attr("members", "complex", true, "Members of the Group.", false)
            .read_write()
            .uniqueness("none")
            .reference_types(vec!["User", "Group"])
            .sub_attributes(vec![
                attr("value", "string", false, "Identifier of the member.", false)
                    .case_exact(true)
                    .immutable()
                    .uniqueness("none"),
                attr("$ref", "reference", false, "The URI of the member.", false)
                    .case_exact(false)
                    .read_only()
                    .uniqueness("none")
                    .reference_types(vec!["User", "Group"]),
                attr(
                    "type",
                    "string",
                    false,
                    "The resource type of the member.",
                    false,
                )
                .case_exact(false)
                .immutable()
                .uniqueness("none"),
                attr(
                    "display",
                    "string",
                    false,
                    "Display name of the member.",
                    false,
                )
                .case_exact(false)
                .read_only()
                .uniqueness("none"),
            ]),
    ]
}

fn enterprise_user_attributes() -> Vec<ScimSchemaAttribute> {
    vec![
        attr(
            "employeeNumber",
            "string",
            false,
            "Numeric or alphanumeric identifier assigned to a person.",
            false,
        )
        .case_exact(false)
        .read_write()
        .uniqueness("none"),
        attr(
            "costCenter",
            "string",
            false,
            "Identifies the name of a cost center.",
            false,
        )
        .case_exact(false)
        .read_write()
        .uniqueness("none"),
        attr(
            "organization",
            "string",
            false,
            "Identifies the name of an organization.",
            false,
        )
        .case_exact(false)
        .read_write()
        .uniqueness("none"),
        attr(
            "division",
            "string",
            false,
            "Identifies the name of a division.",
            false,
        )
        .case_exact(false)
        .read_write()
        .uniqueness("none"),
        attr(
            "department",
            "string",
            false,
            "Identifies the name of a department.",
            false,
        )
        .case_exact(false)
        .read_write()
        .uniqueness("none"),
        attr("manager", "complex", false, "The User's manager.", false)
            .read_write()
            .uniqueness("none")
            .sub_attributes(vec![
                attr(
                    "value",
                    "string",
                    false,
                    "The id of the SCIM resource representing the User's manager.",
                    false,
                )
                .case_exact(true)
                .read_write()
                .uniqueness("none"),
                attr(
                    "$ref",
                    "reference",
                    false,
                    "The URI of the SCIM resource representing the User's manager.",
                    false,
                )
                .case_exact(false)
                .read_write()
                .uniqueness("none"),
                attr(
                    "displayName",
                    "string",
                    false,
                    "The displayName of the User's manager.",
                    false,
                )
                .case_exact(false)
                .read_write()
                .uniqueness("none"),
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
        reference_types: Vec::new(),
    }
}

impl Supported {
    fn new(supported: bool) -> Self {
        Self {
            supported,
            max_operations: None,
            max_payload_size: None,
            max_results: None,
        }
    }

    fn max_operations(mut self, value: usize) -> Self {
        self.max_operations = Some(value);
        self
    }

    fn max_payload_size(mut self, value: usize) -> Self {
        self.max_payload_size = Some(value);
        self
    }

    fn max_results(mut self, value: usize) -> Self {
        self.max_results = Some(value);
        self
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

    fn immutable(mut self) -> Self {
        self.mutability = Some("immutable".to_owned());
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

    fn reference_types(mut self, reference_types: Vec<&str>) -> Self {
        self.reference_types = reference_types.into_iter().map(str::to_owned).collect();
        self
    }
}

fn simple_user_string(name: &str, description: &str) -> ScimSchemaAttribute {
    attr(name, "string", false, description, false)
        .case_exact(false)
        .read_write()
        .uniqueness("none")
}

fn multi_valued_string(name: &str, description: &str) -> ScimSchemaAttribute {
    attr(name, "complex", true, description, false)
        .read_write()
        .uniqueness("none")
        .sub_attributes(multi_valued_common_sub_attributes("string"))
}

fn multi_valued_common_sub_attributes(value_type: &str) -> Vec<ScimSchemaAttribute> {
    vec![
        attr("value", value_type, false, "The attribute value.", false)
            .case_exact(false)
            .read_write()
            .uniqueness("none"),
        attr(
            "type",
            "string",
            false,
            "A label indicating the attribute's function.",
            false,
        )
        .case_exact(false)
        .read_write()
        .uniqueness("none"),
        attr(
            "display",
            "string",
            false,
            "A human-readable name, primarily used for display purposes.",
            false,
        )
        .case_exact(false)
        .read_only()
        .uniqueness("none"),
        attr(
            "primary",
            "boolean",
            false,
            "A Boolean value indicating the preferred attribute value.",
            false,
        )
        .read_write(),
    ]
}
