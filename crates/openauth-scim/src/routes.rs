//! SCIM endpoint registration.

use std::sync::{Arc, Mutex};

use http::{header, Method, Response, StatusCode};
use openauth_core::api::{
    create_auth_endpoint, ApiRequest, ApiResponse, AuthEndpointOptions, OpenApiOperation,
    PathParams,
};
use openauth_core::auth::session::{GetSessionInput, SessionAuth};
use openauth_core::crypto::random::generate_random_string;
use openauth_core::crypto::{symmetric_decrypt, symmetric_encrypt};
use openauth_core::db::{
    Account, Create, DbAdapter, DbRecord, DbValue, Delete, DeleteMany, FindMany, FindOne, Update,
    User, Where, WhereOperator,
};
use openauth_core::error::OpenAuthError;
use openauth_core::user::{CreateOAuthAccountInput, CreateUserInput, DbUserStore, UpdateUserInput};
use serde::Deserialize;
use serde::Serialize;
use subtle::ConstantTimeEq;
use time::OffsetDateTime;

use crate::errors::ScimError;
use crate::filters::{
    parse_filter, parse_user_filter, resource_matches_filter, ScimFilterOperator,
};
use crate::mappings::{account_id, primary_email, user_full_name, ScimEmail, ScimName};
use crate::metadata;
use crate::options::{
    AfterScimTokenGeneratedInput, BeforeScimTokenGeneratedInput, DefaultScimProvider,
    ScimAuditEvent, ScimAuditEventKind, ScimAuditSeverity, ScimBulkMode, ScimHookError,
    ScimOptions, ScimOrganizationMember, ScimTokenStorage,
};
use crate::patch::{build_user_patch, PatchOperation};
use crate::resources::{
    group_member_resource, group_resource, resource_version, user_resource, ScimGroupResource,
    ScimUserResource, ScimUserResourceGroup,
};
use crate::store::{ScimProviderRecord, ScimProviderStore};
use crate::token::{decode_bearer_token, hash_base_token};

mod auth_context;
mod bulk;
mod common;
mod group_resources;
mod groups;
mod management;
mod metadata_routes;
mod user_resources;
mod users;

use auth_context::*;
use common::*;
use group_resources::*;
use user_resources::*;

const PATCH_OP_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const BULK_REQUEST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:BulkRequest";
const BULK_RESPONSE_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:BulkResponse";
const ACCOUNT_FIELDS: [&str; 13] = [
    "id",
    "provider_id",
    "account_id",
    "user_id",
    "access_token",
    "refresh_token",
    "id_token",
    "access_token_expires_at",
    "refresh_token_expires_at",
    "scope",
    "password",
    "created_at",
    "updated_at",
];

pub fn endpoints(options: ScimOptions) -> Vec<openauth_core::api::AsyncAuthEndpoint> {
    let options = Arc::new(options);
    vec![
        management::generate_token_endpoint(Arc::clone(&options)),
        management::list_provider_connections_endpoint(Arc::clone(&options)),
        management::get_provider_connection_endpoint(Arc::clone(&options)),
        management::delete_provider_connection_endpoint(Arc::clone(&options)),
        users::create_user_endpoint(Arc::clone(&options)),
        users::list_users_endpoint(Arc::clone(&options)),
        users::get_user_endpoint(Arc::clone(&options)),
        users::put_user_endpoint(Arc::clone(&options)),
        users::patch_user_endpoint(Arc::clone(&options)),
        users::delete_user_endpoint(Arc::clone(&options)),
        users::search_users_endpoint(Arc::clone(&options)),
        groups::create_group_endpoint(Arc::clone(&options)),
        groups::list_groups_endpoint(Arc::clone(&options)),
        groups::get_group_endpoint(Arc::clone(&options)),
        groups::put_group_endpoint(Arc::clone(&options)),
        groups::patch_group_endpoint(Arc::clone(&options)),
        groups::delete_group_endpoint(Arc::clone(&options)),
        groups::search_groups_endpoint(Arc::clone(&options)),
        metadata_routes::search_resources_endpoint(Arc::clone(&options)),
        bulk::bulk_endpoint(Arc::clone(&options)),
        metadata_routes::me_endpoint(),
        metadata_routes::service_provider_config_endpoint(),
        metadata_routes::schemas_endpoint(),
        metadata_routes::schema_endpoint(),
        metadata_routes::resource_types_endpoint(),
        metadata_routes::resource_type_endpoint(),
    ]
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScimUserInput {
    #[serde(default)]
    schemas: Vec<String>,
    #[serde(rename = "userName")]
    user_name: String,
    name: Option<ScimName>,
    emails: Option<Vec<ScimEmail>>,
    external_id: Option<String>,
    #[serde(flatten)]
    additional_fields: std::collections::BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScimGroupInput {
    #[serde(rename = "displayName")]
    display_name: String,
    external_id: Option<String>,
    #[serde(default)]
    members: Vec<ScimGroupMemberInput>,
}

#[derive(Debug, Deserialize)]
struct ScimGroupMemberInput {
    value: String,
    #[serde(rename = "type")]
    type_: Option<String>,
}

#[derive(Debug, Clone)]
struct ScimTeamRecord {
    id: String,
    name: String,
    created_at: OffsetDateTime,
    updated_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone)]
struct ScimGroupProfileRecord {
    external_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SearchRequest {
    filter: Option<String>,
    #[serde(default)]
    attributes: Option<Vec<String>>,
    #[serde(default, rename = "excludedAttributes")]
    excluded_attributes: Option<Vec<String>>,
    #[serde(rename = "startIndex")]
    start_index: Option<usize>,
    count: Option<usize>,
    #[serde(rename = "sortBy")]
    sort_by: Option<String>,
    #[serde(rename = "sortOrder")]
    sort_order: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BulkRequest {
    #[serde(default)]
    schemas: Vec<String>,
    #[serde(rename = "failOnErrors")]
    fail_on_errors: Option<u64>,
    #[serde(rename = "Operations")]
    operations: Vec<BulkOperationRequest>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BulkOperationRequest {
    method: String,
    path: String,
    #[serde(rename = "bulkId")]
    bulk_id: Option<String>,
    #[serde(default, rename = "data")]
    data: Option<serde_json::Value>,
    version: Option<String>,
}

#[derive(Debug, Serialize)]
struct BulkResponse {
    schemas: Vec<String>,
    #[serde(rename = "Operations")]
    operations: Vec<BulkOperationResponse>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BulkOperationResponse {
    method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(rename = "bulkId", skip_serializing_if = "Option::is_none")]
    bulk_id: Option<String>,
    status: BulkOperationStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct BulkOperationStatus {
    code: u16,
}

#[derive(Debug, Deserialize)]
struct PatchBody {
    #[serde(default)]
    schemas: Vec<String>,
    #[serde(rename = "Operations")]
    operations: Vec<PatchOperationInput>,
}

#[derive(Debug, Deserialize)]
struct PatchOperationInput {
    op: Option<String>,
    path: Option<String>,
    #[serde(default)]
    value: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GenerateTokenBody {
    provider_id: String,
    organization_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProviderIdBody {
    provider_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GenerateTokenResponse {
    scim_token: String,
}

#[derive(Debug, Serialize)]
struct DeleteProviderResponse {
    success: bool,
}

#[derive(Debug, Serialize)]
struct ProviderListResponse {
    providers: Vec<SanitizedProvider>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SanitizedProvider {
    id: String,
    provider_id: String,
    organization_id: Option<String>,
}

impl From<ScimProviderRecord> for SanitizedProvider {
    fn from(provider: ScimProviderRecord) -> Self {
        Self {
            id: provider.id,
            provider_id: provider.provider_id,
            organization_id: provider.organization_id,
        }
    }
}

#[derive(Debug, Clone)]
struct AuthenticatedScimProvider {
    provider_id: String,
    organization_id: Option<String>,
}

struct CreateScimUserResult {
    user: User,
    account: Account,
}

enum ScimErrorOrOpenAuth {
    Scim(ScimError),
    OpenAuth(OpenAuthError),
}

impl ScimErrorOrOpenAuth {
    fn into_response(self) -> Result<ApiResponse, OpenAuthError> {
        match self {
            Self::Scim(error) => error.into_response(),
            Self::OpenAuth(error) => Err(error),
        }
    }
}
