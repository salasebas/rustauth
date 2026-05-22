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
    Account, Create, DbAdapter, DbRecord, DbValue, FindMany, FindOne, Update, User, Where,
};
use openauth_core::error::OpenAuthError;
use openauth_core::user::{CreateOAuthAccountInput, CreateUserInput, DbUserStore, UpdateUserInput};
use serde::Deserialize;
use serde::Serialize;
use subtle::ConstantTimeEq;
use time::OffsetDateTime;

use crate::errors::ScimError;
use crate::filters::{parse_user_filter, ScimDbFilter, ScimFilterOperator};
use crate::mappings::{account_id, primary_email, user_full_name, ScimEmail, ScimName};
use crate::metadata;
use crate::options::{
    AfterScimTokenGeneratedInput, BeforeScimTokenGeneratedInput, DefaultScimProvider,
    ScimHookError, ScimOptions, ScimOrganizationMember, ScimTokenStorage,
};
use crate::patch::{build_user_patch, PatchOperation};
use crate::resources::user_resource;
use crate::store::{ScimProviderRecord, ScimProviderStore};
use crate::token::{decode_bearer_token, hash_base_token};

const PATCH_OP_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

pub fn endpoints(options: ScimOptions) -> Vec<openauth_core::api::AsyncAuthEndpoint> {
    let options = Arc::new(options);
    vec![
        generate_token_endpoint(Arc::clone(&options)),
        list_provider_connections_endpoint(Arc::clone(&options)),
        get_provider_connection_endpoint(Arc::clone(&options)),
        delete_provider_connection_endpoint(Arc::clone(&options)),
        create_user_endpoint(Arc::clone(&options)),
        list_users_endpoint(Arc::clone(&options)),
        get_user_endpoint(Arc::clone(&options)),
        put_user_endpoint(Arc::clone(&options)),
        patch_user_endpoint(Arc::clone(&options)),
        delete_user_endpoint(Arc::clone(&options)),
        service_provider_config_endpoint(),
        schemas_endpoint(),
        schema_endpoint(),
        resource_types_endpoint(),
        resource_type_endpoint(),
    ]
}

fn scim_endpoint_options(operation_id: &str, description: &str) -> AuthEndpointOptions {
    AuthEndpointOptions::new()
        .operation_id(operation_id)
        .openapi(
            OpenApiOperation::new(operation_id)
                .description(description)
                .tag("SCIM"),
        )
}

fn generate_token_endpoint(options: Arc<ScimOptions>) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/generate-token",
        Method::POST,
        scim_endpoint_options("generateScimToken", "Generate a SCIM bearer token")
            .allowed_media_types(["application/json"]),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                let adapter = required_adapter(context)?;
                let Some(user) = current_user(context, adapter.as_ref(), &request).await? else {
                    return json_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
                };
                let body: GenerateTokenBody = match serde_json::from_slice(request.body()) {
                    Ok(body) => body,
                    Err(error) => {
                        return json_error(
                            StatusCode::BAD_REQUEST,
                            "BAD_REQUEST",
                            &format!("invalid JSON request body: {error}"),
                        );
                    }
                };
                if body.provider_id.contains(':') {
                    return json_error(
                        StatusCode::BAD_REQUEST,
                        "BAD_REQUEST",
                        "Provider id contains forbidden characters",
                    );
                }
                if body.organization_id.is_some() && !context.has_plugin("organization") {
                    return json_error(
                        StatusCode::BAD_REQUEST,
                        "BAD_REQUEST",
                        "Restricting a token to an organization requires the organization plugin",
                    );
                }

                let store = ScimProviderStore::new(adapter.as_ref());
                let existing_provider = store.find_by_provider_id(&body.provider_id).await?;
                if let Some(existing) = existing_provider.as_ref() {
                    if existing.organization_id != body.organization_id {
                        return json_error(
                            StatusCode::FORBIDDEN,
                            "FORBIDDEN",
                            "SCIM provider exists for a different scope",
                        );
                    }
                    if !provider_access_allowed(
                        adapter.as_ref(),
                        existing,
                        &user,
                        &options,
                        organization_creator_role(context).as_deref(),
                    )
                    .await?
                    {
                        return json_error(
                            StatusCode::FORBIDDEN,
                            "FORBIDDEN",
                            "You must be the owner to access this provider",
                        );
                    }
                }

                let member = if let Some(organization_id) = body.organization_id.as_deref() {
                    let Some(member) =
                        organization_member(adapter.as_ref(), organization_id, &user.id).await?
                    else {
                        return json_error(
                            StatusCode::FORBIDDEN,
                            "FORBIDDEN",
                            "You are not a member of the organization",
                        );
                    };
                    if !role_has_required_access(
                        &member.role,
                        options.required_role.as_deref(),
                        organization_creator_role(context).as_deref(),
                    ) {
                        return json_error(
                            StatusCode::FORBIDDEN,
                            "FORBIDDEN",
                            "Insufficient role for this operation",
                        );
                    }
                    Some(member)
                } else {
                    None
                };

                let base_token = generate_random_string(24);
                let scim_token = crate::token::encode_bearer_token(
                    &base_token,
                    &body.provider_id,
                    body.organization_id.as_deref(),
                );
                if let Some(before_hook) = options.before_token_generated.as_ref() {
                    if let Err(error) = before_hook(BeforeScimTokenGeneratedInput {
                        user: user.clone(),
                        member: member.clone(),
                        scim_token: scim_token.clone(),
                    })
                    .await
                    {
                        return hook_error(error);
                    }
                }
                if existing_provider.is_some() {
                    store.delete(&body.provider_id).await?;
                }
                let stored_token =
                    store_scim_token(&context.secret, &options.token_storage, &base_token).await?;
                let provider = store
                    .create(crate::store::CreateScimProviderInput {
                        provider_id: body.provider_id,
                        scim_token: stored_token,
                        organization_id: body.organization_id,
                        user_id: options.provider_ownership.enabled.then(|| user.id.clone()),
                    })
                    .await?;
                if let Some(after_hook) = options.after_token_generated.as_ref() {
                    if let Err(error) = after_hook(AfterScimTokenGeneratedInput {
                        user,
                        member,
                        scim_token: scim_token.clone(),
                        provider,
                    })
                    .await
                    {
                        return hook_error(error);
                    }
                }

                json(StatusCode::CREATED, &GenerateTokenResponse { scim_token })
            })
        },
    )
}

fn list_provider_connections_endpoint(
    options: Arc<ScimOptions>,
) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/list-provider-connections",
        Method::GET,
        scim_endpoint_options(
            "listScimProviderConnections",
            "List SCIM provider connections",
        ),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                let adapter = required_adapter(context)?;
                let Some(user) = current_user(context, adapter.as_ref(), &request).await? else {
                    return json_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
                };
                let mut providers = Vec::new();
                for provider in ScimProviderStore::new(adapter.as_ref()).list().await? {
                    if provider_access_allowed(
                        adapter.as_ref(),
                        &provider,
                        &user,
                        &options,
                        organization_creator_role(context).as_deref(),
                    )
                    .await?
                    {
                        providers.push(SanitizedProvider::from(provider));
                    }
                }
                json(StatusCode::OK, &ProviderListResponse { providers })
            })
        },
    )
}

fn get_provider_connection_endpoint(
    options: Arc<ScimOptions>,
) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/get-provider-connection",
        Method::GET,
        scim_endpoint_options(
            "getScimProviderConnection",
            "Get a SCIM provider connection",
        ),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                let adapter = required_adapter(context)?;
                let Some(user) = current_user(context, adapter.as_ref(), &request).await? else {
                    return json_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
                };
                let Some(provider_id) = query_param(&request, "providerId") else {
                    return json_error(
                        StatusCode::BAD_REQUEST,
                        "BAD_REQUEST",
                        "providerId is required",
                    );
                };
                let Some(provider) = ScimProviderStore::new(adapter.as_ref())
                    .find_by_provider_id(&provider_id)
                    .await?
                else {
                    return json_error(
                        StatusCode::NOT_FOUND,
                        "NOT_FOUND",
                        "SCIM provider not found",
                    );
                };
                if !provider_access_allowed(
                    adapter.as_ref(),
                    &provider,
                    &user,
                    &options,
                    organization_creator_role(context).as_deref(),
                )
                .await?
                {
                    return json_error(
                        StatusCode::FORBIDDEN,
                        "FORBIDDEN",
                        "You must be the owner to access this provider",
                    );
                }
                json(StatusCode::OK, &SanitizedProvider::from(provider))
            })
        },
    )
}

fn delete_provider_connection_endpoint(
    options: Arc<ScimOptions>,
) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/delete-provider-connection",
        Method::POST,
        scim_endpoint_options(
            "deleteScimProviderConnection",
            "Delete a SCIM provider connection",
        )
        .allowed_media_types(["application/json"]),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                let adapter = required_adapter(context)?;
                let Some(user) = current_user(context, adapter.as_ref(), &request).await? else {
                    return json_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
                };
                let body: ProviderIdBody = match serde_json::from_slice(request.body()) {
                    Ok(body) => body,
                    Err(error) => {
                        return json_error(
                            StatusCode::BAD_REQUEST,
                            "BAD_REQUEST",
                            &format!("invalid JSON request body: {error}"),
                        );
                    }
                };
                let store = ScimProviderStore::new(adapter.as_ref());
                let Some(provider) = store.find_by_provider_id(&body.provider_id).await? else {
                    return json_error(
                        StatusCode::NOT_FOUND,
                        "NOT_FOUND",
                        "SCIM provider not found",
                    );
                };
                if !provider_access_allowed(
                    adapter.as_ref(),
                    &provider,
                    &user,
                    &options,
                    organization_creator_role(context).as_deref(),
                )
                .await?
                {
                    return json_error(
                        StatusCode::FORBIDDEN,
                        "FORBIDDEN",
                        "You must be the owner to access this provider",
                    );
                }
                store.delete(&body.provider_id).await?;
                json(StatusCode::OK, &DeleteProviderResponse { success: true })
            })
        },
    )
}

fn get_user_endpoint(options: Arc<ScimOptions>) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/v2/Users/:userId",
        Method::GET,
        scim_endpoint_options("getScimUser", "Get a SCIM User resource"),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                let adapter = required_adapter(context)?;
                let Some(provider) = authenticate_scim_request(
                    adapter.as_ref(),
                    &context.secret,
                    &options,
                    &request,
                )
                .await?
                else {
                    return scim_auth_error(&request).into_response();
                };
                let Some(user_id) = path_param(&request, "userId") else {
                    return ScimError::not_found("User not found").into_response();
                };
                let Some((user, account)) = find_scim_user(
                    adapter.as_ref(),
                    &user_id,
                    &provider.provider_id,
                    provider.organization_id.as_deref(),
                )
                .await?
                else {
                    return ScimError::not_found("User not found").into_response();
                };
                scim_json(
                    StatusCode::OK,
                    &user_resource(&context.base_url, &user, Some(&account)),
                )
            })
        },
    )
}

fn create_user_endpoint(options: Arc<ScimOptions>) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/v2/Users",
        Method::POST,
        scim_endpoint_options("createScimUser", "Create a SCIM User resource")
            .allowed_media_types(["application/scim+json", "application/json"]),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                let adapter = required_adapter(context)?;
                let Some(provider) = authenticate_scim_request(
                    adapter.as_ref(),
                    &context.secret,
                    &options,
                    &request,
                )
                .await?
                else {
                    return scim_auth_error(&request).into_response();
                };
                let input: ScimUserInput = match serde_json::from_slice(request.body()) {
                    Ok(input) => input,
                    Err(error) => {
                        return ScimError::bad_request(format!(
                            "invalid JSON request body: {error}"
                        ))
                        .into_response();
                    }
                };
                let emails = input.emails.unwrap_or_default();
                if let Err(error) = validate_emails(&emails) {
                    return error.into_response();
                }
                let email = primary_email(&input.user_name, &emails).to_lowercase();
                let name = user_full_name(&email, input.name.as_ref());
                let account_id = account_id(&input.user_name, input.external_id.as_deref());

                let users = DbUserStore::new(adapter.as_ref());
                if users
                    .find_account_by_provider_account(&account_id, &provider.provider_id)
                    .await?
                    .is_some()
                {
                    return ScimError::bad_request("User already exists").into_response();
                }

                let user_input = CreateUserInput::new(name, email.clone()).email_verified(true);
                let account_input = CreateOAuthAccountInput {
                    id: None,
                    provider_id: provider.provider_id.clone(),
                    account_id,
                    user_id: String::new(),
                    access_token: None,
                    refresh_token: None,
                    id_token: None,
                    access_token_expires_at: None,
                    refresh_token_expires_at: None,
                    scope: None,
                };
                let (user, account) = create_scim_user_account_and_membership(
                    adapter.as_ref(),
                    users.find_user_by_email(&email).await?,
                    user_input,
                    account_input,
                    provider.organization_id.clone(),
                )
                .await?;

                let resource = user_resource(&context.base_url, &user, Some(&account));
                scim_json_with_location(StatusCode::CREATED, &resource, &resource.meta.location)
            })
        },
    )
}

fn put_user_endpoint(options: Arc<ScimOptions>) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/v2/Users/:userId",
        Method::PUT,
        scim_endpoint_options("replaceScimUser", "Replace a SCIM User resource")
            .allowed_media_types(["application/scim+json", "application/json"]),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                let adapter = required_adapter(context)?;
                let Some(provider) = authenticate_scim_request(
                    adapter.as_ref(),
                    &context.secret,
                    &options,
                    &request,
                )
                .await?
                else {
                    return scim_auth_error(&request).into_response();
                };
                let Some(user_id) = path_param(&request, "userId") else {
                    return ScimError::not_found("User not found").into_response();
                };
                let Some((user, account)) = find_scim_user(
                    adapter.as_ref(),
                    &user_id,
                    &provider.provider_id,
                    provider.organization_id.as_deref(),
                )
                .await?
                else {
                    return ScimError::not_found("User not found").into_response();
                };
                let input: ScimUserInput = match serde_json::from_slice(request.body()) {
                    Ok(input) => input,
                    Err(error) => {
                        return ScimError::bad_request(format!(
                            "invalid JSON request body: {error}"
                        ))
                        .into_response();
                    }
                };
                let emails = input.emails.unwrap_or_default();
                if let Err(error) = validate_emails(&emails) {
                    return error.into_response();
                }
                let email = primary_email(&input.user_name, &emails).to_lowercase();
                let name = user_full_name(&email, input.name.as_ref());
                let next_account_id = account_id(&input.user_name, input.external_id.as_deref());

                update_scim_user_and_account(
                    adapter.as_ref(),
                    &user.id,
                    &account.id,
                    Some(email),
                    Some(name),
                    Some(next_account_id),
                )
                .await?;

                let Some((updated_user, updated_account)) = find_scim_user(
                    adapter.as_ref(),
                    &user.id,
                    &provider.provider_id,
                    provider.organization_id.as_deref(),
                )
                .await?
                else {
                    return ScimError::not_found("User not found").into_response();
                };

                scim_json(
                    StatusCode::OK,
                    &user_resource(&context.base_url, &updated_user, Some(&updated_account)),
                )
            })
        },
    )
}

fn patch_user_endpoint(options: Arc<ScimOptions>) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/v2/Users/:userId",
        Method::PATCH,
        scim_endpoint_options("patchScimUser", "Patch a SCIM User resource")
            .allowed_media_types(["application/scim+json", "application/json"]),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                let adapter = required_adapter(context)?;
                let Some(provider) = authenticate_scim_request(
                    adapter.as_ref(),
                    &context.secret,
                    &options,
                    &request,
                )
                .await?
                else {
                    return scim_auth_error(&request).into_response();
                };
                let Some(user_id) = path_param(&request, "userId") else {
                    return ScimError::not_found("User not found").into_response();
                };
                let Some((user, account)) = find_scim_user(
                    adapter.as_ref(),
                    &user_id,
                    &provider.provider_id,
                    provider.organization_id.as_deref(),
                )
                .await?
                else {
                    return ScimError::not_found("User not found").into_response();
                };
                let body: PatchBody = match serde_json::from_slice(request.body()) {
                    Ok(body) => body,
                    Err(error) => {
                        return ScimError::bad_request(format!(
                            "invalid JSON request body: {error}"
                        ))
                        .into_response();
                    }
                };
                if !body.schemas.iter().any(|schema| schema == PATCH_OP_SCHEMA) {
                    return ScimError::bad_request("Invalid schemas for PatchOp").into_response();
                }
                let operations = body
                    .operations
                    .into_iter()
                    .map(|operation| PatchOperation {
                        op: operation.op.unwrap_or_else(|| "replace".to_owned()),
                        path: operation.path,
                        value: operation.value,
                    })
                    .collect::<Vec<_>>();
                let patch = match build_user_patch(&user, &operations) {
                    Ok(patch) => patch,
                    Err(error) => return error.into_response(),
                };

                update_scim_user_and_account(
                    adapter.as_ref(),
                    &user.id,
                    &account.id,
                    patch
                        .user
                        .get("email")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned),
                    patch
                        .user
                        .get("name")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned),
                    patch
                        .account
                        .get("account_id")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned),
                )
                .await?;

                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(Vec::new())
                    .map_err(|error| OpenAuthError::Api(error.to_string()))
            })
        },
    )
}

fn delete_user_endpoint(options: Arc<ScimOptions>) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/v2/Users/:userId",
        Method::DELETE,
        scim_endpoint_options("deleteScimUser", "Delete a SCIM User resource"),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                let adapter = required_adapter(context)?;
                let Some(provider) = authenticate_scim_request(
                    adapter.as_ref(),
                    &context.secret,
                    &options,
                    &request,
                )
                .await?
                else {
                    return scim_auth_error(&request).into_response();
                };
                let Some(user_id) = path_param(&request, "userId") else {
                    return ScimError::not_found("User not found").into_response();
                };
                let users = DbUserStore::new(adapter.as_ref());
                if find_scim_user(
                    adapter.as_ref(),
                    &user_id,
                    &provider.provider_id,
                    provider.organization_id.as_deref(),
                )
                .await?
                .is_none()
                {
                    return ScimError::not_found("User not found").into_response();
                }
                users.delete_user_accounts(&user_id).await?;
                users.delete_user(&user_id).await?;
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(Vec::new())
                    .map_err(|error| OpenAuthError::Api(error.to_string()))
            })
        },
    )
}

fn list_users_endpoint(options: Arc<ScimOptions>) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/v2/Users",
        Method::GET,
        scim_endpoint_options("listScimUsers", "List SCIM User resources"),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                let adapter = required_adapter(context)?;
                let Some(provider) = authenticate_scim_request(
                    adapter.as_ref(),
                    &context.secret,
                    &options,
                    &request,
                )
                .await?
                else {
                    return scim_auth_error(&request).into_response();
                };
                let filters = match query_param(&request, "filter") {
                    Some(filter) => match parse_user_filter(&filter) {
                        Ok(filters) => filters,
                        Err(error) => return error.into_response(),
                    },
                    None => Vec::new(),
                };
                let users = adapter
                    .find_many(FindMany::new("user").select([
                        "id",
                        "name",
                        "email",
                        "email_verified",
                        "image",
                        "created_at",
                        "updated_at",
                    ]))
                    .await?
                    .into_iter()
                    .map(user_from_record)
                    .collect::<Result<Vec<_>, _>>()?;
                let mut resources = Vec::with_capacity(users.len());
                for user in users {
                    if !user_matches_filters(&user, &filters) {
                        continue;
                    }
                    if let Some((user, account)) = find_scim_user(
                        adapter.as_ref(),
                        &user.id,
                        &provider.provider_id,
                        provider.organization_id.as_deref(),
                    )
                    .await?
                    {
                        resources.push(user_resource(&context.base_url, &user, Some(&account)));
                    }
                }
                scim_json(
                    StatusCode::OK,
                    &metadata::ListResponse {
                        schemas: vec![metadata::LIST_RESPONSE_SCHEMA.to_owned()],
                        total_results: resources.len(),
                        start_index: 1,
                        items_per_page: resources.len(),
                        resources,
                    },
                )
            })
        },
    )
}

fn service_provider_config_endpoint() -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/v2/ServiceProviderConfig",
        Method::GET,
        scim_endpoint_options(
            "getScimServiceProviderConfig",
            "Get SCIM ServiceProviderConfig",
        ),
        |_context, _request| {
            Box::pin(async { scim_json(StatusCode::OK, &metadata::service_provider_config()) })
        },
    )
}

fn schemas_endpoint() -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/v2/Schemas",
        Method::GET,
        scim_endpoint_options("listScimSchemas", "List SCIM schemas"),
        |context, _request| {
            Box::pin(
                async move { scim_json(StatusCode::OK, &metadata::schemas(&context.base_url)) },
            )
        },
    )
}

fn schema_endpoint() -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/v2/Schemas/:schemaId",
        Method::GET,
        scim_endpoint_options("getScimSchema", "Get a SCIM schema"),
        |context, request| {
            Box::pin(async move {
                let Some(schema_id) = path_param(&request, "schemaId") else {
                    return ScimError::not_found("Schema not found").into_response();
                };
                match metadata::schema(&context.base_url, &schema_id) {
                    Ok(schema) => scim_json(StatusCode::OK, &schema),
                    Err(error) => error.into_response(),
                }
            })
        },
    )
}

fn resource_types_endpoint() -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/v2/ResourceTypes",
        Method::GET,
        scim_endpoint_options("listScimResourceTypes", "List SCIM resource types"),
        |context, _request| {
            Box::pin(async move {
                scim_json(StatusCode::OK, &metadata::resource_types(&context.base_url))
            })
        },
    )
}

fn resource_type_endpoint() -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/v2/ResourceTypes/:resourceTypeId",
        Method::GET,
        scim_endpoint_options("getScimResourceType", "Get a SCIM resource type"),
        |context, request| {
            Box::pin(async move {
                let Some(resource_type_id) = path_param(&request, "resourceTypeId") else {
                    return ScimError::not_found("Resource type not found").into_response();
                };
                match metadata::resource_type(&context.base_url, &resource_type_id) {
                    Ok(resource_type) => scim_json(StatusCode::OK, &resource_type),
                    Err(error) => error.into_response(),
                }
            })
        },
    )
}

fn path_param(request: &ApiRequest, name: &str) -> Option<String> {
    request
        .extensions()
        .get::<PathParams>()
        .and_then(|params| params.get(name))
        .map(str::to_owned)
}

fn scim_json<T: Serialize>(status: StatusCode, body: &T) -> Result<ApiResponse, OpenAuthError> {
    let body = serde_json::to_vec(body).map_err(|error| OpenAuthError::Api(error.to_string()))?;
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/scim+json")
        .body(body)
        .map_err(|error| OpenAuthError::Api(error.to_string()))
}

fn scim_json_with_location<T: Serialize>(
    status: StatusCode,
    body: &T,
    location: &str,
) -> Result<ApiResponse, OpenAuthError> {
    let body = serde_json::to_vec(body).map_err(|error| OpenAuthError::Api(error.to_string()))?;
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/scim+json")
        .header(header::LOCATION, location)
        .body(body)
        .map_err(|error| OpenAuthError::Api(error.to_string()))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScimUserInput {
    #[serde(rename = "userName")]
    user_name: String,
    name: Option<ScimName>,
    emails: Option<Vec<ScimEmail>>,
    external_id: Option<String>,
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
    user_id: Option<String>,
}

impl From<ScimProviderRecord> for SanitizedProvider {
    fn from(provider: ScimProviderRecord) -> Self {
        Self {
            id: provider.id,
            provider_id: provider.provider_id,
            organization_id: provider.organization_id,
            user_id: provider.user_id,
        }
    }
}

#[derive(Debug, Clone)]
struct AuthenticatedScimProvider {
    provider_id: String,
    organization_id: Option<String>,
}

fn required_adapter(
    context: &openauth_core::context::AuthContext,
) -> Result<Arc<dyn DbAdapter>, OpenAuthError> {
    context
        .adapter()
        .ok_or_else(|| OpenAuthError::InvalidConfig("SCIM requires an adapter".to_owned()))
}

async fn authenticate_scim_request(
    adapter: &dyn DbAdapter,
    secret: &str,
    options: &ScimOptions,
    request: &ApiRequest,
) -> Result<Option<AuthenticatedScimProvider>, OpenAuthError> {
    let Some(token) = bearer_token(request) else {
        return Ok(None);
    };
    let Ok(decoded) = decode_bearer_token(token) else {
        return Ok(None);
    };

    for provider in &options.default_scim {
        if default_provider_matches(
            provider,
            &decoded.provider_id,
            decoded.organization_id.as_deref(),
            &decoded.base_token,
        ) {
            return Ok(Some(AuthenticatedScimProvider {
                provider_id: provider.provider_id.clone(),
                organization_id: provider.organization_id.clone(),
            }));
        }
    }

    let Some(provider) = ScimProviderStore::new(adapter)
        .find_by_provider_id(&decoded.provider_id)
        .await?
    else {
        return Ok(None);
    };
    if provider.organization_id != decoded.organization_id {
        return Ok(None);
    }
    if provider_matches(
        &provider,
        &options.token_storage,
        &decoded.base_token,
        secret,
    )
    .await?
    {
        Ok(Some(AuthenticatedScimProvider {
            provider_id: provider.provider_id,
            organization_id: provider.organization_id,
        }))
    } else {
        Ok(None)
    }
}

fn bearer_token(request: &ApiRequest) -> Option<&str> {
    let value = authorization_header(request)?.trim();
    let mut parts = value.split_whitespace();
    let scheme = parts.next()?;
    let token = parts.next()?;
    if parts.next().is_some() || token.is_empty() {
        return None;
    }
    scheme.eq_ignore_ascii_case("Bearer").then_some(token)
}

fn authorization_header(request: &ApiRequest) -> Option<&str> {
    request.headers().get(header::AUTHORIZATION)?.to_str().ok()
}

fn scim_auth_error(request: &ApiRequest) -> ScimError {
    if authorization_header(request).is_some() {
        ScimError::unauthorized("Invalid SCIM token")
    } else {
        ScimError::unauthorized("SCIM token is required")
    }
}

async fn current_user(
    context: &openauth_core::context::AuthContext,
    adapter: &dyn DbAdapter,
    request: &ApiRequest,
) -> Result<Option<User>, OpenAuthError> {
    let cookie_header = request
        .headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let Some(result) = SessionAuth::new(adapter, context)
        .get_session(GetSessionInput::new(cookie_header))
        .await?
    else {
        return Ok(None);
    };
    Ok(result.user)
}

fn organization_creator_role(context: &openauth_core::context::AuthContext) -> Option<String> {
    context
        .plugins
        .iter()
        .find(|plugin| plugin.id == "organization")
        .and_then(|plugin| plugin.options.as_ref())
        .and_then(|options| options.get("creatorRole"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

async fn provider_access_allowed(
    adapter: &dyn DbAdapter,
    provider: &ScimProviderRecord,
    user: &User,
    options: &ScimOptions,
    creator_role: Option<&str>,
) -> Result<bool, OpenAuthError> {
    if let Some(organization_id) = provider.organization_id.as_deref() {
        return Ok(member_role(adapter, organization_id, &user.id)
            .await?
            .map(|role| {
                role_has_required_access(&role, options.required_role.as_deref(), creator_role)
            })
            .unwrap_or(false));
    }
    if options.provider_ownership.enabled {
        return Ok(match provider.user_id.as_deref() {
            Some(user_id) => user_id == user.id,
            None => true,
        });
    }
    Ok(true)
}

async fn store_scim_token(
    secret: &str,
    storage: &ScimTokenStorage,
    base_token: &str,
) -> Result<String, OpenAuthError> {
    match storage {
        ScimTokenStorage::Plain => Ok(base_token.to_owned()),
        ScimTokenStorage::Hashed => Ok(hash_base_token(base_token)),
        ScimTokenStorage::Encrypted => symmetric_encrypt(secret, base_token),
        ScimTokenStorage::CustomHash { hash } => hash(base_token.to_owned()).await,
        ScimTokenStorage::CustomEncryption { encrypt, .. } => encrypt(base_token.to_owned()).await,
    }
}

fn query_param(request: &ApiRequest, name: &str) -> Option<String> {
    request.uri().query()?.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        (key == name).then(|| percent_decode_component(value))
    })
}

fn percent_decode_component(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hex = &value[index + 1..index + 3];
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    decoded.push(byte);
                    index += 3;
                } else {
                    decoded.push(bytes[index]);
                    index += 1;
                }
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }

    String::from_utf8_lossy(&decoded).into_owned()
}

fn json<T: Serialize>(status: StatusCode, body: &T) -> Result<ApiResponse, OpenAuthError> {
    let body = serde_json::to_vec(body).map_err(|error| OpenAuthError::Api(error.to_string()))?;
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .map_err(|error| OpenAuthError::Api(error.to_string()))
}

fn json_error(status: StatusCode, code: &str, message: &str) -> Result<ApiResponse, OpenAuthError> {
    json(
        status,
        &serde_json::json!({
            "code": code,
            "message": message,
        }),
    )
}

fn hook_error(error: ScimHookError) -> Result<ApiResponse, OpenAuthError> {
    json_error(error.status, &error.code, &error.message)
}

fn default_provider_matches(
    provider: &DefaultScimProvider,
    provider_id: &str,
    organization_id: Option<&str>,
    base_token: &str,
) -> bool {
    provider.provider_id == provider_id
        && provider.organization_id.as_deref() == organization_id
        && plain_token_matches(&provider.scim_token, base_token)
}

async fn provider_matches(
    provider: &ScimProviderRecord,
    storage: &ScimTokenStorage,
    base_token: &str,
    secret: &str,
) -> Result<bool, OpenAuthError> {
    token_matches(&provider.scim_token, storage, base_token, secret).await
}

async fn token_matches(
    stored: &str,
    storage: &ScimTokenStorage,
    base_token: &str,
    secret: &str,
) -> Result<bool, OpenAuthError> {
    let candidate = match storage {
        ScimTokenStorage::Plain => base_token.to_owned(),
        ScimTokenStorage::Hashed => hash_base_token(base_token),
        ScimTokenStorage::Encrypted => {
            return Ok(plain_token_matches(
                &symmetric_decrypt(secret, stored)?,
                base_token,
            ));
        }
        ScimTokenStorage::CustomHash { hash } => hash(base_token.to_owned()).await?,
        ScimTokenStorage::CustomEncryption { decrypt, .. } => {
            return Ok(plain_token_matches(
                &decrypt(stored.to_owned()).await?,
                base_token,
            ));
        }
    };
    Ok(plain_token_matches(stored, &candidate))
}

fn plain_token_matches(stored: &str, candidate: &str) -> bool {
    stored.len() == candidate.len() && stored.as_bytes().ct_eq(candidate.as_bytes()).into()
}

async fn find_scim_user(
    adapter: &dyn DbAdapter,
    user_id: &str,
    provider_id: &str,
    organization_id: Option<&str>,
) -> Result<Option<(User, Account)>, OpenAuthError> {
    if let Some(organization_id) = organization_id {
        if member_role(adapter, organization_id, user_id)
            .await?
            .is_none()
        {
            return Ok(None);
        }
    }
    let users = DbUserStore::new(adapter);
    let accounts = users.list_accounts_for_user(user_id).await?;
    let Some(account) = accounts
        .into_iter()
        .find(|account| account.provider_id == provider_id)
    else {
        return Ok(None);
    };
    let Some(user) = users.find_user_by_id(user_id).await? else {
        return Ok(None);
    };
    Ok(Some((user, account)))
}

async fn member_role(
    adapter: &dyn DbAdapter,
    organization_id: &str,
    user_id: &str,
) -> Result<Option<String>, OpenAuthError> {
    Ok(organization_member(adapter, organization_id, user_id)
        .await?
        .map(|member| member.role))
}

async fn organization_member(
    adapter: &dyn DbAdapter,
    organization_id: &str,
    user_id: &str,
) -> Result<Option<ScimOrganizationMember>, OpenAuthError> {
    let member = adapter
        .find_one(
            FindOne::new("member")
                .where_clause(Where::new(
                    "organization_id",
                    DbValue::String(organization_id.to_owned()),
                ))
                .where_clause(Where::new("user_id", DbValue::String(user_id.to_owned())))
                .select(["role"]),
        )
        .await?;
    let Some(member) = member else {
        return Ok(None);
    };
    match member.get("role") {
        Some(DbValue::String(role)) => Ok(Some(ScimOrganizationMember {
            organization_id: organization_id.to_owned(),
            user_id: user_id.to_owned(),
            role: role.to_owned(),
        })),
        Some(DbValue::Null) | None => Ok(None),
        Some(_) => Err(OpenAuthError::Adapter(
            "member field `role` must be string or null".to_owned(),
        )),
    }
}

fn role_has_required_access(
    role: &str,
    required: Option<&[String]>,
    creator_role: Option<&str>,
) -> bool {
    let roles = parse_roles(role);
    match required {
        Some([]) => true,
        Some(required) => roles
            .iter()
            .any(|role| required.iter().any(|required| role == required)),
        _ => {
            let creator_role = creator_role.unwrap_or("owner");
            roles
                .iter()
                .any(|role| role == "admin" || role == creator_role)
        }
    }
}

fn parse_roles(role: &str) -> Vec<String> {
    role.split(',')
        .map(str::trim)
        .filter(|role| !role.is_empty())
        .map(str::to_owned)
        .collect()
}

async fn create_org_membership_if_missing(
    adapter: &dyn DbAdapter,
    organization_id: &str,
    user_id: &str,
) -> Result<(), OpenAuthError> {
    if member_role(adapter, organization_id, user_id)
        .await?
        .is_some()
    {
        return Ok(());
    }
    adapter
        .create(
            Create::new("member")
                .data("id", DbValue::String(generate_random_string(32)))
                .data(
                    "organization_id",
                    DbValue::String(organization_id.to_owned()),
                )
                .data("user_id", DbValue::String(user_id.to_owned()))
                .data("role", DbValue::String("member".to_owned()))
                .data("created_at", DbValue::Timestamp(OffsetDateTime::now_utc()))
                .force_allow_id(),
        )
        .await?;
    Ok(())
}

#[derive(Debug, Clone)]
struct CreateScimUserResult {
    user: User,
    account: Account,
}

async fn create_scim_user_account_and_membership(
    adapter: &dyn DbAdapter,
    existing_user: Option<User>,
    user_input: CreateUserInput,
    mut account_input: CreateOAuthAccountInput,
    organization_id: Option<String>,
) -> Result<(User, Account), OpenAuthError> {
    let result = Arc::new(Mutex::new(None));
    let result_for_transaction = Arc::clone(&result);
    let transaction_status = adapter
        .transaction(Box::new(move |transaction| {
            Box::pin(async move {
                let users = DbUserStore::new(transaction.as_ref());
                let user = match existing_user {
                    Some(user) => user,
                    None => users.create_user(user_input).await?,
                };
                account_input.user_id = user.id.clone();
                let account = users.link_account(account_input).await?;
                if let Some(organization_id) = organization_id.as_deref() {
                    create_org_membership_if_missing(
                        transaction.as_ref(),
                        organization_id,
                        &user.id,
                    )
                    .await?;
                }
                store_create_scim_user_result(
                    &result_for_transaction,
                    CreateScimUserResult { user, account },
                )?;
                Ok(())
            })
        }))
        .await;

    match transaction_status {
        Ok(()) => take_create_scim_user_result(&result)?
            .map(|result| (result.user, result.account))
            .ok_or_else(|| {
                OpenAuthError::Adapter(
                    "create SCIM user transaction completed without a result".to_owned(),
                )
            }),
        Err(error) => Err(error),
    }
}

fn store_create_scim_user_result(
    result: &Mutex<Option<CreateScimUserResult>>,
    value: CreateScimUserResult,
) -> Result<(), OpenAuthError> {
    let mut guard = result.lock().map_err(|_| {
        OpenAuthError::Adapter("create SCIM user result mutex was poisoned".to_owned())
    })?;
    *guard = Some(value);
    Ok(())
}

fn take_create_scim_user_result(
    result: &Mutex<Option<CreateScimUserResult>>,
) -> Result<Option<CreateScimUserResult>, OpenAuthError> {
    let mut guard = result.lock().map_err(|_| {
        OpenAuthError::Adapter("create SCIM user result mutex was poisoned".to_owned())
    })?;
    Ok(guard.take())
}

fn user_matches_filters(user: &User, filters: &[ScimDbFilter]) -> bool {
    filters.iter().all(|filter| match filter.operator {
        ScimFilterOperator::Eq if filter.field == "email" => user.email == filter.value,
        ScimFilterOperator::Eq => false,
    })
}

fn validate_emails(emails: &[ScimEmail]) -> Result<(), ScimError> {
    for email in emails {
        if !is_valid_email(&email.value) {
            return Err(
                ScimError::bad_request("emails.value must be a valid email address")
                    .with_scim_type("invalidValue"),
            );
        }
    }
    Ok(())
}

fn is_valid_email(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() || value.contains(char::is_whitespace) {
        return false;
    }
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains('@')
}

async fn update_account_id(
    adapter: &dyn DbAdapter,
    account_record_id: &str,
    account_id: &str,
) -> Result<(), OpenAuthError> {
    adapter
        .update(
            Update::new("account")
                .where_clause(Where::new(
                    "id",
                    DbValue::String(account_record_id.to_owned()),
                ))
                .data("account_id", DbValue::String(account_id.to_owned()))
                .data("updated_at", DbValue::Timestamp(OffsetDateTime::now_utc())),
        )
        .await?;
    Ok(())
}

async fn update_scim_user_and_account(
    adapter: &dyn DbAdapter,
    user_id: &str,
    account_record_id: &str,
    email: Option<String>,
    name: Option<String>,
    account_id: Option<String>,
) -> Result<(), OpenAuthError> {
    let user_id = user_id.to_owned();
    let account_record_id = account_record_id.to_owned();
    adapter
        .transaction(Box::new(move |transaction| {
            Box::pin(async move {
                let users = DbUserStore::new(transaction.as_ref());
                if let Some(email) = email {
                    users.update_user_email(&user_id, &email, true).await?;
                }
                if let Some(name) = name {
                    users
                        .update_user(&user_id, UpdateUserInput::new().name(name))
                        .await?;
                }
                if let Some(account_id) = account_id {
                    update_account_id(transaction.as_ref(), &account_record_id, &account_id)
                        .await?;
                }
                Ok(())
            })
        }))
        .await
}

fn user_from_record(record: DbRecord) -> Result<User, OpenAuthError> {
    Ok(User {
        id: required_string(&record, "id")?.to_owned(),
        name: required_string(&record, "name")?.to_owned(),
        email: required_string(&record, "email")?.to_owned(),
        email_verified: required_bool(&record, "email_verified")?,
        image: optional_string(&record, "image")?,
        username: optional_string(&record, "username")?,
        display_username: optional_string(&record, "display_username")?,
        created_at: required_timestamp(&record, "created_at")?,
        updated_at: required_timestamp(&record, "updated_at")?,
    })
}

fn required_string<'a>(record: &'a DbRecord, field: &str) -> Result<&'a str, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(value),
        Some(_) => Err(OpenAuthError::Adapter(format!(
            "user field `{field}` must be string"
        ))),
        None => Err(OpenAuthError::Adapter(format!("user is missing `{field}`"))),
    }
}

fn required_bool(record: &DbRecord, field: &str) -> Result<bool, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Boolean(value)) => Ok(*value),
        Some(_) => Err(OpenAuthError::Adapter(format!(
            "user field `{field}` must be boolean"
        ))),
        None => Err(OpenAuthError::Adapter(format!("user is missing `{field}`"))),
    }
}

fn required_timestamp(record: &DbRecord, field: &str) -> Result<OffsetDateTime, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Timestamp(value)) => Ok(*value),
        Some(_) => Err(OpenAuthError::Adapter(format!(
            "user field `{field}` must be timestamp"
        ))),
        None => Err(OpenAuthError::Adapter(format!("user is missing `{field}`"))),
    }
}

fn optional_string(record: &DbRecord, field: &str) -> Result<Option<String>, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(Some(value.to_owned())),
        Some(DbValue::Null) | None => Ok(None),
        Some(_) => Err(OpenAuthError::Adapter(format!(
            "user field `{field}` must be string or null"
        ))),
    }
}
