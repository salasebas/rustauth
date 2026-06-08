use super::*;

pub(super) fn bulk_endpoint(options: Arc<ScimOptions>) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/v2/Bulk",
        Method::POST,
        scim_endpoint_options("bulkSCIM", "Run SCIM Bulk operations")
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
                if let Err(error) = ensure_scim_provider_scope_supported(context, &provider) {
                    return error.into_response();
                }
                if request.body().len() > metadata::SCIM_BULK_MAX_PAYLOAD_SIZE {
                    return ScimError::bad_request("Bulk payload exceeds maxPayloadSize")
                        .with_scim_type("tooMany")
                        .into_response();
                }
                let body: BulkRequest = match serde_json::from_slice(request.body()) {
                    Ok(body) => body,
                    Err(error) => {
                        return ScimError::bad_request(format!(
                            "invalid JSON request body: {error}"
                        ))
                        .into_response();
                    }
                };
                if !body.schemas.is_empty()
                    && !body
                        .schemas
                        .iter()
                        .any(|schema| schema == BULK_REQUEST_SCHEMA)
                {
                    return ScimError::bad_request("Invalid schemas for BulkRequest")
                        .with_scim_type("invalidValue")
                        .into_response();
                }
                if body.operations.len() > metadata::SCIM_BULK_MAX_OPERATIONS {
                    return ScimError::bad_request("Bulk request exceeds maxOperations")
                        .with_scim_type("tooMany")
                        .into_response();
                }
                let operations = match process_bulk_operations(
                    adapter.as_ref(),
                    context,
                    &options,
                    &provider,
                    body.fail_on_errors,
                    body.operations,
                )
                .await
                {
                    Ok(operations) => operations,
                    Err(OpenAuthError::InvalidConfig(message))
                        if message.contains("Atomic bulk requires") =>
                    {
                        return ScimError::bad_request(message)
                            .with_scim_type("invalidValue")
                            .into_response();
                    }
                    Err(error) => return Err(error),
                };
                scim_json(
                    StatusCode::OK,
                    &BulkResponse {
                        schemas: vec![BULK_RESPONSE_SCHEMA.to_owned()],
                        operations,
                    },
                )
            })
        },
    )
}

async fn process_bulk_operations(
    adapter: &dyn DbAdapter,
    context: &openauth_core::context::AuthContext,
    options: &ScimOptions,
    provider: &AuthenticatedScimProvider,
    fail_on_errors: Option<u64>,
    operations: Vec<BulkOperationRequest>,
) -> Result<Vec<BulkOperationResponse>, OpenAuthError> {
    match options.bulk_mode {
        ScimBulkMode::Independent => {
            process_bulk_operations_independent(
                adapter,
                context,
                options,
                provider,
                fail_on_errors,
                operations,
            )
            .await
        }
        ScimBulkMode::Atomic => {
            process_bulk_operations_atomic(adapter, context, options, provider, operations).await
        }
    }
}

async fn process_bulk_operations_independent(
    adapter: &dyn DbAdapter,
    context: &openauth_core::context::AuthContext,
    options: &ScimOptions,
    provider: &AuthenticatedScimProvider,
    fail_on_errors: Option<u64>,
    operations: Vec<BulkOperationRequest>,
) -> Result<Vec<BulkOperationResponse>, OpenAuthError> {
    let mut responses = Vec::new();
    let mut errors = 0_u64;
    let mut bulk_ids = std::collections::BTreeMap::new();
    let organization_options =
        openauth_plugins::organization::organization_options_from_context(context);
    for operation in operations {
        let result = execute_bulk_operation(
            organization_options.clone(),
            adapter,
            &context.base_url,
            options,
            provider,
            &mut bulk_ids,
            operation,
        )
        .await?;
        if result.status.code >= 400 {
            errors += 1;
            emit_bulk_failure(context, options, provider, &result).await;
        }
        responses.push(result);
        if fail_on_errors.is_some_and(|limit| errors >= limit) {
            break;
        }
    }
    Ok(responses)
}

async fn process_bulk_operations_atomic(
    adapter: &dyn DbAdapter,
    context: &openauth_core::context::AuthContext,
    options: &ScimOptions,
    provider: &AuthenticatedScimProvider,
    operations: Vec<BulkOperationRequest>,
) -> Result<Vec<BulkOperationResponse>, OpenAuthError> {
    if !adapter.capabilities().supports_transactions {
        return Err(OpenAuthError::InvalidConfig(
            "Atomic bulk requires a database adapter with native transaction support".to_owned(),
        ));
    }
    let options_for_audit = options.clone();
    let options = options.clone();
    let provider_for_audit = provider.clone();
    let provider = provider.clone();
    let base_url = context.base_url.clone();
    let organization_options =
        openauth_plugins::organization::organization_options_from_context(context);
    let responses = Arc::new(Mutex::new(Vec::new()));
    let responses_for_transaction = Arc::clone(&responses);
    let transaction_result = adapter
        .transaction(Box::new(move |transaction| {
            let base_url = base_url.clone();
            let options = options.clone();
            let provider = provider.clone();
            let organization_options = organization_options.clone();
            let responses = Arc::clone(&responses_for_transaction);
            let mut bulk_ids = std::collections::BTreeMap::new();
            Box::pin(async move {
                for operation in operations {
                    let result = execute_bulk_operation(
                        organization_options.clone(),
                        transaction.as_ref(),
                        &base_url,
                        &options,
                        &provider,
                        &mut bulk_ids,
                        operation,
                    )
                    .await?;
                    let failed = result.status.code >= 400;
                    responses
                        .lock()
                        .map_err(|_| {
                            OpenAuthError::Adapter(
                                "atomic bulk response mutex was poisoned".to_owned(),
                            )
                        })?
                        .push(result);
                    if failed {
                        return Err(OpenAuthError::Adapter(
                            "atomic bulk operation failed".to_owned(),
                        ));
                    }
                }
                Ok(())
            })
        }))
        .await;

    let responses = Arc::try_unwrap(responses)
        .map_err(|_| OpenAuthError::Adapter("atomic bulk responses still shared".to_owned()))?
        .into_inner()
        .map_err(|_| {
            OpenAuthError::Adapter("atomic bulk response mutex was poisoned".to_owned())
        })?;

    if transaction_result.is_ok() {
        return Ok(responses);
    }

    let rolled_back = mark_atomic_bulk_rollback(responses);
    crate::audit::emit(
        context,
        &options_for_audit,
        ScimAuditEvent::new(ScimAuditEventKind::BulkRolledBack, ScimAuditSeverity::Warn)
            .with_provider_id(&provider_for_audit.provider_id)
            .with_reason("atomic bulk failure"),
    )
    .await;
    if let Some(failure) = rolled_back
        .iter()
        .find(|response| response.status.code >= 400)
    {
        emit_bulk_failure(context, &options_for_audit, &provider_for_audit, failure).await;
    }
    Ok(rolled_back)
}

fn mark_atomic_bulk_rollback(
    mut responses: Vec<BulkOperationResponse>,
) -> Vec<BulkOperationResponse> {
    let Some(failure_index) = responses
        .iter()
        .position(|response| response.status.code >= 400)
    else {
        return responses;
    };
    for response in &mut responses[..failure_index] {
        if response.status.code < 400 {
            let error =
                ScimError::precondition_failed("Operation rolled back due to atomic bulk failure");
            response.status.code = error.status.as_u16();
            response.location = None;
            response.version = None;
            response.response =
                Some(serde_json::to_value(error.body()).unwrap_or_else(|_| serde_json::json!({})));
        }
    }
    responses.truncate(failure_index + 1);
    responses
}

async fn emit_bulk_failure(
    context: &openauth_core::context::AuthContext,
    options: &ScimOptions,
    provider: &AuthenticatedScimProvider,
    response: &BulkOperationResponse,
) {
    let detail = response
        .response
        .as_ref()
        .and_then(|body| body.get("detail"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("bulk operation failed");
    let mut event = ScimAuditEvent::new(ScimAuditEventKind::BulkFailed, ScimAuditSeverity::Warn)
        .with_provider_id(&provider.provider_id)
        .with_reason(detail);
    if let Some(organization_id) = provider.organization_id.as_deref() {
        event = event.with_organization_id(organization_id);
    }
    crate::audit::emit(context, options, event).await;
}

async fn execute_bulk_operation(
    organization_options: Option<
        std::sync::Arc<openauth_plugins::organization::OrganizationOptions>,
    >,
    adapter: &dyn DbAdapter,
    base_url: &str,
    options: &ScimOptions,
    provider: &AuthenticatedScimProvider,
    bulk_ids: &mut std::collections::BTreeMap<String, String>,
    operation: BulkOperationRequest,
) -> Result<BulkOperationResponse, OpenAuthError> {
    let method = operation.method.to_ascii_uppercase();
    let path = match resolve_bulk_path(&operation.path, bulk_ids) {
        Ok(path) => path,
        Err(error) => {
            return bulk_error_response(method, Some(operation.path), operation.bulk_id, error);
        }
    };
    if let Some(version) = operation.version.as_deref() {
        if let Some(error_response) = validate_bulk_operation_version(
            adapter,
            base_url,
            provider,
            &method,
            &path,
            operation.bulk_id.clone(),
            version,
        )
        .await?
        {
            return Ok(error_response);
        }
    }
    if method == "POST" && operation.bulk_id.is_none() {
        return bulk_error_response(
            method,
            Some(path),
            None,
            ScimError::bad_request("bulkId is required for Bulk POST operations")
                .with_scim_type("invalidValue"),
        );
    }
    if method == "GET" {
        if let Some(user_id) = path.strip_prefix("/Users/") {
            let response = match find_scim_user(
                adapter,
                user_id,
                &provider.provider_id,
                provider.organization_id.as_deref(),
            )
            .await?
            {
                Some((user, account)) => {
                    let resource =
                        complete_user_resource(adapter, base_url, provider, &user, &account)
                            .await?;
                    Some((
                        StatusCode::OK,
                        serde_json::to_value(resource)
                            .map_err(|error| OpenAuthError::Api(error.to_string()))?,
                    ))
                }
                None => Some((
                    StatusCode::NOT_FOUND,
                    serde_json::to_value(ScimError::not_found("User not found").body())
                        .map_err(|error| OpenAuthError::Api(error.to_string()))?,
                )),
            };
            if let Some((status, response)) = response {
                return Ok(BulkOperationResponse {
                    method,
                    path: Some(path),
                    bulk_id: operation.bulk_id,
                    status: BulkOperationStatus {
                        code: status.as_u16(),
                    },
                    location: bulk_response_location(&response),
                    version: bulk_response_version(&response),
                    response: Some(response),
                });
            }
        }
        if let Some(group_id) = path.strip_prefix("/Groups/") {
            let response = match provider.organization_id.as_deref() {
                Some(organization_id) => {
                    match load_group_resource(
                        adapter,
                        base_url,
                        &provider.provider_id,
                        organization_id,
                        group_id,
                    )
                    .await?
                    {
                        Some(resource) => (
                            StatusCode::OK,
                            serde_json::to_value(resource)
                                .map_err(|error| OpenAuthError::Api(error.to_string()))?,
                        ),
                        None => (
                            StatusCode::NOT_FOUND,
                            serde_json::to_value(ScimError::not_found("Group not found").body())
                                .map_err(|error| OpenAuthError::Api(error.to_string()))?,
                        ),
                    }
                }
                None => (
                    StatusCode::BAD_REQUEST,
                    serde_json::to_value(groups_require_organization().body())
                        .map_err(|error| OpenAuthError::Api(error.to_string()))?,
                ),
            };
            return Ok(BulkOperationResponse {
                method,
                path: Some(path),
                bulk_id: operation.bulk_id,
                status: BulkOperationStatus {
                    code: response.0.as_u16(),
                },
                location: bulk_response_location(&response.1),
                version: bulk_response_version(&response.1),
                response: Some(response.1),
            });
        }
    }
    if method == "POST" && path == "/Users" {
        let Some(data) = operation.data.clone() else {
            return bulk_error_response(
                method,
                Some(path),
                operation.bulk_id,
                ScimError::bad_request("Bulk data is required"),
            );
        };
        let response =
            bulk_create_user(organization_options, adapter, base_url, provider, data).await?;
        if let (Some(bulk_id), Some(id)) = (operation.bulk_id.as_ref(), response.2.as_ref()) {
            bulk_ids.insert(bulk_id.clone(), format!("/Users/{id}"));
        }
        return Ok(BulkOperationResponse {
            method,
            path: Some(path),
            bulk_id: operation.bulk_id,
            status: BulkOperationStatus {
                code: response.0.as_u16(),
            },
            location: bulk_response_location(&response.1),
            version: bulk_response_version(&response.1),
            response: Some(response.1),
        });
    }
    if method == "POST" && path == "/Groups" {
        let Some(data) = operation.data.clone() else {
            return bulk_error_response(
                method,
                Some(path),
                operation.bulk_id,
                ScimError::bad_request("Bulk data is required"),
            );
        };
        let response = bulk_create_group(adapter, base_url, provider, bulk_ids, data).await?;
        if let (Some(bulk_id), Some(id)) = (operation.bulk_id.as_ref(), response.2.as_ref()) {
            bulk_ids.insert(bulk_id.clone(), format!("/Groups/{id}"));
        }
        return Ok(BulkOperationResponse {
            method,
            path: Some(path),
            bulk_id: operation.bulk_id,
            status: BulkOperationStatus {
                code: response.0.as_u16(),
            },
            location: bulk_response_location(&response.1),
            version: bulk_response_version(&response.1),
            response: Some(response.1),
        });
    }
    if method == "PUT" {
        let Some(data) = operation.data.clone() else {
            return bulk_error_response(
                method,
                Some(path),
                operation.bulk_id,
                ScimError::bad_request("Bulk data is required"),
            );
        };
        if let Some(user_id) = path.strip_prefix("/Users/") {
            let response = bulk_update_user(adapter, base_url, provider, user_id, data).await?;
            return Ok(BulkOperationResponse {
                method,
                path: Some(path),
                bulk_id: operation.bulk_id,
                status: BulkOperationStatus {
                    code: response.0.as_u16(),
                },
                location: bulk_response_location(&response.1),
                version: bulk_response_version(&response.1),
                response: Some(response.1),
            });
        }
        if let Some(group_id) = path.strip_prefix("/Groups/") {
            let response = bulk_replace_group(adapter, base_url, provider, group_id, data).await?;
            return Ok(BulkOperationResponse {
                method,
                path: Some(path),
                bulk_id: operation.bulk_id,
                status: BulkOperationStatus {
                    code: response.0.as_u16(),
                },
                location: bulk_response_location(&response.1),
                version: bulk_response_version(&response.1),
                response: Some(response.1),
            });
        }
    }
    if method == "PATCH" {
        let Some(data) = operation.data.clone() else {
            return bulk_error_response(
                method,
                Some(path),
                operation.bulk_id,
                ScimError::bad_request("Bulk data is required"),
            );
        };
        if let Some(user_id) = path.strip_prefix("/Users/") {
            let response = bulk_patch_user(adapter, base_url, provider, user_id, data).await?;
            return Ok(BulkOperationResponse {
                method,
                path: Some(path),
                bulk_id: operation.bulk_id,
                status: BulkOperationStatus {
                    code: response.0.as_u16(),
                },
                location: bulk_response_location(&response.1),
                version: bulk_response_version(&response.1),
                response: Some(response.1),
            });
        }
        if let Some(group_id) = path.strip_prefix("/Groups/") {
            let response = bulk_patch_group(adapter, base_url, provider, group_id, data).await?;
            return Ok(BulkOperationResponse {
                method,
                path: Some(path),
                bulk_id: operation.bulk_id,
                status: BulkOperationStatus {
                    code: response.0.as_u16(),
                },
                location: bulk_response_location(&response.1),
                version: bulk_response_version(&response.1),
                response: Some(response.1),
            });
        }
    }
    if method == "DELETE" {
        if let Some(user_id) = path.strip_prefix("/Users/") {
            let Some((user, _account)) = find_scim_user(
                adapter,
                user_id,
                &provider.provider_id,
                provider.organization_id.as_deref(),
            )
            .await?
            else {
                return bulk_error_response(
                    method,
                    Some(path),
                    operation.bulk_id,
                    ScimError::not_found("User not found"),
                );
            };
            deprovision_scim_user(
                adapter,
                &user.id,
                &provider.provider_id,
                provider.organization_id.as_deref(),
                options.deprovision_mode,
            )
            .await?;
            return Ok(BulkOperationResponse {
                method,
                path: Some(path),
                bulk_id: operation.bulk_id,
                status: BulkOperationStatus {
                    code: StatusCode::NO_CONTENT.as_u16(),
                },
                location: None,
                version: None,
                response: None,
            });
        }
        if let Some(group_id) = path.strip_prefix("/Groups/") {
            let Some(organization_id) = provider.organization_id.as_deref() else {
                return bulk_error_response(
                    method,
                    Some(path),
                    operation.bulk_id,
                    groups_require_organization(),
                );
            };
            if load_group_resource(
                adapter,
                base_url,
                &provider.provider_id,
                organization_id,
                group_id,
            )
            .await?
            .is_none()
            {
                return bulk_error_response(
                    method,
                    Some(path),
                    operation.bulk_id,
                    ScimError::not_found("Group not found"),
                );
            }
            delete_group(adapter, organization_id, &provider.provider_id, group_id).await?;
            return Ok(BulkOperationResponse {
                method,
                path: Some(path),
                bulk_id: operation.bulk_id,
                status: BulkOperationStatus {
                    code: StatusCode::NO_CONTENT.as_u16(),
                },
                location: None,
                version: None,
                response: None,
            });
        }
    }
    Ok(BulkOperationResponse {
        method,
        path: Some(path),
        bulk_id: operation.bulk_id,
        status: BulkOperationStatus {
            code: StatusCode::NOT_IMPLEMENTED.as_u16(),
        },
        location: None,
        version: None,
        response: Some(
            serde_json::to_value(
                ScimError::not_implemented("Bulk operation is not implemented").body(),
            )
            .map_err(|error| OpenAuthError::Api(error.to_string()))?,
        ),
    })
}

async fn validate_bulk_operation_version(
    adapter: &dyn DbAdapter,
    base_url: &str,
    provider: &AuthenticatedScimProvider,
    method: &str,
    path: &str,
    bulk_id: Option<String>,
    version: &str,
) -> Result<Option<BulkOperationResponse>, OpenAuthError> {
    let current_version = if let Some(user_id) = path.strip_prefix("/Users/") {
        match find_scim_user(
            adapter,
            user_id,
            &provider.provider_id,
            provider.organization_id.as_deref(),
        )
        .await?
        {
            Some((user, account)) => {
                complete_user_resource(adapter, base_url, provider, &user, &account)
                    .await
                    .map(|resource| resource.meta.version)?
            }
            None => None,
        }
    } else if let Some(group_id) = path.strip_prefix("/Groups/") {
        match provider.organization_id.as_deref() {
            Some(organization_id) => load_group_resource(
                adapter,
                base_url,
                &provider.provider_id,
                organization_id,
                group_id,
            )
            .await?
            .and_then(|resource| resource.meta.version),
            None => None,
        }
    } else {
        None
    };
    if current_version
        .as_deref()
        .is_some_and(|current| current == version)
    {
        return Ok(None);
    }
    Ok(Some(BulkOperationResponse {
        method: method.to_owned(),
        path: Some(path.to_owned()),
        bulk_id,
        status: BulkOperationStatus {
            code: StatusCode::PRECONDITION_FAILED.as_u16(),
        },
        location: None,
        version: current_version,
        response: Some(
            serde_json::to_value(
                ScimError::precondition_failed("Resource version does not match").body(),
            )
            .map_err(|error| OpenAuthError::Api(error.to_string()))?,
        ),
    }))
}

fn resolve_bulk_path(
    path: &str,
    bulk_ids: &std::collections::BTreeMap<String, String>,
) -> Result<String, ScimError> {
    let Some(bulk_id) = path.strip_prefix("bulkId:") else {
        return Ok(path.to_owned());
    };
    bulk_ids.get(bulk_id).cloned().ok_or_else(|| {
        ScimError::bad_request(format!("Unresolved bulkId reference: {bulk_id}"))
            .with_scim_type("invalidValue")
    })
}

fn bulk_error_response(
    method: String,
    path: Option<String>,
    bulk_id: Option<String>,
    error: ScimError,
) -> Result<BulkOperationResponse, OpenAuthError> {
    Ok(BulkOperationResponse {
        method,
        path,
        bulk_id,
        status: BulkOperationStatus {
            code: error.status.as_u16(),
        },
        location: None,
        version: None,
        response: Some(
            serde_json::to_value(error.body())
                .map_err(|serialize_error| OpenAuthError::Api(serialize_error.to_string()))?,
        ),
    })
}

fn scim_error_value(error: ScimError) -> Result<(StatusCode, serde_json::Value), OpenAuthError> {
    Ok((
        error.status,
        serde_json::to_value(error.body())
            .map_err(|serialize_error| OpenAuthError::Api(serialize_error.to_string()))?,
    ))
}

fn invalid_bulk_data(error: serde_json::Error) -> ScimError {
    ScimError::bad_request(format!("Invalid Bulk operation data: {error}"))
        .with_scim_type("invalidValue")
}

fn scim_or_openauth_value(
    error: ScimErrorOrOpenAuth,
) -> Result<(StatusCode, serde_json::Value), OpenAuthError> {
    match error {
        ScimErrorOrOpenAuth::Scim(error) => scim_error_value(error),
        ScimErrorOrOpenAuth::OpenAuth(error) => Err(error),
    }
}

fn bulk_response_location(response: &serde_json::Value) -> Option<String> {
    response
        .get("meta")
        .and_then(|meta| meta.get("location"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

fn bulk_response_version(response: &serde_json::Value) -> Option<String> {
    response
        .get("meta")
        .and_then(|meta| meta.get("version"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

async fn bulk_create_user(
    organization_options: Option<
        std::sync::Arc<openauth_plugins::organization::OrganizationOptions>,
    >,
    adapter: &dyn DbAdapter,
    base_url: &str,
    provider: &AuthenticatedScimProvider,
    data: serde_json::Value,
) -> Result<(StatusCode, serde_json::Value, Option<String>), OpenAuthError> {
    let mut input: ScimUserInput = match serde_json::from_value(data) {
        Ok(input) => input,
        Err(error) => {
            let (status, body) = scim_error_value(invalid_bulk_data(error))?;
            return Ok((status, body, None));
        }
    };
    input.user_name = input.user_name.to_ascii_lowercase();
    let emails = input.emails.clone().unwrap_or_default();
    if let Err(error) = validate_emails(&emails) {
        return Ok((
            error.status,
            serde_json::to_value(error.body())
                .map_err(|serialize_error| OpenAuthError::Api(serialize_error.to_string()))?,
            None,
        ));
    }
    if let Err(error) = validate_multivalued_primary_attributes(&input.additional_fields) {
        return Ok((
            error.status,
            serde_json::to_value(error.body())
                .map_err(|serialize_error| OpenAuthError::Api(serialize_error.to_string()))?,
            None,
        ));
    }
    if let Err(error) = validate_scim_user_profile_attributes(&input) {
        return Ok((
            error.status,
            serde_json::to_value(error.body())
                .map_err(|serialize_error| OpenAuthError::Api(serialize_error.to_string()))?,
            None,
        ));
    }
    let email = match validate_scim_user_identity(&input.user_name, &emails) {
        Ok(email) => email,
        Err(error) => {
            return Ok((
                error.status,
                serde_json::to_value(error.body())
                    .map_err(|serialize_error| OpenAuthError::Api(serialize_error.to_string()))?,
                None,
            ));
        }
    };
    let name = user_full_name(&email, input.name.as_ref());
    let account_id = account_id(&input.user_name, input.external_id.as_deref());
    let users = DbUserStore::new(adapter);
    if users
        .find_account_by_provider_account(&account_id, &provider.provider_id)
        .await?
        .is_some()
    {
        let error = ScimError::conflict("User already exists").with_scim_type("uniqueness");
        return Ok((
            error.status,
            serde_json::to_value(error.body())
                .map_err(|serialize_error| OpenAuthError::Api(serialize_error.to_string()))?,
            None,
        ));
    }
    let profile_attributes = scim_user_profile_attributes(&input);
    let (user, account) = create_scim_user_account_and_membership(
        organization_options,
        adapter,
        users.find_user_by_email(&email).await?,
        CreateUserInput::new(name, email).email_verified(true),
        CreateOAuthAccountInput {
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
        },
        provider.organization_id.clone(),
        provider.provider_id.clone(),
        input.external_id.clone(),
        profile_attributes,
    )
    .await?;
    let resource = complete_user_resource(adapter, base_url, provider, &user, &account).await?;
    Ok((
        StatusCode::CREATED,
        serde_json::to_value(resource).map_err(|error| OpenAuthError::Api(error.to_string()))?,
        Some(user.id),
    ))
}

async fn bulk_create_group(
    adapter: &dyn DbAdapter,
    base_url: &str,
    provider: &AuthenticatedScimProvider,
    bulk_ids: &std::collections::BTreeMap<String, String>,
    data: serde_json::Value,
) -> Result<(StatusCode, serde_json::Value, Option<String>), OpenAuthError> {
    let Some(organization_id) = provider.organization_id.as_deref() else {
        let error = groups_require_organization();
        return Ok((
            error.status,
            serde_json::to_value(error.body())
                .map_err(|serialize_error| OpenAuthError::Api(serialize_error.to_string()))?,
            None,
        ));
    };
    let mut input: ScimGroupInput = match serde_json::from_value(data) {
        Ok(input) => input,
        Err(error) => {
            let (status, body) = scim_error_value(invalid_bulk_data(error))?;
            return Ok((status, body, None));
        }
    };
    if let Err(error) = reject_nested_group_members(&input.members) {
        return Ok((
            error.status,
            serde_json::to_value(error.body())
                .map_err(|serialize_error| OpenAuthError::Api(serialize_error.to_string()))?,
            None,
        ));
    }
    if let Err(error) = validate_group_display_name(&input.display_name) {
        return Ok((
            error.status,
            serde_json::to_value(error.body())
                .map_err(|serialize_error| OpenAuthError::Api(serialize_error.to_string()))?,
            None,
        ));
    }
    for member in &mut input.members {
        if let Err(error) = resolve_bulk_user_member(&mut member.value, bulk_ids) {
            return Ok((
                error.status,
                serde_json::to_value(error.body())
                    .map_err(|serialize_error| OpenAuthError::Api(serialize_error.to_string()))?,
                None,
            ));
        }
    }
    if let Err(error) = validate_group_member_users(
        adapter,
        &provider.provider_id,
        organization_id,
        &group_input_member_values(&input.members),
    )
    .await
    {
        let (status, body) = scim_or_openauth_value(error)?;
        return Ok((status, body, None));
    }
    let team = create_group_with_profile_and_members(
        adapter,
        &provider.provider_id,
        organization_id,
        input,
    )
    .await?;
    let resource = load_group_resource(
        adapter,
        base_url,
        &provider.provider_id,
        organization_id,
        &team.id,
    )
    .await?
    .ok_or_else(|| OpenAuthError::Adapter("created SCIM group is missing".to_owned()))?;
    Ok((
        StatusCode::CREATED,
        serde_json::to_value(resource).map_err(|error| OpenAuthError::Api(error.to_string()))?,
        Some(team.id),
    ))
}

async fn bulk_update_user(
    adapter: &dyn DbAdapter,
    base_url: &str,
    provider: &AuthenticatedScimProvider,
    user_id: &str,
    data: serde_json::Value,
) -> Result<(StatusCode, serde_json::Value), OpenAuthError> {
    let Some((user, account)) = find_scim_user(
        adapter,
        user_id,
        &provider.provider_id,
        provider.organization_id.as_deref(),
    )
    .await?
    else {
        let error = ScimError::not_found("User not found");
        return Ok((
            error.status,
            serde_json::to_value(error.body())
                .map_err(|serialize_error| OpenAuthError::Api(serialize_error.to_string()))?,
        ));
    };
    let mut input: ScimUserInput = match serde_json::from_value(data) {
        Ok(input) => input,
        Err(error) => {
            return scim_error_value(invalid_bulk_data(error));
        }
    };
    input.user_name = input.user_name.to_ascii_lowercase();
    let emails = input.emails.clone().unwrap_or_default();
    if let Err(error) = validate_emails(&emails) {
        return Ok((
            error.status,
            serde_json::to_value(error.body())
                .map_err(|serialize_error| OpenAuthError::Api(serialize_error.to_string()))?,
        ));
    }
    if let Err(error) = validate_multivalued_primary_attributes(&input.additional_fields) {
        return Ok((
            error.status,
            serde_json::to_value(error.body())
                .map_err(|serialize_error| OpenAuthError::Api(serialize_error.to_string()))?,
        ));
    }
    if let Err(error) = validate_scim_user_profile_attributes(&input) {
        return Ok((
            error.status,
            serde_json::to_value(error.body())
                .map_err(|serialize_error| OpenAuthError::Api(serialize_error.to_string()))?,
        ));
    }
    let email = match validate_scim_user_identity(&input.user_name, &emails) {
        Ok(email) => email,
        Err(error) => {
            return Ok((
                error.status,
                serde_json::to_value(error.body())
                    .map_err(|serialize_error| OpenAuthError::Api(serialize_error.to_string()))?,
            ));
        }
    };
    let name = user_full_name(&email, input.name.as_ref());
    let next_account_id = account_id(&input.user_name, input.external_id.as_deref());
    if next_account_id != account.account_id {
        if let Some(error) = ensure_provider_account_id_available(
            adapter,
            &provider.provider_id,
            &next_account_id,
            &user.id,
        )
        .await?
        {
            return Ok((
                error.status,
                serde_json::to_value(error.body())
                    .map_err(|serialize_error| OpenAuthError::Api(serialize_error.to_string()))?,
            ));
        }
    }
    let profile_attributes = scim_user_profile_attributes(&input);
    update_scim_user_account_and_replace_profile(
        adapter,
        &provider.provider_id,
        &user.id,
        &account.id,
        Some(email),
        Some(name),
        Some(next_account_id),
        input.external_id,
        profile_attributes,
    )
    .await?;
    let Some((updated_user, updated_account)) = find_scim_user(
        adapter,
        &user.id,
        &provider.provider_id,
        provider.organization_id.as_deref(),
    )
    .await?
    else {
        let error = ScimError::not_found("User not found");
        return Ok((
            error.status,
            serde_json::to_value(error.body())
                .map_err(|serialize_error| OpenAuthError::Api(serialize_error.to_string()))?,
        ));
    };
    let resource =
        complete_user_resource(adapter, base_url, provider, &updated_user, &updated_account)
            .await?;
    Ok((
        StatusCode::OK,
        serde_json::to_value(resource).map_err(|error| OpenAuthError::Api(error.to_string()))?,
    ))
}

async fn bulk_replace_group(
    adapter: &dyn DbAdapter,
    base_url: &str,
    provider: &AuthenticatedScimProvider,
    group_id: &str,
    data: serde_json::Value,
) -> Result<(StatusCode, serde_json::Value), OpenAuthError> {
    let Some(organization_id) = provider.organization_id.as_deref() else {
        let error = groups_require_organization();
        return Ok((
            error.status,
            serde_json::to_value(error.body())
                .map_err(|serialize_error| OpenAuthError::Api(serialize_error.to_string()))?,
        ));
    };
    if load_group_resource(
        adapter,
        base_url,
        &provider.provider_id,
        organization_id,
        group_id,
    )
    .await?
    .is_none()
    {
        return scim_error_value(ScimError::not_found("Group not found"));
    }
    let input: ScimGroupInput = match serde_json::from_value(data) {
        Ok(input) => input,
        Err(error) => {
            return scim_error_value(invalid_bulk_data(error));
        }
    };
    if let Err(error) = reject_nested_group_members(&input.members) {
        return Ok((
            error.status,
            serde_json::to_value(error.body())
                .map_err(|serialize_error| OpenAuthError::Api(serialize_error.to_string()))?,
        ));
    }
    if let Err(error) = validate_group_display_name(&input.display_name) {
        return scim_error_value(error);
    }
    if let Err(error) = validate_group_member_users(
        adapter,
        &provider.provider_id,
        organization_id,
        &group_input_member_values(&input.members),
    )
    .await
    {
        return scim_or_openauth_value(error);
    }
    replace_group(
        adapter,
        &provider.provider_id,
        organization_id,
        group_id,
        input,
    )
    .await?;
    bulk_get_group(adapter, base_url, provider, organization_id, group_id).await
}

async fn bulk_patch_group(
    adapter: &dyn DbAdapter,
    base_url: &str,
    provider: &AuthenticatedScimProvider,
    group_id: &str,
    data: serde_json::Value,
) -> Result<(StatusCode, serde_json::Value), OpenAuthError> {
    let Some(organization_id) = provider.organization_id.as_deref() else {
        let error = groups_require_organization();
        return Ok((
            error.status,
            serde_json::to_value(error.body())
                .map_err(|serialize_error| OpenAuthError::Api(serialize_error.to_string()))?,
        ));
    };
    if load_group_resource(
        adapter,
        base_url,
        &provider.provider_id,
        organization_id,
        group_id,
    )
    .await?
    .is_none()
    {
        return scim_error_value(ScimError::not_found("Group not found"));
    }
    let body: PatchBody = match serde_json::from_value(data) {
        Ok(body) => body,
        Err(error) => {
            return scim_error_value(invalid_bulk_data(error));
        }
    };
    if !body.schemas.iter().any(|schema| schema == PATCH_OP_SCHEMA) {
        return scim_error_value(
            ScimError::bad_request("Invalid schemas for PatchOp").with_scim_type("invalidValue"),
        );
    }
    if let Err(error) = apply_group_patch(
        adapter,
        &provider.provider_id,
        organization_id,
        group_id,
        body.operations,
    )
    .await
    {
        return scim_or_openauth_value(error);
    }
    bulk_get_group(adapter, base_url, provider, organization_id, group_id).await
}

async fn bulk_patch_user(
    adapter: &dyn DbAdapter,
    base_url: &str,
    provider: &AuthenticatedScimProvider,
    user_id: &str,
    data: serde_json::Value,
) -> Result<(StatusCode, serde_json::Value), OpenAuthError> {
    let Some((user, account)) = find_scim_user(
        adapter,
        user_id,
        &provider.provider_id,
        provider.organization_id.as_deref(),
    )
    .await?
    else {
        let error = ScimError::not_found("User not found");
        return Ok((
            error.status,
            serde_json::to_value(error.body())
                .map_err(|serialize_error| OpenAuthError::Api(serialize_error.to_string()))?,
        ));
    };
    let body: PatchBody = match serde_json::from_value(data) {
        Ok(body) => body,
        Err(error) => {
            return scim_error_value(invalid_bulk_data(error));
        }
    };
    if !body.schemas.iter().any(|schema| schema == PATCH_OP_SCHEMA) {
        let error =
            ScimError::bad_request("Invalid schemas for PatchOp").with_scim_type("invalidValue");
        return Ok((
            error.status,
            serde_json::to_value(error.body())
                .map_err(|serialize_error| OpenAuthError::Api(serialize_error.to_string()))?,
        ));
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
        Err(error) => {
            return Ok((
                error.status,
                serde_json::to_value(error.body())
                    .map_err(|serialize_error| OpenAuthError::Api(serialize_error.to_string()))?,
            ));
        }
    };
    let email = match patched_email(&user, &patch) {
        Ok(email) => email,
        Err(error) => {
            return Ok((
                error.status,
                serde_json::to_value(error.body())
                    .map_err(|serialize_error| OpenAuthError::Api(serialize_error.to_string()))?,
            ));
        }
    };
    let next_account_id = patched_account_id(&user, &patch);
    if let Some(next_account_id) = &next_account_id {
        if next_account_id != &account.account_id {
            if let Some(error) = ensure_provider_account_id_available(
                adapter,
                &provider.provider_id,
                next_account_id,
                &user.id,
            )
            .await?
            {
                return Ok((
                    error.status,
                    serde_json::to_value(error.body()).map_err(|serialize_error| {
                        OpenAuthError::Api(serialize_error.to_string())
                    })?,
                ));
            }
        }
    }
    update_scim_user_account_and_merge_profile(
        adapter,
        &provider.provider_id,
        &user.id,
        &account.id,
        email,
        patch
            .user
            .get("name")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        next_account_id,
        patch.profile,
    )
    .await?;
    let Some((updated_user, updated_account)) = find_scim_user(
        adapter,
        &user.id,
        &provider.provider_id,
        provider.organization_id.as_deref(),
    )
    .await?
    else {
        let error = ScimError::not_found("User not found");
        return Ok((
            error.status,
            serde_json::to_value(error.body())
                .map_err(|serialize_error| OpenAuthError::Api(serialize_error.to_string()))?,
        ));
    };
    let resource =
        complete_user_resource(adapter, base_url, provider, &updated_user, &updated_account)
            .await?;
    Ok((
        StatusCode::OK,
        serde_json::to_value(resource).map_err(|error| OpenAuthError::Api(error.to_string()))?,
    ))
}

async fn bulk_get_group(
    adapter: &dyn DbAdapter,
    base_url: &str,
    provider: &AuthenticatedScimProvider,
    organization_id: &str,
    group_id: &str,
) -> Result<(StatusCode, serde_json::Value), OpenAuthError> {
    match load_group_resource(
        adapter,
        base_url,
        &provider.provider_id,
        organization_id,
        group_id,
    )
    .await?
    {
        Some(resource) => Ok((
            StatusCode::OK,
            serde_json::to_value(resource)
                .map_err(|error| OpenAuthError::Api(error.to_string()))?,
        )),
        None => {
            let error = ScimError::not_found("Group not found");
            Ok((
                error.status,
                serde_json::to_value(error.body())
                    .map_err(|serialize_error| OpenAuthError::Api(serialize_error.to_string()))?,
            ))
        }
    }
}

fn resolve_bulk_user_member(
    value: &mut String,
    bulk_ids: &std::collections::BTreeMap<String, String>,
) -> Result<(), ScimError> {
    let Some(bulk_id) = value.strip_prefix("bulkId:") else {
        return Ok(());
    };
    let Some(path) = bulk_ids.get(bulk_id) else {
        return Err(
            ScimError::bad_request(format!("Unresolved bulkId reference: {bulk_id}"))
                .with_scim_type("invalidValue"),
        );
    };
    let Some(user_id) = path.strip_prefix("/Users/") else {
        return Err(ScimError::bad_request("Group members must reference Users")
            .with_scim_type("invalidValue"));
    };
    *value = user_id.to_owned();
    Ok(())
}
