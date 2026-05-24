use super::*;

pub(super) fn search_users_endpoint(
    options: Arc<ScimOptions>,
) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/v2/Users/.search",
        Method::POST,
        scim_endpoint_options("searchSCIMUsers", "Search SCIM User resources")
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
                let search = match parse_search_request(&request) {
                    Ok(search) => search,
                    Err(error) => return error.into_response(),
                };
                let mut resources = match load_user_resources(
                    adapter.as_ref(),
                    &context.base_url,
                    &provider,
                    search.filter.as_deref(),
                )
                .await
                {
                    Ok(resources) => resources,
                    Err(error) => return error.into_response(),
                };
                if let Err(error) = apply_user_sort(
                    &mut resources,
                    search.sort_by.as_deref(),
                    search.sort_order.as_deref(),
                ) {
                    return error.into_response();
                }
                scim_json_projected_from_search(
                    StatusCode::OK,
                    &user_list_response(resources, search.start_index, search.count),
                    &search,
                )
            })
        },
    )
}

pub(super) fn get_user_endpoint(
    options: Arc<ScimOptions>,
) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/v2/Users/:userId",
        Method::GET,
        scim_endpoint_options("getSCIMUser", "Get a SCIM User resource"),
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
                let resource = complete_user_resource(
                    adapter.as_ref(),
                    &context.base_url,
                    &provider,
                    &user,
                    &account,
                )
                .await?;
                scim_json_projected_with_etag(
                    StatusCode::OK,
                    &resource,
                    &request,
                    resource.meta.version.as_deref(),
                )
            })
        },
    )
}

pub(super) fn create_user_endpoint(
    options: Arc<ScimOptions>,
) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/v2/Users",
        Method::POST,
        scim_endpoint_options("createSCIMUser", "Create a SCIM User resource")
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
                let mut input: ScimUserInput = match serde_json::from_slice(request.body()) {
                    Ok(input) => input,
                    Err(error) => {
                        return ScimError::bad_request(format!(
                            "invalid JSON request body: {error}"
                        ))
                        .into_response();
                    }
                };
                input.user_name = input.user_name.to_ascii_lowercase();
                let emails = input.emails.clone().unwrap_or_default();
                if let Err(error) = validate_emails(&emails) {
                    return error.into_response();
                }
                if let Err(error) =
                    validate_multivalued_primary_attributes(&input.additional_fields)
                {
                    return error.into_response();
                }
                if let Err(error) = validate_scim_user_profile_attributes(&input) {
                    return error.into_response();
                }
                let email = primary_email(&input.user_name, &emails).to_lowercase();
                let name = user_full_name(&email, input.name.as_ref());
                let account_id = account_id(&input.user_name, input.external_id.as_deref());
                let user_profile_attributes = scim_user_profile_attributes(&input);

                let users = DbUserStore::new(adapter.as_ref());
                if users
                    .find_account_by_provider_account(&account_id, &provider.provider_id)
                    .await?
                    .is_some()
                {
                    return ScimError::conflict("User already exists")
                        .with_scim_type("uniqueness")
                        .into_response();
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
                    provider.provider_id.clone(),
                    input.external_id.clone(),
                    user_profile_attributes,
                )
                .await?;

                let resource = complete_user_resource(
                    adapter.as_ref(),
                    &context.base_url,
                    &provider,
                    &user,
                    &account,
                )
                .await?;
                scim_json_with_location_and_etag(
                    StatusCode::CREATED,
                    &resource,
                    &resource.meta.location,
                    resource.meta.version.as_deref(),
                )
            })
        },
    )
}

pub(super) fn put_user_endpoint(
    options: Arc<ScimOptions>,
) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/v2/Users/:userId",
        Method::PUT,
        scim_endpoint_options("updateSCIMUser", "Replace a SCIM User resource")
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
                let mut input: ScimUserInput = match serde_json::from_slice(request.body()) {
                    Ok(input) => input,
                    Err(error) => {
                        return ScimError::bad_request(format!(
                            "invalid JSON request body: {error}"
                        ))
                        .into_response();
                    }
                };
                input.user_name = input.user_name.to_ascii_lowercase();
                let emails = input.emails.clone().unwrap_or_default();
                if let Err(error) = validate_emails(&emails) {
                    return error.into_response();
                }
                if let Err(error) =
                    validate_multivalued_primary_attributes(&input.additional_fields)
                {
                    return error.into_response();
                }
                if let Err(error) = validate_scim_user_profile_attributes(&input) {
                    return error.into_response();
                }
                let email = primary_email(&input.user_name, &emails).to_lowercase();
                let name = user_full_name(&email, input.name.as_ref());
                let next_account_id = account_id(&input.user_name, input.external_id.as_deref());
                let user_profile_attributes = scim_user_profile_attributes(&input);
                let current_resource = complete_user_resource(
                    adapter.as_ref(),
                    &context.base_url,
                    &provider,
                    &user,
                    &account,
                )
                .await?;
                if let Err(error) =
                    validate_if_match(&request, current_resource.meta.version.as_deref())
                {
                    return error.into_response();
                }

                update_scim_user_account_and_replace_profile(
                    adapter.as_ref(),
                    &provider.provider_id,
                    &user.id,
                    &account.id,
                    Some(email),
                    Some(name),
                    Some(next_account_id),
                    input.external_id,
                    user_profile_attributes,
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

                let resource = complete_user_resource(
                    adapter.as_ref(),
                    &context.base_url,
                    &provider,
                    &updated_user,
                    &updated_account,
                )
                .await?;
                scim_json_projected_with_etag(
                    StatusCode::OK,
                    &resource,
                    &request,
                    resource.meta.version.as_deref(),
                )
            })
        },
    )
}

pub(super) fn patch_user_endpoint(
    options: Arc<ScimOptions>,
) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/v2/Users/:userId",
        Method::PATCH,
        scim_endpoint_options("patchSCIMUser", "Patch a SCIM User resource")
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
                let current_resource = complete_user_resource(
                    adapter.as_ref(),
                    &context.base_url,
                    &provider,
                    &user,
                    &account,
                )
                .await?;
                if let Err(error) =
                    validate_if_match(&request, current_resource.meta.version.as_deref())
                {
                    return error.into_response();
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
                let email = match patched_email(&user, &patch) {
                    Ok(email) => email,
                    Err(error) => return error.into_response(),
                };

                update_scim_user_account_and_merge_profile(
                    adapter.as_ref(),
                    &provider.provider_id,
                    &user.id,
                    &account.id,
                    email,
                    patch
                        .user
                        .get("name")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned),
                    patched_account_id(&user, &patch),
                    patch.profile,
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

pub(super) fn delete_user_endpoint(
    options: Arc<ScimOptions>,
) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/v2/Users/:userId",
        Method::DELETE,
        scim_endpoint_options("deleteSCIMUser", "Delete a SCIM User resource"),
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
                let current_resource = complete_user_resource(
                    adapter.as_ref(),
                    &context.base_url,
                    &provider,
                    &user,
                    &account,
                )
                .await?;
                if let Err(error) =
                    validate_if_match(&request, current_resource.meta.version.as_deref())
                {
                    return error.into_response();
                }
                delete_scim_user(adapter.as_ref(), &user.id).await?;
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(Vec::new())
                    .map_err(|error| OpenAuthError::Api(error.to_string()))
            })
        },
    )
}

pub(super) fn list_users_endpoint(
    options: Arc<ScimOptions>,
) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/v2/Users",
        Method::GET,
        scim_endpoint_options("listSCIMUsers", "List SCIM User resources"),
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
                let mut resources = match load_user_resources(
                    adapter.as_ref(),
                    &context.base_url,
                    &provider,
                    query_param(&request, "filter").as_deref(),
                )
                .await
                {
                    Ok(resources) => resources,
                    Err(error) => return error.into_response(),
                };
                let sort_order = query_param(&request, "sortOrder");
                if let Some(sort_by) = query_param(&request, "sortBy") {
                    if let Err(error) =
                        sort_user_resources(&mut resources, &sort_by, sort_order.as_deref())
                    {
                        return error.into_response();
                    }
                } else if let Err(error) = validate_sort_order(sort_order.as_deref()) {
                    return error.into_response();
                }
                let start_index = match query_usize(&request, "startIndex") {
                    Ok(value) => value,
                    Err(error) => return error.into_response(),
                };
                let count = match query_usize(&request, "count") {
                    Ok(value) => value,
                    Err(error) => return error.into_response(),
                };
                scim_json_projected(
                    StatusCode::OK,
                    &user_list_response(resources, start_index, count),
                    &request,
                )
            })
        },
    )
}
