use super::*;

pub(super) fn create_group_endpoint(
    options: Arc<ScimOptions>,
) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/v2/Groups",
        Method::POST,
        scim_endpoint_options("createSCIMGroup", "Create a SCIM Group resource")
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
                let Some(organization_id) = provider.organization_id.as_deref() else {
                    return groups_require_organization().into_response();
                };
                let input: ScimGroupInput = match serde_json::from_slice(request.body()) {
                    Ok(input) => input,
                    Err(error) => {
                        return ScimError::bad_request(format!(
                            "invalid JSON request body: {error}"
                        ))
                        .into_response();
                    }
                };
                if let Err(error) = validate_group_display_name(&input.display_name) {
                    return error.into_response();
                }
                if let Err(error) = reject_nested_group_members(&input.members) {
                    return error.into_response();
                }
                if let Err(error) = validate_group_member_users(
                    adapter.as_ref(),
                    &provider.provider_id,
                    organization_id,
                    &group_input_member_values(&input.members),
                )
                .await
                {
                    return error.into_response();
                }

                let team = create_group_with_profile_and_members(
                    adapter.as_ref(),
                    &provider.provider_id,
                    organization_id,
                    input,
                )
                .await?;

                let resource = load_group_resource(
                    adapter.as_ref(),
                    &context.base_url,
                    &provider.provider_id,
                    organization_id,
                    &team.id,
                )
                .await?
                .ok_or_else(|| {
                    OpenAuthError::Adapter("created SCIM group is missing".to_owned())
                })?;
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

pub(super) fn list_groups_endpoint(
    options: Arc<ScimOptions>,
) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/v2/Groups",
        Method::GET,
        scim_endpoint_options("listSCIMGroups", "List SCIM Group resources"),
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
                let Some(organization_id) = provider.organization_id.as_deref() else {
                    return groups_require_organization().into_response();
                };
                let mut resources = load_group_resources(
                    adapter.as_ref(),
                    &context.base_url,
                    &provider.provider_id,
                    organization_id,
                )
                .await?;
                if let Some(filter) = query_param(&request, "filter") {
                    resources = match filter_group_resources(resources, &filter) {
                        Ok(resources) => resources,
                        Err(error) => return error.into_response(),
                    };
                }
                let sort_order = query_param(&request, "sortOrder");
                if let Some(sort_by) = query_param(&request, "sortBy") {
                    if let Err(error) =
                        sort_group_resources(&mut resources, &sort_by, sort_order.as_deref())
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
                    &group_list_response(resources, start_index, count),
                    &request,
                )
            })
        },
    )
}

pub(super) fn get_group_endpoint(
    options: Arc<ScimOptions>,
) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/v2/Groups/:groupId",
        Method::GET,
        scim_endpoint_options("getSCIMGroup", "Get a SCIM Group resource"),
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
                let Some(organization_id) = provider.organization_id.as_deref() else {
                    return groups_require_organization().into_response();
                };
                let Some(group_id) = path_param(&request, "groupId") else {
                    return ScimError::not_found("Group not found").into_response();
                };
                let Some(resource) = load_group_resource(
                    adapter.as_ref(),
                    &context.base_url,
                    &provider.provider_id,
                    organization_id,
                    &group_id,
                )
                .await?
                else {
                    return ScimError::not_found("Group not found").into_response();
                };
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

pub(super) fn put_group_endpoint(
    options: Arc<ScimOptions>,
) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/v2/Groups/:groupId",
        Method::PUT,
        scim_endpoint_options("updateSCIMGroup", "Replace a SCIM Group resource")
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
                let Some(organization_id) = provider.organization_id.as_deref() else {
                    return groups_require_organization().into_response();
                };
                let Some(group_id) = path_param(&request, "groupId") else {
                    return ScimError::not_found("Group not found").into_response();
                };
                let Some(current_resource) = load_group_resource(
                    adapter.as_ref(),
                    &context.base_url,
                    &provider.provider_id,
                    organization_id,
                    &group_id,
                )
                .await?
                else {
                    return ScimError::not_found("Group not found").into_response();
                };
                let input: ScimGroupInput = match serde_json::from_slice(request.body()) {
                    Ok(input) => input,
                    Err(error) => {
                        return ScimError::bad_request(format!(
                            "invalid JSON request body: {error}"
                        ))
                        .into_response();
                    }
                };
                if let Err(error) =
                    validate_if_match(&request, current_resource.meta.version.as_deref())
                {
                    return error.into_response();
                }
                if let Err(error) = reject_nested_group_members(&input.members) {
                    return error.into_response();
                }
                if let Err(error) = validate_group_display_name(&input.display_name) {
                    return error.into_response();
                }
                if let Err(error) = validate_group_member_users(
                    adapter.as_ref(),
                    &provider.provider_id,
                    organization_id,
                    &group_input_member_values(&input.members),
                )
                .await
                {
                    return error.into_response();
                }
                replace_group(
                    adapter.as_ref(),
                    &provider.provider_id,
                    organization_id,
                    &group_id,
                    input,
                )
                .await?;
                let resource = load_group_resource(
                    adapter.as_ref(),
                    &context.base_url,
                    &provider.provider_id,
                    organization_id,
                    &group_id,
                )
                .await?
                .ok_or_else(|| {
                    OpenAuthError::Adapter("updated SCIM group is missing".to_owned())
                })?;
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

pub(super) fn patch_group_endpoint(
    options: Arc<ScimOptions>,
) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/v2/Groups/:groupId",
        Method::PATCH,
        scim_endpoint_options("patchSCIMGroup", "Patch a SCIM Group resource")
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
                let Some(organization_id) = provider.organization_id.as_deref() else {
                    return groups_require_organization().into_response();
                };
                let Some(group_id) = path_param(&request, "groupId") else {
                    return ScimError::not_found("Group not found").into_response();
                };
                let Some(current_resource) = load_group_resource(
                    adapter.as_ref(),
                    &context.base_url,
                    &provider.provider_id,
                    organization_id,
                    &group_id,
                )
                .await?
                else {
                    return ScimError::not_found("Group not found").into_response();
                };
                if let Err(error) =
                    validate_if_match(&request, current_resource.meta.version.as_deref())
                {
                    return error.into_response();
                }
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
                if let Err(error) = apply_group_patch(
                    adapter.as_ref(),
                    &provider.provider_id,
                    organization_id,
                    &group_id,
                    body.operations,
                )
                .await
                {
                    return error.into_response();
                }
                let resource = load_group_resource(
                    adapter.as_ref(),
                    &context.base_url,
                    &provider.provider_id,
                    organization_id,
                    &group_id,
                )
                .await?
                .ok_or_else(|| {
                    OpenAuthError::Adapter("patched SCIM group is missing".to_owned())
                })?;
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

pub(super) fn delete_group_endpoint(
    options: Arc<ScimOptions>,
) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/v2/Groups/:groupId",
        Method::DELETE,
        scim_endpoint_options("deleteSCIMGroup", "Delete a SCIM Group resource"),
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
                let Some(organization_id) = provider.organization_id.as_deref() else {
                    return groups_require_organization().into_response();
                };
                let Some(group_id) = path_param(&request, "groupId") else {
                    return ScimError::not_found("Group not found").into_response();
                };
                let Some(current_resource) = load_group_resource(
                    adapter.as_ref(),
                    &context.base_url,
                    &provider.provider_id,
                    organization_id,
                    &group_id,
                )
                .await?
                else {
                    return ScimError::not_found("Group not found").into_response();
                };
                if let Err(error) =
                    validate_if_match(&request, current_resource.meta.version.as_deref())
                {
                    return error.into_response();
                }
                delete_group(
                    adapter.as_ref(),
                    organization_id,
                    &provider.provider_id,
                    &group_id,
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

pub(super) fn search_groups_endpoint(
    options: Arc<ScimOptions>,
) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/v2/Groups/.search",
        Method::POST,
        scim_endpoint_options("searchSCIMGroups", "Search SCIM Group resources")
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
                let Some(organization_id) = provider.organization_id.as_deref() else {
                    return groups_require_organization().into_response();
                };
                let search = match parse_search_request(&request) {
                    Ok(search) => search,
                    Err(error) => return error.into_response(),
                };
                let mut resources = load_group_resources(
                    adapter.as_ref(),
                    &context.base_url,
                    &provider.provider_id,
                    organization_id,
                )
                .await?;
                if let Some(filter) = search.filter.as_deref() {
                    resources = match filter_group_resources(resources, filter) {
                        Ok(resources) => resources,
                        Err(error) => return error.into_response(),
                    };
                }
                if let Some(sort_by) = search.sort_by.as_deref() {
                    if let Err(error) =
                        sort_group_resources(&mut resources, sort_by, search.sort_order.as_deref())
                    {
                        return error.into_response();
                    }
                }
                scim_json_projected_from_search(
                    StatusCode::OK,
                    &group_list_response(resources, search.start_index, search.count),
                    &search,
                )
            })
        },
    )
}
