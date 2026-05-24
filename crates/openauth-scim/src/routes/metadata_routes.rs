use super::*;

pub(super) fn search_resources_endpoint(
    options: Arc<ScimOptions>,
) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/v2/.search",
        Method::POST,
        scim_endpoint_options("searchSCIMResources", "Search SCIM resources")
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
                let users =
                    match load_user_resources(adapter.as_ref(), &context.base_url, &provider, None)
                        .await
                    {
                        Ok(resources) => resources,
                        Err(error) => return error.into_response(),
                    };
                let mut resources = users
                    .into_iter()
                    .map(serde_json::to_value)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| OpenAuthError::Api(error.to_string()))?;
                if let Some(organization_id) = provider.organization_id.as_deref() {
                    resources.extend(
                        load_group_resources(
                            adapter.as_ref(),
                            &context.base_url,
                            &provider.provider_id,
                            organization_id,
                        )
                        .await?
                        .into_iter()
                        .map(serde_json::to_value)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|error| OpenAuthError::Api(error.to_string()))?,
                    );
                }
                if let Some(filter) = search.filter.as_deref() {
                    let mut filtered = Vec::new();
                    for resource in resources {
                        match resource_matches_filter(&resource, filter) {
                            Ok(true) => filtered.push(resource),
                            Ok(false) => {}
                            Err(error) => return error.into_response(),
                        }
                    }
                    resources = filtered;
                }
                if let Some(sort_by) = search.sort_by.as_deref() {
                    if let Err(error) =
                        sort_json_resources(&mut resources, sort_by, search.sort_order.as_deref())
                    {
                        return error.into_response();
                    }
                }
                scim_json_projected_from_search(
                    StatusCode::OK,
                    &json_list_response(resources, search.start_index, search.count),
                    &search,
                )
            })
        },
    )
}

pub(super) fn me_endpoint() -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/v2/Me",
        Method::GET,
        scim_endpoint_options("getSCIMMe", "Get the authenticated SCIM subject alias"),
        |_context, _request| {
            Box::pin(async {
                ScimError::not_implemented("/Me is not supported for provider-scoped SCIM tokens")
                    .into_response()
            })
        },
    )
}

pub(super) fn service_provider_config_endpoint() -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/v2/ServiceProviderConfig",
        Method::GET,
        scim_endpoint_options(
            "getSCIMServiceProviderConfig",
            "Get SCIM ServiceProviderConfig",
        ),
        |_context, _request| {
            Box::pin(async { scim_json(StatusCode::OK, &metadata::service_provider_config()) })
        },
    )
}

pub(super) fn schemas_endpoint() -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/v2/Schemas",
        Method::GET,
        scim_endpoint_options("getSCIMSchemas", "List SCIM schemas"),
        |context, _request| {
            Box::pin(
                async move { scim_json(StatusCode::OK, &metadata::schemas(&context.base_url)) },
            )
        },
    )
}

pub(super) fn schema_endpoint() -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/v2/Schemas/:schemaId",
        Method::GET,
        scim_endpoint_options("getSCIMSchema", "Get a SCIM schema"),
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

pub(super) fn resource_types_endpoint() -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/v2/ResourceTypes",
        Method::GET,
        scim_endpoint_options("getSCIMResourceTypes", "List SCIM resource types"),
        |context, _request| {
            Box::pin(async move {
                scim_json(StatusCode::OK, &metadata::resource_types(&context.base_url))
            })
        },
    )
}

pub(super) fn resource_type_endpoint() -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/v2/ResourceTypes/:resourceTypeId",
        Method::GET,
        scim_endpoint_options("getSCIMResourceType", "Get a SCIM resource type"),
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
