use super::*;

pub(super) fn generate_token_endpoint(
    options: Arc<ScimOptions>,
) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/generate-token",
        Method::POST,
        management_endpoint_options("generateSCIMToken", "Generate a SCIM bearer token")
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
                } else if !options.provider_ownership.enabled {
                    return json_error(
                        StatusCode::FORBIDDEN,
                        "FORBIDDEN",
                        "Global SCIM provider management requires provider ownership to be enabled",
                    );
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
                let stored_token =
                    store_scim_token(&context.secret, &options.token_storage, &base_token).await?;
                let provider = store
                    .upsert(crate::store::CreateScimProviderInput {
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
                        provider: provider.clone(),
                    })
                    .await
                    {
                        return hook_error(error);
                    }
                }

                let mut event = ScimAuditEvent::new(
                    ScimAuditEventKind::TokenGenerated,
                    ScimAuditSeverity::Info,
                )
                .with_provider_id(&provider.provider_id);
                if let Some(organization_id) = provider.organization_id.as_deref() {
                    event = event.with_organization_id(organization_id);
                }
                crate::audit::emit(context, &options, event).await;

                json(StatusCode::CREATED, &GenerateTokenResponse { scim_token })
            })
        },
    )
}

pub(super) fn list_provider_connections_endpoint(
    options: Arc<ScimOptions>,
) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/list-provider-connections",
        Method::GET,
        management_endpoint_options(
            "listSCIMProviderConnections",
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
                    if !provider_scope_supported_for_management(context, &provider) {
                        continue;
                    }
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

pub(super) fn get_provider_connection_endpoint(
    options: Arc<ScimOptions>,
) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/get-provider-connection",
        Method::GET,
        management_endpoint_options(
            "getSCIMProviderConnection",
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
                if !provider_scope_supported_for_management(context, &provider) {
                    return json_error(
                        StatusCode::FORBIDDEN,
                        "FORBIDDEN",
                        "Organization plugin is required to access this provider",
                    );
                }
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

pub(super) fn delete_provider_connection_endpoint(
    options: Arc<ScimOptions>,
) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/scim/delete-provider-connection",
        Method::POST,
        management_endpoint_options(
            "deleteSCIMProviderConnection",
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
                if !provider_scope_supported_for_management(context, &provider) {
                    return json_error(
                        StatusCode::FORBIDDEN,
                        "FORBIDDEN",
                        "Organization plugin is required to access this provider",
                    );
                }
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
                purge_provider_connection(adapter.as_ref(), &provider, options.deprovision_mode)
                    .await?;
                json(StatusCode::OK, &DeleteProviderResponse { success: true })
            })
        },
    )
}

async fn purge_provider_connection(
    adapter: &dyn DbAdapter,
    provider: &ScimProviderRecord,
    deprovision_mode: crate::options::ScimDeprovisionMode,
) -> Result<(), OpenAuthError> {
    purge_provider_groups(adapter, provider).await?;
    purge_provider_users(adapter, provider, deprovision_mode).await?;
    ScimProviderStore::new(adapter)
        .delete(&provider.provider_id)
        .await
}

async fn purge_provider_groups(
    adapter: &dyn DbAdapter,
    provider: &ScimProviderRecord,
) -> Result<(), OpenAuthError> {
    let Some(organization_id) = provider.organization_id.as_deref() else {
        return Ok(());
    };
    let profiles = adapter
        .find_many(
            FindMany::new("scimGroupProfile")
                .where_clause(Where::new(
                    "providerId",
                    DbValue::String(provider.provider_id.clone()),
                ))
                .select(["teamId"]),
        )
        .await?;
    for profile in profiles {
        let team_id = required_string(&profile, "teamId")?.to_owned();
        delete_group(adapter, organization_id, &provider.provider_id, &team_id).await?;
    }
    Ok(())
}

async fn purge_provider_users(
    adapter: &dyn DbAdapter,
    provider: &ScimProviderRecord,
    deprovision_mode: crate::options::ScimDeprovisionMode,
) -> Result<(), OpenAuthError> {
    let accounts = adapter
        .find_many(
            FindMany::new("account")
                .where_clause(Where::new(
                    "provider_id",
                    DbValue::String(provider.provider_id.clone()),
                ))
                .select(["user_id"]),
        )
        .await?;
    let mut user_ids = accounts
        .into_iter()
        .filter_map(|record| required_string(&record, "user_id").ok().map(str::to_owned))
        .collect::<Vec<_>>();
    user_ids.sort();
    user_ids.dedup();

    if let Some(organization_id) = provider.organization_id.as_deref() {
        if !user_ids.is_empty() {
            let members = adapter
                .find_many(
                    FindMany::new("member")
                        .where_clause(Where::new(
                            "organization_id",
                            DbValue::String(organization_id.to_owned()),
                        ))
                        .where_clause(
                            Where::new("user_id", DbValue::StringArray(user_ids.clone()))
                                .operator(WhereOperator::In),
                        )
                        .select(["user_id"]),
                )
                .await?;
            user_ids = members
                .into_iter()
                .filter_map(|member| match member.get("user_id") {
                    Some(DbValue::String(user_id)) => Some(user_id.to_owned()),
                    _ => None,
                })
                .collect();
        }
    }

    for user_id in user_ids {
        deprovision_scim_user(
            adapter,
            &user_id,
            &provider.provider_id,
            provider.organization_id.as_deref(),
            deprovision_mode,
        )
        .await?;
    }
    Ok(())
}
