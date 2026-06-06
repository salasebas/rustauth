use super::*;

pub(super) fn group_list_response(
    resources: Vec<ScimGroupResource>,
    start_index: Option<usize>,
    count: Option<usize>,
) -> metadata::ListResponse<ScimGroupResource> {
    let total_results = resources.len();
    let start_index = start_index.unwrap_or(1).max(1);
    let count = bounded_result_count(count, total_results);
    let resources = resources
        .into_iter()
        .skip(start_index.saturating_sub(1))
        .take(count)
        .collect::<Vec<_>>();
    metadata::ListResponse {
        schemas: vec![metadata::LIST_RESPONSE_SCHEMA.to_owned()],
        total_results,
        start_index,
        items_per_page: resources.len(),
        resources,
    }
}

pub(super) fn json_list_response(
    resources: Vec<serde_json::Value>,
    start_index: Option<usize>,
    count: Option<usize>,
) -> metadata::ListResponse<serde_json::Value> {
    let total_results = resources.len();
    let start_index = start_index.unwrap_or(1).max(1);
    let count = bounded_result_count(count, total_results);
    let resources = resources
        .into_iter()
        .skip(start_index.saturating_sub(1))
        .take(count)
        .collect::<Vec<_>>();
    metadata::ListResponse {
        schemas: vec![metadata::LIST_RESPONSE_SCHEMA.to_owned()],
        total_results,
        start_index,
        items_per_page: resources.len(),
        resources,
    }
}

pub(super) fn groups_require_organization() -> ScimError {
    ScimError::bad_request("Groups require an organization-scoped SCIM provider")
        .with_scim_type("invalidValue")
}

pub(super) fn validate_group_display_name(display_name: &str) -> Result<(), ScimError> {
    if display_name.trim().is_empty() {
        return Err(
            ScimError::bad_request("displayName is required").with_scim_type("invalidValue")
        );
    }
    Ok(())
}

pub(super) async fn create_team_for_group(
    adapter: &dyn DbAdapter,
    organization_id: &str,
    display_name: &str,
) -> Result<ScimTeamRecord, OpenAuthError> {
    let now = OffsetDateTime::now_utc();
    let record = adapter
        .create(
            Create::new("team")
                .data("id", DbValue::String(generate_random_string(32)))
                .data("name", DbValue::String(display_name.to_owned()))
                .data(
                    "organization_id",
                    DbValue::String(organization_id.to_owned()),
                )
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Timestamp(now))
                .force_allow_id(),
        )
        .await?;
    team_from_record(record)
}

pub(super) async fn create_scim_group_profile(
    adapter: &dyn DbAdapter,
    provider_id: &str,
    organization_id: &str,
    team_id: &str,
    external_id: Option<&str>,
) -> Result<(), OpenAuthError> {
    let now = OffsetDateTime::now_utc();
    adapter
        .create(
            Create::new("scimGroupProfile")
                .data("id", DbValue::String(generate_random_string(32)))
                .data("providerId", DbValue::String(provider_id.to_owned()))
                .data(
                    "organizationId",
                    DbValue::String(organization_id.to_owned()),
                )
                .data("teamId", DbValue::String(team_id.to_owned()))
                .data(
                    "externalId",
                    external_id
                        .map(|value| DbValue::String(value.to_owned()))
                        .unwrap_or(DbValue::Null),
                )
                .data("attributes", DbValue::Json(serde_json::json!({})))
                .data("version", DbValue::String(resource_version(now)))
                .data("createdAt", DbValue::Timestamp(now))
                .data("updatedAt", DbValue::Timestamp(now))
                .force_allow_id(),
        )
        .await?;
    Ok(())
}

pub(super) async fn create_group_with_profile_and_members(
    adapter: &dyn DbAdapter,
    provider_id: &str,
    organization_id: &str,
    input: ScimGroupInput,
) -> Result<ScimTeamRecord, OpenAuthError> {
    let provider_id = provider_id.to_owned();
    let organization_id = organization_id.to_owned();
    let result = Arc::new(Mutex::new(None));
    let result_for_transaction = Arc::clone(&result);
    adapter
        .transaction(Box::new(move |transaction| {
            Box::pin(async move {
                let team = create_team_for_group(
                    transaction.as_ref(),
                    &organization_id,
                    input.display_name.trim(),
                )
                .await?;
                create_scim_group_profile(
                    transaction.as_ref(),
                    &provider_id,
                    &organization_id,
                    &team.id,
                    input.external_id.as_deref(),
                )
                .await?;
                for member in &input.members {
                    create_team_member_if_missing(transaction.as_ref(), &team.id, &member.value)
                        .await?;
                }
                let mut guard = result_for_transaction.lock().map_err(|_| {
                    OpenAuthError::Adapter("create SCIM group result mutex was poisoned".to_owned())
                })?;
                *guard = Some(team);
                Ok(())
            })
        }))
        .await?;
    let team = result
        .lock()
        .map_err(|_| {
            OpenAuthError::Adapter("create SCIM group result mutex was poisoned".to_owned())
        })?
        .take()
        .ok_or_else(|| {
            OpenAuthError::Adapter(
                "create SCIM group transaction completed without a result".to_owned(),
            )
        })?;
    Ok(team)
}

pub(super) async fn create_team_member_if_missing(
    adapter: &dyn DbAdapter,
    team_id: &str,
    user_id: &str,
) -> Result<bool, OpenAuthError> {
    if adapter
        .find_one(
            FindOne::new("team_member")
                .where_clause(Where::new("team_id", DbValue::String(team_id.to_owned())))
                .where_clause(Where::new("user_id", DbValue::String(user_id.to_owned()))),
        )
        .await?
        .is_some()
    {
        return Ok(false);
    }
    adapter
        .create(
            Create::new("team_member")
                .data("id", DbValue::String(generate_random_string(32)))
                .data("team_id", DbValue::String(team_id.to_owned()))
                .data("user_id", DbValue::String(user_id.to_owned()))
                .data("created_at", DbValue::Timestamp(OffsetDateTime::now_utc()))
                .force_allow_id(),
        )
        .await?;
    Ok(true)
}

async fn touch_group_updated_at(
    adapter: &dyn DbAdapter,
    group_id: &str,
) -> Result<(), OpenAuthError> {
    adapter
        .update(
            Update::new("team")
                .where_clause(Where::new("id", DbValue::String(group_id.to_owned())))
                .data("updated_at", DbValue::Timestamp(OffsetDateTime::now_utc())),
        )
        .await?;
    Ok(())
}

pub(super) async fn list_group_teams(
    adapter: &dyn DbAdapter,
    organization_id: &str,
) -> Result<Vec<ScimTeamRecord>, OpenAuthError> {
    adapter
        .find_many(
            FindMany::new("team")
                .where_clause(Where::new(
                    "organization_id",
                    DbValue::String(organization_id.to_owned()),
                ))
                .select(["id", "name", "organization_id", "created_at", "updated_at"]),
        )
        .await?
        .into_iter()
        .map(team_from_record)
        .collect()
}

pub(super) async fn load_group_resource(
    adapter: &dyn DbAdapter,
    base_url: &str,
    provider_id: &str,
    organization_id: &str,
    group_id: &str,
) -> Result<Option<ScimGroupResource>, OpenAuthError> {
    let Some(record) = adapter
        .find_one(
            FindOne::new("team")
                .where_clause(Where::new("id", DbValue::String(group_id.to_owned())))
                .where_clause(Where::new(
                    "organization_id",
                    DbValue::String(organization_id.to_owned()),
                ))
                .select(["id", "name", "organization_id", "created_at", "updated_at"]),
        )
        .await?
    else {
        return Ok(None);
    };
    let team = team_from_record(record)?;
    group_resource_from_team(adapter, base_url, provider_id, organization_id, &team).await
}

pub(super) async fn group_resource_from_team(
    adapter: &dyn DbAdapter,
    base_url: &str,
    provider_id: &str,
    organization_id: &str,
    team: &ScimTeamRecord,
) -> Result<Option<ScimGroupResource>, OpenAuthError> {
    // SCIM may only manage teams that carry a `scimGroupProfile` marker within
    // the organization. Native organization teams have no such marker and must
    // stay outside the SCIM boundary, so they cannot be enumerated, read, or
    // mutated through SCIM group routes. Markers are shared across providers in
    // the same organization, so ownership is enforced at the org level (not per
    // provider) to preserve cross-provider visibility of SCIM-managed groups.
    if !team_is_scim_managed(adapter, organization_id, &team.id).await? {
        return Ok(None);
    }
    let profile = scim_group_profile(adapter, provider_id, &team.id).await?;
    let members = group_members(adapter, base_url, provider_id, organization_id, &team.id).await?;
    Ok(Some(group_resource(
        base_url,
        &team.id,
        profile.and_then(|profile| profile.external_id),
        team.name.clone(),
        team.created_at,
        team.updated_at.unwrap_or(team.created_at),
        members,
    )))
}

pub(super) async fn team_is_scim_managed(
    adapter: &dyn DbAdapter,
    organization_id: &str,
    team_id: &str,
) -> Result<bool, OpenAuthError> {
    Ok(
        scim_managed_team_ids(adapter, organization_id, &[team_id.to_owned()])
            .await?
            .contains(team_id),
    )
}

pub(super) async fn scim_managed_team_ids(
    adapter: &dyn DbAdapter,
    organization_id: &str,
    team_ids: &[String],
) -> Result<std::collections::BTreeSet<String>, OpenAuthError> {
    if team_ids.is_empty() {
        return Ok(std::collections::BTreeSet::new());
    }
    let profiles = match adapter
        .find_many(
            FindMany::new("scimGroupProfile")
                .where_clause(Where::new(
                    "organizationId",
                    DbValue::String(organization_id.to_owned()),
                ))
                .where_clause(
                    Where::new("teamId", DbValue::StringArray(team_ids.to_vec()))
                        .operator(WhereOperator::In),
                )
                .select(["teamId"]),
        )
        .await
    {
        Ok(profiles) => profiles,
        Err(OpenAuthError::TableNotFound { table }) if table == "scimGroupProfile" => {
            return Ok(std::collections::BTreeSet::new());
        }
        Err(error) => return Err(error),
    };
    let mut managed = std::collections::BTreeSet::new();
    for profile in profiles {
        let Some(team_id) = optional_string(&profile, "teamId")? else {
            continue;
        };
        managed.insert(team_id);
    }
    Ok(managed)
}

pub(super) async fn replace_group(
    adapter: &dyn DbAdapter,
    provider_id: &str,
    organization_id: &str,
    group_id: &str,
    input: ScimGroupInput,
) -> Result<(), OpenAuthError> {
    if input.display_name.trim().is_empty() {
        return Err(OpenAuthError::Api("displayName is required".to_owned()));
    }
    reject_nested_group_members(&input.members).map_err(|error| {
        OpenAuthError::Api(
            error
                .detail
                .unwrap_or_else(|| "Invalid group member".to_owned()),
        )
    })?;
    let provider_id = provider_id.to_owned();
    let organization_id = organization_id.to_owned();
    let group_id = group_id.to_owned();
    adapter
        .transaction(Box::new(move |transaction| {
            Box::pin(async move {
                transaction
                    .update(
                        Update::new("team")
                            .where_clause(Where::new("id", DbValue::String(group_id.clone())))
                            .data(
                                "name",
                                DbValue::String(input.display_name.trim().to_owned()),
                            )
                            .data("updated_at", DbValue::Timestamp(OffsetDateTime::now_utc())),
                    )
                    .await?;
                upsert_scim_group_profile(
                    transaction.as_ref(),
                    &provider_id,
                    &organization_id,
                    &group_id,
                    input.external_id.as_deref(),
                )
                .await?;
                transaction
                    .delete_many(
                        DeleteMany::new("team_member")
                            .where_clause(Where::new("team_id", DbValue::String(group_id.clone()))),
                    )
                    .await?;
                for member in input.members {
                    create_team_member_if_missing(transaction.as_ref(), &group_id, &member.value)
                        .await?;
                }
                Ok(())
            })
        }))
        .await
}

pub(super) async fn upsert_scim_group_profile(
    adapter: &dyn DbAdapter,
    provider_id: &str,
    organization_id: &str,
    team_id: &str,
    external_id: Option<&str>,
) -> Result<(), OpenAuthError> {
    if adapter
        .find_one(
            FindOne::new("scimGroupProfile")
                .where_clause(Where::new(
                    "providerId",
                    DbValue::String(provider_id.to_owned()),
                ))
                .where_clause(Where::new("teamId", DbValue::String(team_id.to_owned()))),
        )
        .await?
        .is_some()
    {
        adapter
            .update(
                Update::new("scimGroupProfile")
                    .where_clause(Where::new(
                        "providerId",
                        DbValue::String(provider_id.to_owned()),
                    ))
                    .where_clause(Where::new("teamId", DbValue::String(team_id.to_owned())))
                    .data(
                        "externalId",
                        external_id
                            .map(|value| DbValue::String(value.to_owned()))
                            .unwrap_or(DbValue::Null),
                    )
                    .data("updatedAt", DbValue::Timestamp(OffsetDateTime::now_utc())),
            )
            .await?;
        return Ok(());
    }
    create_scim_group_profile(adapter, provider_id, organization_id, team_id, external_id).await
}

pub(super) async fn apply_group_patch(
    adapter: &dyn DbAdapter,
    provider_id: &str,
    organization_id: &str,
    group_id: &str,
    operations: Vec<PatchOperationInput>,
) -> Result<(), ScimErrorOrOpenAuth> {
    let mut mutations = Vec::new();
    for operation in operations {
        let op = operation.op.unwrap_or_else(|| "replace".to_owned());
        match op.to_ascii_lowercase().as_str() {
            "add" => {
                if operation.path.as_deref() == Some("members") {
                    let members = members_from_patch_value(&operation.value)
                        .map_err(ScimErrorOrOpenAuth::Scim)?;
                    validate_group_member_users(adapter, provider_id, organization_id, &members)
                        .await?;
                    mutations.push(GroupPatchMutation::AddMembers(members));
                } else {
                    return Err(ScimErrorOrOpenAuth::Scim(unsupported_group_patch_path()));
                }
            }
            "replace" => {
                if operation.path.as_deref() == Some("displayName") {
                    let Some(display_name) = operation.value.as_str() else {
                        return Err(ScimErrorOrOpenAuth::Scim(
                            ScimError::bad_request("displayName must be a string")
                                .with_scim_type("invalidValue"),
                        ));
                    };
                    validate_group_display_name(display_name).map_err(ScimErrorOrOpenAuth::Scim)?;
                    mutations.push(GroupPatchMutation::ReplaceDisplayName(
                        display_name.trim().to_owned(),
                    ));
                } else if operation.path.as_deref() == Some("members") {
                    let members = members_from_patch_value(&operation.value)
                        .map_err(ScimErrorOrOpenAuth::Scim)?;
                    validate_group_member_users(adapter, provider_id, organization_id, &members)
                        .await?;
                    mutations.push(GroupPatchMutation::ReplaceMembers(members));
                } else {
                    return Err(ScimErrorOrOpenAuth::Scim(unsupported_group_patch_path()));
                }
            }
            "remove" => {
                if let Some(path) = operation.path.as_deref() {
                    if let Some(member_id) = member_value_from_filter_path(path) {
                        mutations.push(GroupPatchMutation::RemoveMember(member_id));
                    } else {
                        return Err(ScimErrorOrOpenAuth::Scim(unsupported_group_patch_path()));
                    }
                } else {
                    return Err(ScimErrorOrOpenAuth::Scim(unsupported_group_patch_path()));
                }
            }
            _ => {
                return Err(ScimErrorOrOpenAuth::Scim(
                    ScimError::bad_request("Invalid PatchOp operation")
                        .with_scim_type("invalidSyntax"),
                ));
            }
        }
    }
    if mutations.is_empty() {
        return Err(ScimErrorOrOpenAuth::Scim(unsupported_group_patch_path()));
    }

    let group_id = group_id.to_owned();
    adapter
        .transaction(Box::new(move |transaction| {
            Box::pin(async move {
                for mutation in mutations {
                    apply_group_patch_mutation(transaction.as_ref(), &group_id, mutation).await?;
                }
                Ok(())
            })
        }))
        .await
        .map_err(ScimErrorOrOpenAuth::OpenAuth)
}

enum GroupPatchMutation {
    AddMembers(Vec<String>),
    ReplaceMembers(Vec<String>),
    ReplaceDisplayName(String),
    RemoveMember(String),
}

async fn apply_group_patch_mutation(
    adapter: &dyn DbAdapter,
    group_id: &str,
    mutation: GroupPatchMutation,
) -> Result<(), OpenAuthError> {
    match mutation {
        GroupPatchMutation::AddMembers(members) => {
            let mut membership_changed = false;
            for member in members {
                membership_changed |=
                    create_team_member_if_missing(adapter, group_id, &member).await?;
            }
            if membership_changed {
                touch_group_updated_at(adapter, group_id).await?;
            }
        }
        GroupPatchMutation::ReplaceMembers(members) => {
            adapter
                .delete_many(
                    DeleteMany::new("team_member")
                        .where_clause(Where::new("team_id", DbValue::String(group_id.to_owned()))),
                )
                .await?;
            for member in members {
                create_team_member_if_missing(adapter, group_id, &member).await?;
            }
            touch_group_updated_at(adapter, group_id).await?;
        }
        GroupPatchMutation::ReplaceDisplayName(display_name) => {
            adapter
                .update(
                    Update::new("team")
                        .where_clause(Where::new("id", DbValue::String(group_id.to_owned())))
                        .data("name", DbValue::String(display_name))
                        .data("updated_at", DbValue::Timestamp(OffsetDateTime::now_utc())),
                )
                .await?;
        }
        GroupPatchMutation::RemoveMember(member_id) => {
            let removed = adapter
                .delete_many(
                    DeleteMany::new("team_member")
                        .where_clause(Where::new("team_id", DbValue::String(group_id.to_owned())))
                        .where_clause(Where::new("user_id", DbValue::String(member_id))),
                )
                .await?;
            if removed > 0 {
                touch_group_updated_at(adapter, group_id).await?;
            }
        }
    }
    Ok(())
}

fn unsupported_group_patch_path() -> ScimError {
    ScimError::bad_request("Unsupported Group PatchOp path").with_scim_type("invalidPath")
}

pub(super) fn group_input_member_values(members: &[ScimGroupMemberInput]) -> Vec<String> {
    members.iter().map(|member| member.value.clone()).collect()
}

pub(super) async fn validate_group_member_users(
    adapter: &dyn DbAdapter,
    provider_id: &str,
    organization_id: &str,
    members: &[String],
) -> Result<(), ScimErrorOrOpenAuth> {
    for member in members {
        if find_scim_user(adapter, member, provider_id, Some(organization_id))
            .await
            .map_err(ScimErrorOrOpenAuth::OpenAuth)?
            .is_none()
        {
            return Err(ScimErrorOrOpenAuth::Scim(
                ScimError::bad_request("Group member not found").with_scim_type("invalidValue"),
            ));
        }
    }
    Ok(())
}

pub(super) fn members_from_patch_value(
    value: &serde_json::Value,
) -> Result<Vec<String>, ScimError> {
    let values = value
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_else(|| std::slice::from_ref(value));
    let mut members = Vec::new();
    for value in values {
        if value
            .get("type")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|type_| type_.eq_ignore_ascii_case("Group"))
        {
            return Err(
                ScimError::bad_request("Nested group members are not supported")
                    .with_scim_type("invalidValue"),
            );
        }
        let Some(member) = value
            .as_str()
            .or_else(|| value.get("value").and_then(serde_json::Value::as_str))
        else {
            return Err(ScimError::bad_request("Group member value is required")
                .with_scim_type("invalidValue"));
        };
        members.push(member.to_owned());
    }
    Ok(members)
}

pub(super) fn member_value_from_filter_path(path: &str) -> Option<String> {
    let prefix = "members[value eq \"";
    let suffix = "\"]";
    path.strip_prefix(prefix)
        .and_then(|value| value.strip_suffix(suffix))
        .map(str::to_owned)
}

pub(super) async fn delete_group(
    adapter: &dyn DbAdapter,
    provider_id: &str,
    group_id: &str,
) -> Result<(), OpenAuthError> {
    let provider_id = provider_id.to_owned();
    let group_id = group_id.to_owned();
    adapter
        .transaction(Box::new(move |transaction| {
            Box::pin(async move {
                transaction
                    .delete_many(
                        DeleteMany::new("team_member")
                            .where_clause(Where::new("team_id", DbValue::String(group_id.clone()))),
                    )
                    .await?;
                transaction
                    .delete_many(
                        DeleteMany::new("scimGroupProfile")
                            .where_clause(Where::new("providerId", DbValue::String(provider_id)))
                            .where_clause(Where::new("teamId", DbValue::String(group_id.clone()))),
                    )
                    .await?;
                transaction
                    .delete(
                        Delete::new("team")
                            .where_clause(Where::new("id", DbValue::String(group_id))),
                    )
                    .await
            })
        }))
        .await
}

pub(super) async fn load_group_resources(
    adapter: &dyn DbAdapter,
    base_url: &str,
    provider_id: &str,
    organization_id: &str,
) -> Result<Vec<ScimGroupResource>, OpenAuthError> {
    let teams = list_group_teams(adapter, organization_id).await?;
    let mut resources = Vec::with_capacity(teams.len());
    for team in teams {
        if let Some(resource) =
            group_resource_from_team(adapter, base_url, provider_id, organization_id, &team).await?
        {
            resources.push(resource);
        }
    }
    Ok(resources)
}

pub(super) fn filter_group_resources(
    resources: Vec<ScimGroupResource>,
    filter: &str,
) -> Result<Vec<ScimGroupResource>, ScimError> {
    resources
        .into_iter()
        .map(|resource| {
            let value = serde_json::to_value(&resource)
                .map_err(|error| ScimError::bad_request(error.to_string()))?;
            Ok((resource, resource_matches_filter(&value, filter)?))
        })
        .filter_map(|result| match result {
            Ok((resource, true)) => Some(Ok(resource)),
            Ok((_, false)) => None,
            Err(error) => Some(Err(error)),
        })
        .collect()
}

pub(super) fn reject_nested_group_members(
    members: &[ScimGroupMemberInput],
) -> Result<(), ScimError> {
    if members.iter().any(|member| {
        member
            .type_
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case("Group"))
    }) {
        return Err(
            ScimError::bad_request("Nested Group members are not supported")
                .with_scim_type("invalidValue"),
        );
    }
    Ok(())
}

pub(super) async fn scim_group_profile(
    adapter: &dyn DbAdapter,
    provider_id: &str,
    team_id: &str,
) -> Result<Option<ScimGroupProfileRecord>, OpenAuthError> {
    adapter
        .find_one(
            FindOne::new("scimGroupProfile")
                .where_clause(Where::new(
                    "providerId",
                    DbValue::String(provider_id.to_owned()),
                ))
                .where_clause(Where::new("teamId", DbValue::String(team_id.to_owned())))
                .select(["externalId"]),
        )
        .await?
        .map(|record| {
            Ok(ScimGroupProfileRecord {
                external_id: optional_string(&record, "externalId")?,
            })
        })
        .transpose()
}

pub(super) async fn group_members(
    adapter: &dyn DbAdapter,
    base_url: &str,
    provider_id: &str,
    organization_id: &str,
    team_id: &str,
) -> Result<Vec<crate::resources::ScimGroupResourceMember>, OpenAuthError> {
    let user_ids = adapter
        .find_many(
            FindMany::new("team_member")
                .where_clause(Where::new("team_id", DbValue::String(team_id.to_owned())))
                .select(["user_id"]),
        )
        .await?
        .into_iter()
        .filter_map(|record| match record.get("user_id") {
            Some(DbValue::String(user_id)) => Some(user_id.to_owned()),
            _ => None,
        })
        .collect::<Vec<_>>();
    if user_ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut members = Vec::new();
    for user_id in user_ids {
        let Some((user, _account)) =
            find_scim_user(adapter, &user_id, provider_id, Some(organization_id)).await?
        else {
            continue;
        };
        members.push(group_member_resource(base_url, &user.id, Some(user.name)));
    }
    Ok(members)
}
