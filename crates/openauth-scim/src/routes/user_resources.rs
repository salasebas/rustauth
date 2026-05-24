use super::*;

pub(super) async fn find_scim_user(
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

#[allow(clippy::too_many_arguments)]
pub(super) async fn create_scim_user_account_and_membership(
    adapter: &dyn DbAdapter,
    existing_user: Option<User>,
    user_input: CreateUserInput,
    mut account_input: CreateOAuthAccountInput,
    organization_id: Option<String>,
    provider_id: String,
    external_id: Option<String>,
    profile_attributes: serde_json::Value,
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
                upsert_scim_user_profile(
                    transaction.as_ref(),
                    &provider_id,
                    &user.id,
                    external_id.as_deref(),
                    profile_attributes,
                )
                .await?;
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

pub(super) fn store_create_scim_user_result(
    result: &Mutex<Option<CreateScimUserResult>>,
    value: CreateScimUserResult,
) -> Result<(), OpenAuthError> {
    let mut guard = result.lock().map_err(|_| {
        OpenAuthError::Adapter("create SCIM user result mutex was poisoned".to_owned())
    })?;
    *guard = Some(value);
    Ok(())
}

pub(super) fn take_create_scim_user_result(
    result: &Mutex<Option<CreateScimUserResult>>,
) -> Result<Option<CreateScimUserResult>, OpenAuthError> {
    let mut guard = result.lock().map_err(|_| {
        OpenAuthError::Adapter("create SCIM user result mutex was poisoned".to_owned())
    })?;
    Ok(guard.take())
}

pub(super) async fn load_user_resources(
    adapter: &dyn DbAdapter,
    base_url: &str,
    provider: &AuthenticatedScimProvider,
    filter: Option<&str>,
) -> Result<Vec<ScimUserResource>, ScimErrorOrOpenAuth> {
    if let Some(filter) = filter {
        parse_filter(filter).map_err(ScimErrorOrOpenAuth::Scim)?;
    }
    let db_filters = filter.and_then(|filter| parse_user_filter(filter).ok());
    let accounts = adapter
        .find_many(
            FindMany::new("account")
                .where_clause(Where::new(
                    "provider_id",
                    DbValue::String(provider.provider_id.clone()),
                ))
                .select(ACCOUNT_FIELDS),
        )
        .await
        .map_err(ScimErrorOrOpenAuth::OpenAuth)?
        .into_iter()
        .map(account_from_record)
        .collect::<Result<Vec<_>, _>>()
        .map_err(ScimErrorOrOpenAuth::OpenAuth)?;
    if accounts.is_empty() {
        return Ok(Vec::new());
    }

    let mut user_ids = accounts
        .iter()
        .map(|account| account.user_id.clone())
        .collect::<Vec<_>>();
    if let Some(organization_id) = provider.organization_id.as_deref() {
        let members = adapter
            .find_many(
                FindMany::new("member")
                    .where_clause(Where::new(
                        "organization_id",
                        DbValue::String(organization_id.to_owned()),
                    ))
                    .where_clause(
                        Where::new("user_id", DbValue::StringArray(user_ids))
                            .operator(WhereOperator::In),
                    )
                    .select(["user_id"]),
            )
            .await
            .map_err(ScimErrorOrOpenAuth::OpenAuth)?;
        user_ids = members
            .into_iter()
            .filter_map(|member| match member.get("user_id") {
                Some(DbValue::String(user_id)) => Some(user_id.to_owned()),
                _ => None,
            })
            .collect();
        if user_ids.is_empty() {
            return Ok(Vec::new());
        }
    }

    let mut query = FindMany::new("user")
        .where_clause(Where::new("id", DbValue::StringArray(user_ids)).operator(WhereOperator::In));
    if let Some(filters) = db_filters.as_deref() {
        for filter in filters {
            match filter.operator {
                ScimFilterOperator::Eq => {
                    query = query.where_clause(Where::new(
                        &filter.field,
                        DbValue::String(filter.value.clone()),
                    ));
                }
            }
        }
    }
    let query = query.select([
        "id",
        "name",
        "email",
        "email_verified",
        "image",
        "created_at",
        "updated_at",
    ]);
    let users = adapter
        .find_many(query)
        .await
        .map_err(ScimErrorOrOpenAuth::OpenAuth)?
        .into_iter()
        .map(user_from_record)
        .collect::<Result<Vec<_>, _>>()
        .map_err(ScimErrorOrOpenAuth::OpenAuth)?;

    let profile_records = scim_user_profiles_by_user(
        adapter,
        &provider.provider_id,
        &users.iter().map(|user| user.id.clone()).collect::<Vec<_>>(),
    )
    .await
    .map_err(ScimErrorOrOpenAuth::OpenAuth)?;
    let mut group_records = scim_user_groups_by_user(
        adapter,
        base_url,
        provider.organization_id.as_deref(),
        &users.iter().map(|user| user.id.clone()).collect::<Vec<_>>(),
    )
    .await
    .map_err(ScimErrorOrOpenAuth::OpenAuth)?;

    let mut resources = Vec::new();
    for user in users {
        if let Some(account) = accounts.iter().find(|account| account.user_id == user.id) {
            let mut resource = user_resource(base_url, &user, Some(account));
            if let Some((attributes, version)) = profile_records.get(&user.id) {
                apply_scim_user_profile(attributes, version.as_deref(), &mut resource);
            }
            if let Some(groups) = group_records.remove(&user.id) {
                resource.groups = groups;
            }
            if let Some(filter) = filter.filter(|_| db_filters.is_none()) {
                let value = serde_json::to_value(&resource).map_err(|error| {
                    ScimErrorOrOpenAuth::OpenAuth(OpenAuthError::Api(error.to_string()))
                })?;
                if !resource_matches_filter(&value, filter).map_err(ScimErrorOrOpenAuth::Scim)? {
                    continue;
                }
            }
            resources.push(resource);
        }
    }
    Ok(resources)
}

pub(super) async fn complete_user_resource(
    adapter: &dyn DbAdapter,
    base_url: &str,
    provider: &AuthenticatedScimProvider,
    user: &User,
    account: &Account,
) -> Result<ScimUserResource, OpenAuthError> {
    let mut resource = user_resource(base_url, user, Some(account));
    merge_scim_user_profile(adapter, &provider.provider_id, &user.id, &mut resource).await?;
    merge_scim_user_groups(
        adapter,
        base_url,
        provider.organization_id.as_deref(),
        &user.id,
        &mut resource,
    )
    .await?;
    Ok(resource)
}

async fn scim_user_profiles_by_user(
    adapter: &dyn DbAdapter,
    provider_id: &str,
    user_ids: &[String],
) -> Result<std::collections::BTreeMap<String, (serde_json::Value, Option<String>)>, OpenAuthError>
{
    if user_ids.is_empty() {
        return Ok(std::collections::BTreeMap::new());
    }
    let records = adapter
        .find_many(
            FindMany::new("scimUserProfile")
                .where_clause(Where::new(
                    "providerId",
                    DbValue::String(provider_id.to_owned()),
                ))
                .where_clause(
                    Where::new("userId", DbValue::StringArray(user_ids.to_vec()))
                        .operator(WhereOperator::In),
                )
                .select(["userId", "attributes", "version"]),
        )
        .await?;
    let mut profiles = std::collections::BTreeMap::new();
    for record in records {
        let Some(user_id) = optional_string(&record, "userId")? else {
            continue;
        };
        let attributes = optional_json(&record, "attributes")?
            .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()));
        let version = optional_string(&record, "version")?;
        profiles.insert(user_id, (attributes, version));
    }
    Ok(profiles)
}

async fn scim_user_groups_by_user(
    adapter: &dyn DbAdapter,
    base_url: &str,
    organization_id: Option<&str>,
    user_ids: &[String],
) -> Result<std::collections::BTreeMap<String, Vec<ScimUserResourceGroup>>, OpenAuthError> {
    let Some(organization_id) = organization_id else {
        return Ok(std::collections::BTreeMap::new());
    };
    if user_ids.is_empty() {
        return Ok(std::collections::BTreeMap::new());
    }
    let memberships = match adapter
        .find_many(
            FindMany::new("team_member")
                .where_clause(
                    Where::new("user_id", DbValue::StringArray(user_ids.to_vec()))
                        .operator(WhereOperator::In),
                )
                .select(["user_id", "team_id"]),
        )
        .await
    {
        Ok(memberships) => memberships,
        Err(OpenAuthError::TableNotFound { table }) if table == "team_member" => {
            return Ok(std::collections::BTreeMap::new());
        }
        Err(error) => return Err(error),
    };
    let mut memberships_by_user = std::collections::BTreeMap::<String, Vec<String>>::new();
    let mut team_ids = Vec::new();
    for membership in memberships {
        let Some(user_id) = optional_string(&membership, "user_id")? else {
            continue;
        };
        let Some(team_id) = optional_string(&membership, "team_id")? else {
            continue;
        };
        memberships_by_user
            .entry(user_id)
            .or_default()
            .push(team_id.clone());
        team_ids.push(team_id);
    }
    if team_ids.is_empty() {
        return Ok(std::collections::BTreeMap::new());
    }
    team_ids.sort();
    team_ids.dedup();
    let teams = match adapter
        .find_many(
            FindMany::new("team")
                .where_clause(
                    Where::new("id", DbValue::StringArray(team_ids)).operator(WhereOperator::In),
                )
                .where_clause(Where::new(
                    "organization_id",
                    DbValue::String(organization_id.to_owned()),
                ))
                .select(["id", "name", "organization_id", "created_at", "updated_at"]),
        )
        .await
    {
        Ok(teams) => teams,
        Err(OpenAuthError::TableNotFound { table }) if table == "team" => {
            return Ok(std::collections::BTreeMap::new());
        }
        Err(error) => return Err(error),
    }
    .into_iter()
    .map(team_from_record)
    .collect::<Result<Vec<_>, _>>()?;
    let teams_by_id = teams
        .into_iter()
        .map(|team| (team.id.clone(), team))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut groups_by_user = std::collections::BTreeMap::new();
    for (user_id, team_ids) in memberships_by_user {
        let groups = team_ids
            .into_iter()
            .filter_map(|team_id| teams_by_id.get(&team_id))
            .map(|team| ScimUserResourceGroup {
                value: team.id.clone(),
                ref_: crate::mappings::resource_url(
                    base_url,
                    &format!("/scim/v2/Groups/{}", team.id),
                ),
                display: Some(team.name.clone()),
            })
            .collect::<Vec<_>>();
        if !groups.is_empty() {
            groups_by_user.insert(user_id, groups);
        }
    }
    Ok(groups_by_user)
}

pub(super) async fn merge_scim_user_groups(
    adapter: &dyn DbAdapter,
    base_url: &str,
    organization_id: Option<&str>,
    user_id: &str,
    resource: &mut ScimUserResource,
) -> Result<(), OpenAuthError> {
    let Some(organization_id) = organization_id else {
        return Ok(());
    };
    let memberships = match adapter
        .find_many(
            FindMany::new("team_member")
                .where_clause(Where::new("user_id", DbValue::String(user_id.to_owned())))
                .select(["team_id"]),
        )
        .await
    {
        Ok(memberships) => memberships,
        Err(OpenAuthError::TableNotFound { table }) if table == "team_member" => return Ok(()),
        Err(error) => return Err(error),
    };
    let team_ids = memberships
        .into_iter()
        .filter_map(|record| match record.get("team_id") {
            Some(DbValue::String(team_id)) => Some(team_id.to_owned()),
            _ => None,
        })
        .collect::<Vec<_>>();
    if team_ids.is_empty() {
        return Ok(());
    }
    let query = FindMany::new("team")
        .where_clause(Where::new("id", DbValue::StringArray(team_ids)).operator(WhereOperator::In))
        .where_clause(Where::new(
            "organization_id",
            DbValue::String(organization_id.to_owned()),
        ))
        .select(["id", "name", "organization_id", "created_at", "updated_at"]);
    let groups = match adapter.find_many(query).await {
        Ok(groups) => groups,
        Err(OpenAuthError::TableNotFound { table }) if table == "team" => return Ok(()),
        Err(error) => return Err(error),
    }
    .into_iter()
    .map(team_from_record)
    .collect::<Result<Vec<_>, _>>()?;
    resource.groups = groups
        .into_iter()
        .map(|team| ScimUserResourceGroup {
            value: team.id.clone(),
            ref_: crate::mappings::resource_url(base_url, &format!("/scim/v2/Groups/{}", team.id)),
            display: Some(team.name),
        })
        .collect();
    Ok(())
}

pub(super) fn user_list_response(
    resources: Vec<ScimUserResource>,
    start_index: Option<usize>,
    count: Option<usize>,
) -> metadata::ListResponse<ScimUserResource> {
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

pub(super) fn scim_user_profile_attributes(input: &ScimUserInput) -> serde_json::Value {
    let mut attributes = serde_json::Map::new();
    for (key, value) in &input.additional_fields {
        if !value.is_null() && !is_reserved_scim_user_profile_attribute(key) {
            attributes.insert(key.clone(), value.clone());
        }
    }
    for schema in &input.schemas {
        if schema != metadata::SCIM_USER_SCHEMA_ID && !attributes.contains_key(schema) {
            attributes.insert(schema.clone(), serde_json::json!({}));
        }
    }
    serde_json::Value::Object(attributes)
}

pub(super) fn validate_scim_user_profile_attributes(
    input: &ScimUserInput,
) -> Result<(), ScimError> {
    for key in input.additional_fields.keys() {
        if is_reserved_scim_user_profile_attribute(key) {
            return Err(reserved_scim_user_attribute_error(key));
        }
    }
    Ok(())
}

pub(super) fn is_reserved_scim_user_profile_attribute(path: &str) -> bool {
    let path = path.trim_start_matches('/');
    if path == metadata::SCIM_USER_SCHEMA_ID {
        return true;
    }
    if path.starts_with("urn:ietf:params:scim:schemas:") && path != metadata::SCIM_USER_SCHEMA_ID {
        return false;
    }
    let root = path
        .split(['.', '['])
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase();
    matches!(
        root.as_str(),
        "id" | "meta"
            | "schemas"
            | "username"
            | "name"
            | "emails"
            | "externalid"
            | "groups"
            | "active"
            | "displayname"
    )
}

pub(super) fn reserved_scim_user_attribute_error(attribute: &str) -> ScimError {
    ScimError::bad_request(format!(
        "Attribute `{attribute}` is a core SCIM User attribute and cannot be persisted as profile data"
    ))
    .with_scim_type("mutability")
}

pub(super) async fn upsert_scim_user_profile(
    adapter: &dyn DbAdapter,
    provider_id: &str,
    user_id: &str,
    external_id: Option<&str>,
    attributes: serde_json::Value,
) -> Result<(), OpenAuthError> {
    let now = OffsetDateTime::now_utc();
    if adapter
        .find_one(
            FindOne::new("scimUserProfile")
                .where_clause(Where::new(
                    "providerId",
                    DbValue::String(provider_id.to_owned()),
                ))
                .where_clause(Where::new("userId", DbValue::String(user_id.to_owned()))),
        )
        .await?
        .is_some()
    {
        adapter
            .update(
                Update::new("scimUserProfile")
                    .where_clause(Where::new(
                        "providerId",
                        DbValue::String(provider_id.to_owned()),
                    ))
                    .where_clause(Where::new("userId", DbValue::String(user_id.to_owned())))
                    .data(
                        "externalId",
                        external_id
                            .map(|value| DbValue::String(value.to_owned()))
                            .unwrap_or(DbValue::Null),
                    )
                    .data("attributes", DbValue::Json(attributes))
                    .data("version", DbValue::String(resource_version(now)))
                    .data("updatedAt", DbValue::Timestamp(now)),
            )
            .await?;
        return Ok(());
    }
    adapter
        .create(
            Create::new("scimUserProfile")
                .data("id", DbValue::String(generate_random_string(32)))
                .data("providerId", DbValue::String(provider_id.to_owned()))
                .data("userId", DbValue::String(user_id.to_owned()))
                .data(
                    "externalId",
                    external_id
                        .map(|value| DbValue::String(value.to_owned()))
                        .unwrap_or(DbValue::Null),
                )
                .data("attributes", DbValue::Json(attributes))
                .data("version", DbValue::String(resource_version(now)))
                .data("createdAt", DbValue::Timestamp(now))
                .data("updatedAt", DbValue::Timestamp(now))
                .force_allow_id(),
        )
        .await?;
    Ok(())
}

pub(super) async fn merge_scim_user_profile(
    adapter: &dyn DbAdapter,
    provider_id: &str,
    user_id: &str,
    resource: &mut ScimUserResource,
) -> Result<(), OpenAuthError> {
    let Some(record) = adapter
        .find_one(
            FindOne::new("scimUserProfile")
                .where_clause(Where::new(
                    "providerId",
                    DbValue::String(provider_id.to_owned()),
                ))
                .where_clause(Where::new("userId", DbValue::String(user_id.to_owned())))
                .select(["attributes", "version"]),
        )
        .await?
    else {
        return Ok(());
    };
    let Some(attributes) = optional_json(&record, "attributes")? else {
        return Ok(());
    };
    if let Some(version) = optional_string(&record, "version")? {
        apply_scim_user_profile(&attributes, Some(&version), resource);
    } else {
        apply_scim_user_profile(&attributes, None, resource);
    }
    Ok(())
}

fn apply_scim_user_profile(
    attributes: &serde_json::Value,
    version: Option<&str>,
    resource: &mut ScimUserResource,
) {
    if let Some(object) = attributes.as_object() {
        for (key, value) in object {
            if is_reserved_scim_user_profile_attribute(key) {
                continue;
            }
            if key.starts_with("urn:ietf:params:scim:schemas:")
                && !resource.schemas.iter().any(|schema| schema == key)
            {
                resource.schemas.push(key.clone());
            }
            resource
                .additional_fields
                .insert(key.clone(), value.clone());
        }
    }
    if let Some(version) = version {
        resource.meta.version = Some(version.to_owned());
    }
}

pub(super) async fn merge_scim_user_profile_patch(
    adapter: &dyn DbAdapter,
    provider_id: &str,
    user_id: &str,
    patch: indexmap::IndexMap<String, serde_json::Value>,
) -> Result<(), OpenAuthError> {
    let mut attributes = adapter
        .find_one(
            FindOne::new("scimUserProfile")
                .where_clause(Where::new(
                    "providerId",
                    DbValue::String(provider_id.to_owned()),
                ))
                .where_clause(Where::new("userId", DbValue::String(user_id.to_owned())))
                .select(["attributes"]),
        )
        .await?
        .map(|record| optional_json(&record, "attributes"))
        .transpose()?
        .flatten()
        .unwrap_or_else(|| serde_json::json!({}));
    if !attributes.is_object() {
        attributes = serde_json::json!({});
    }
    if let Some(object) = attributes.as_object_mut() {
        for (key, value) in patch {
            if is_reserved_scim_user_profile_attribute(&key) {
                continue;
            }
            merge_json_field(object, key, value);
        }
    }
    let now = OffsetDateTime::now_utc();
    if adapter
        .find_one(
            FindOne::new("scimUserProfile")
                .where_clause(Where::new(
                    "providerId",
                    DbValue::String(provider_id.to_owned()),
                ))
                .where_clause(Where::new("userId", DbValue::String(user_id.to_owned()))),
        )
        .await?
        .is_some()
    {
        adapter
            .update(
                Update::new("scimUserProfile")
                    .where_clause(Where::new(
                        "providerId",
                        DbValue::String(provider_id.to_owned()),
                    ))
                    .where_clause(Where::new("userId", DbValue::String(user_id.to_owned())))
                    .data("attributes", DbValue::Json(attributes))
                    .data("version", DbValue::String(resource_version(now)))
                    .data("updatedAt", DbValue::Timestamp(now)),
            )
            .await?;
        return Ok(());
    }
    upsert_scim_user_profile(adapter, provider_id, user_id, None, attributes).await
}

pub(super) fn merge_json_field(
    object: &mut serde_json::Map<String, serde_json::Value>,
    key: String,
    value: serde_json::Value,
) {
    if value.is_null() {
        remove_json_field(object, &key);
        return;
    }
    if let Some(existing) = object.get_mut(&key) {
        if let (Some(existing), Some(incoming)) = (existing.as_object_mut(), value.as_object()) {
            for (nested_key, nested_value) in incoming {
                existing.insert(nested_key.clone(), nested_value.clone());
            }
            return;
        }
    }
    object.insert(key, value);
}

fn remove_json_field(object: &mut serde_json::Map<String, serde_json::Value>, path: &str) {
    if let Some((attribute, filter)) = path.split_once('[') {
        if let Some(values) = object
            .get_mut(attribute)
            .and_then(serde_json::Value::as_array_mut)
        {
            if let Some(value) = filter
                .strip_prefix("value eq \"")
                .and_then(|value| value.strip_suffix("\"]"))
            {
                values.retain(|item| {
                    item.get("value").and_then(serde_json::Value::as_str) != Some(value)
                });
                if values.is_empty() {
                    object.remove(attribute);
                }
            }
        }
        return;
    }
    if let Some((schema, attribute)) = path.rsplit_once(':') {
        if schema.starts_with("urn:ietf:params:scim:schemas:") {
            if let Some(schema_object) = object
                .get_mut(schema)
                .and_then(serde_json::Value::as_object_mut)
            {
                schema_object.remove(attribute);
                if schema_object.is_empty() {
                    object.remove(schema);
                }
                return;
            }
        }
    }
    object.remove(path);
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn update_scim_user_account_and_replace_profile(
    adapter: &dyn DbAdapter,
    provider_id: &str,
    user_id: &str,
    account_record_id: &str,
    email: Option<String>,
    name: Option<String>,
    account_id: Option<String>,
    external_id: Option<String>,
    attributes: serde_json::Value,
) -> Result<(), OpenAuthError> {
    let provider_id = provider_id.to_owned();
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
                upsert_scim_user_profile(
                    transaction.as_ref(),
                    &provider_id,
                    &user_id,
                    external_id.as_deref(),
                    attributes,
                )
                .await
            })
        }))
        .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn update_scim_user_account_and_merge_profile(
    adapter: &dyn DbAdapter,
    provider_id: &str,
    user_id: &str,
    account_record_id: &str,
    email: Option<String>,
    name: Option<String>,
    account_id: Option<String>,
    profile_patch: indexmap::IndexMap<String, serde_json::Value>,
) -> Result<(), OpenAuthError> {
    let provider_id = provider_id.to_owned();
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
                if !profile_patch.is_empty() {
                    merge_scim_user_profile_patch(
                        transaction.as_ref(),
                        &provider_id,
                        &user_id,
                        profile_patch,
                    )
                    .await?;
                }
                Ok(())
            })
        }))
        .await
}

pub(super) fn patched_account_id(user: &User, patch: &crate::patch::UserPatch) -> Option<String> {
    let value = patch.account.get("account_id")?;
    if value.is_null() {
        Some(user.email.clone())
    } else {
        value.as_str().map(str::to_owned)
    }
}

pub(super) fn patched_email(
    user: &User,
    patch: &crate::patch::UserPatch,
) -> Result<Option<String>, ScimError> {
    if let Some(value) = patch
        .user
        .get("email")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
    {
        return Ok(Some(value));
    }
    let Some(emails) = patch.emails.as_deref() else {
        return Ok(None);
    };
    validate_emails(emails)?;
    Ok(Some(primary_email(&user.email, emails).to_lowercase()))
}

pub(super) async fn delete_scim_user(
    adapter: &dyn DbAdapter,
    user_id: &str,
) -> Result<(), OpenAuthError> {
    let user_id = user_id.to_owned();
    adapter
        .transaction(Box::new(move |transaction| {
            Box::pin(async move {
                transaction
                    .delete_many(
                        DeleteMany::new("scimUserProfile")
                            .where_clause(Where::new("userId", DbValue::String(user_id.clone()))),
                    )
                    .await?;
                transaction
                    .delete_many(
                        DeleteMany::new("team_member")
                            .where_clause(Where::new("user_id", DbValue::String(user_id.clone()))),
                    )
                    .await?;
                let users = DbUserStore::new(transaction.as_ref());
                users.delete_user_accounts(&user_id).await?;
                users.delete_user(&user_id).await
            })
        }))
        .await
}
