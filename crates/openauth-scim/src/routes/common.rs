use super::*;

pub(super) fn scim_endpoint_options(operation_id: &str, description: &str) -> AuthEndpointOptions {
    endpoint_options(operation_id, description, "application/scim+json", true)
}

pub(super) fn management_endpoint_options(
    operation_id: &str,
    description: &str,
) -> AuthEndpointOptions {
    endpoint_options(operation_id, description, "application/json", false)
}

fn endpoint_options(
    operation_id: &str,
    description: &str,
    success_content_type: &str,
    scim_request_body: bool,
) -> AuthEndpointOptions {
    let mut operation = OpenApiOperation::new(operation_id)
        .description(description)
        .tag("SCIM")
        .response(
            success_status(operation_id),
            openapi_response(description, success_content_type),
        )
        .response("400", openapi_error_response("Bad SCIM request"))
        .response(
            "401",
            openapi_error_response("Invalid or missing SCIM bearer token"),
        )
        .response("403", openapi_error_response("SCIM access denied"))
        .response("404", openapi_error_response("SCIM resource not found"))
        .response("409", openapi_error_response("SCIM resource conflict"))
        .response(
            "412",
            openapi_error_response("SCIM resource version precondition failed"),
        )
        .response(
            "501",
            openapi_error_response("SCIM endpoint is not implemented"),
        );

    if request_body_operation(operation_id) {
        operation = operation.request_body(openapi_request_body(operation_id, scim_request_body));
    }

    AuthEndpointOptions::new()
        .operation_id(operation_id)
        .openapi(operation)
}

fn success_status(operation_id: &str) -> &'static str {
    match operation_id {
        "generateSCIMToken" | "createSCIMUser" | "createSCIMGroup" => "201",
        "patchSCIMUser" | "deleteSCIMUser" | "deleteSCIMGroup" => "204",
        "getSCIMMe" => "501",
        _ => "200",
    }
}

fn request_body_operation(operation_id: &str) -> bool {
    matches!(
        operation_id,
        "generateSCIMToken"
            | "deleteSCIMProviderConnection"
            | "createSCIMUser"
            | "updateSCIMUser"
            | "patchSCIMUser"
            | "searchSCIMUsers"
            | "createSCIMGroup"
            | "updateSCIMGroup"
            | "patchSCIMGroup"
            | "searchSCIMGroups"
            | "searchSCIMResources"
            | "bulkSCIM"
    )
}

fn openapi_request_body(operation_id: &str, include_scim_json: bool) -> serde_json::Value {
    let schema = openapi_named_object_schema(operation_id);
    let mut content = serde_json::Map::new();
    content.insert(
        "application/json".to_owned(),
        serde_json::json!({ "schema": schema.clone() }),
    );
    if include_scim_json {
        content.insert(
            "application/scim+json".to_owned(),
            serde_json::json!({ "schema": schema }),
        );
    }
    serde_json::json!({
        "required": true,
        "content": content
    })
}

fn openapi_response(description: &str, content_type: &str) -> serde_json::Value {
    serde_json::json!({
        "description": description,
        "content": {
            content_type: {
                "schema": {
                    "type": "object"
                }
            }
        }
    })
}

fn openapi_error_response(description: &str) -> serde_json::Value {
    serde_json::json!({
        "description": description,
        "content": {
            "application/scim+json": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "schemas": {
                            "type": "array",
                            "items": { "type": "string" }
                        },
                        "status": { "type": "string" },
                        "scimType": { "type": "string" },
                        "detail": { "type": "string" }
                    }
                }
            },
            "application/json": {
                "schema": {
                    "type": "object"
                }
            }
        }
    })
}

fn openapi_named_object_schema(name: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "title": name
    })
}

pub(super) fn path_param(request: &ApiRequest, name: &str) -> Option<String> {
    request
        .extensions()
        .get::<PathParams>()
        .and_then(|params| params.get(name))
        .map(str::to_owned)
}

pub(super) fn scim_json<T: Serialize>(
    status: StatusCode,
    body: &T,
) -> Result<ApiResponse, OpenAuthError> {
    let body = serde_json::to_vec(body).map_err(|error| OpenAuthError::Api(error.to_string()))?;
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/scim+json")
        .body(body)
        .map_err(|error| OpenAuthError::Api(error.to_string()))
}

pub(super) fn scim_json_with_location_and_etag<T: Serialize>(
    status: StatusCode,
    body: &T,
    location: &str,
    etag: Option<&str>,
) -> Result<ApiResponse, OpenAuthError> {
    let body = serde_json::to_vec(body).map_err(|error| OpenAuthError::Api(error.to_string()))?;
    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/scim+json")
        .header(header::LOCATION, location);
    if let Some(etag) = etag {
        builder = builder.header(header::ETAG, etag);
    }
    builder
        .body(body)
        .map_err(|error| OpenAuthError::Api(error.to_string()))
}

pub(super) fn scim_json_projected_with_etag<T: Serialize>(
    status: StatusCode,
    body: &T,
    request: &ApiRequest,
    etag: Option<&str>,
) -> Result<ApiResponse, OpenAuthError> {
    let mut body =
        serde_json::to_value(body).map_err(|error| OpenAuthError::Api(error.to_string()))?;
    apply_projection(&mut body, request);
    let body = serde_json::to_vec(&body).map_err(|error| OpenAuthError::Api(error.to_string()))?;
    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/scim+json");
    if let Some(etag) = etag {
        builder = builder.header(header::ETAG, etag);
    }
    builder
        .body(body)
        .map_err(|error| OpenAuthError::Api(error.to_string()))
}

pub(super) fn scim_json_projected<T: Serialize>(
    status: StatusCode,
    body: &T,
    request: &ApiRequest,
) -> Result<ApiResponse, OpenAuthError> {
    scim_json_projected_with_etag(status, body, request, None)
}

pub(super) fn scim_json_projected_from_search<T: Serialize>(
    status: StatusCode,
    body: &T,
    search: &SearchRequest,
) -> Result<ApiResponse, OpenAuthError> {
    let mut body =
        serde_json::to_value(body).map_err(|error| OpenAuthError::Api(error.to_string()))?;
    apply_projection_lists(
        &mut body,
        search.attributes.as_deref().unwrap_or(&[]),
        search.excluded_attributes.as_deref().unwrap_or(&[]),
    );
    let body = serde_json::to_vec(&body).map_err(|error| OpenAuthError::Api(error.to_string()))?;
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/scim+json")
        .body(body)
        .map_err(|error| OpenAuthError::Api(error.to_string()))
}

pub(super) fn apply_projection(value: &mut serde_json::Value, request: &ApiRequest) {
    let attributes = query_param(request, "attributes")
        .map(|value| parse_attribute_list(&value))
        .unwrap_or_default();
    let excluded = query_param(request, "excludedAttributes")
        .map(|value| parse_attribute_list(&value))
        .unwrap_or_default();
    apply_projection_lists(value, &attributes, &excluded);
}

pub(super) fn apply_projection_lists(
    value: &mut serde_json::Value,
    attributes: &[String],
    excluded: &[String],
) {
    if let Some(resources) = value
        .get_mut("Resources")
        .and_then(serde_json::Value::as_array_mut)
    {
        for resource in resources {
            apply_resource_projection(resource, attributes, excluded);
        }
    } else {
        apply_resource_projection(value, attributes, excluded);
    }
}

fn apply_resource_projection(
    value: &mut serde_json::Value,
    attributes: &[String],
    excluded: &[String],
) {
    if !attributes.is_empty() {
        let mut projected = serde_json::Map::new();
        if let Some(object) = value.as_object() {
            for key in ["schemas", "id", "meta"] {
                if let Some(existing) = object.get(key) {
                    projected.insert(key.to_owned(), existing.clone());
                }
            }
            for attribute in attributes {
                project_attribute(object, &mut projected, attribute);
            }
        }
        *value = serde_json::Value::Object(projected);
    }
    if !excluded.is_empty() {
        if let Some(object) = value.as_object_mut() {
            for attribute in excluded {
                if !matches!(attribute.as_str(), "schemas" | "id" | "meta") {
                    remove_projected_attribute(object, attribute);
                }
            }
        }
    }
}

fn project_attribute(
    source: &serde_json::Map<String, serde_json::Value>,
    target: &mut serde_json::Map<String, serde_json::Value>,
    attribute: &str,
) {
    if let Some(value) = source.get(attribute) {
        target.insert(attribute.to_owned(), value.clone());
        return;
    }
    if let Some((schema, child)) = attribute.rsplit_once(':') {
        if schema.starts_with("urn:ietf:params:scim:schemas:") {
            if let Some(value) = project_sub_attribute(source.get(schema), child) {
                target.insert(schema.to_owned(), value);
            }
            return;
        }
    }
    if let Some((parent, child)) = attribute.split_once('.') {
        if let Some(value) = project_sub_attribute(source.get(parent), child) {
            target.insert(parent.to_owned(), value);
        }
    }
}

fn project_sub_attribute(
    value: Option<&serde_json::Value>,
    child: &str,
) -> Option<serde_json::Value> {
    match value? {
        serde_json::Value::Array(items) => Some(serde_json::Value::Array(
            items
                .iter()
                .filter_map(|item| {
                    item.get(child)
                        .map(|child_value| serde_json::json!({ child: child_value }))
                })
                .collect(),
        )),
        serde_json::Value::Object(object) => object
            .get(child)
            .map(|child_value| serde_json::json!({ child: child_value })),
        _ => None,
    }
}

fn remove_projected_attribute(
    object: &mut serde_json::Map<String, serde_json::Value>,
    attribute: &str,
) {
    if object.remove(attribute).is_some() {
        return;
    }
    if let Some((schema, child)) = attribute.rsplit_once(':') {
        if schema.starts_with("urn:ietf:params:scim:schemas:") {
            remove_sub_attribute(object.get_mut(schema), child);
            return;
        }
    }
    if let Some((parent, child)) = attribute.split_once('.') {
        remove_sub_attribute(object.get_mut(parent), child);
    }
}

fn remove_sub_attribute(value: Option<&mut serde_json::Value>, child: &str) {
    let Some(value) = value else {
        return;
    };
    match value {
        serde_json::Value::Array(items) => {
            for item in items {
                remove_child_path(item, child);
            }
        }
        serde_json::Value::Object(_) => remove_child_path(value, child),
        _ => {}
    }
}

fn remove_child_path(value: &mut serde_json::Value, child: &str) {
    let Some(object) = value.as_object_mut() else {
        return;
    };
    if let Some((parent, nested)) = child.split_once('.') {
        remove_sub_attribute(object.get_mut(parent), nested);
    } else {
        object.remove(child);
    }
}

pub(super) fn parse_attribute_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

pub(super) fn validate_if_match(
    request: &ApiRequest,
    current_version: Option<&str>,
) -> Result<(), ScimError> {
    let Some(value) = request.headers().get(header::IF_MATCH) else {
        return Ok(());
    };
    let Ok(value) = value.to_str() else {
        return Err(ScimError::precondition_failed("Invalid If-Match header"));
    };
    if value == "*" || current_version == Some(value) {
        Ok(())
    } else {
        Err(ScimError::precondition_failed(
            "Resource version does not match",
        ))
    }
}

pub(super) fn query_param(request: &ApiRequest, name: &str) -> Option<String> {
    request.uri().query()?.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        (key == name).then(|| percent_decode_component(value))
    })
}

pub(super) fn query_usize(request: &ApiRequest, name: &str) -> Result<Option<usize>, ScimError> {
    let Some(value) = query_param(request, name) else {
        return Ok(None);
    };
    let parsed = value.parse::<usize>().map_err(|_| {
        ScimError::bad_request(format!("{name} must be a positive integer"))
            .with_scim_type("invalidValue")
    })?;
    if name == "startIndex" && parsed == 0 {
        return Err(
            ScimError::bad_request("startIndex must be greater than or equal to 1")
                .with_scim_type("invalidValue"),
        );
    }
    Ok(Some(parsed))
}

pub(super) fn bounded_result_count(count: Option<usize>, total_results: usize) -> usize {
    count
        .unwrap_or(total_results)
        .min(metadata::SCIM_FILTER_MAX_RESULTS)
}

pub(super) fn parse_search_request(request: &ApiRequest) -> Result<SearchRequest, ScimError> {
    let search: SearchRequest = serde_json::from_slice(request.body()).map_err(|error| {
        ScimError::bad_request(format!("invalid JSON request body: {error}"))
            .with_scim_type("invalidValue")
    })?;
    validate_optional_start_index(search.start_index)?;
    validate_sort_order(search.sort_order.as_deref())?;
    Ok(search)
}

pub(super) fn sort_user_resources(
    resources: &mut [crate::resources::ScimUserResource],
    sort_by: &str,
    sort_order: Option<&str>,
) -> Result<(), ScimError> {
    validate_sort_order(sort_order)?;
    match sort_by {
        "id" => resources.sort_by(|left, right| left.id.cmp(&right.id)),
        "userName" => resources.sort_by(|left, right| left.user_name.cmp(&right.user_name)),
        "displayName" => {
            resources.sort_by(|left, right| left.display_name.cmp(&right.display_name))
        }
        "externalId" => resources.sort_by(|left, right| left.external_id.cmp(&right.external_id)),
        _ => {
            return Err(ScimError::bad_request(format!(
                r#"Sorting by "{sort_by}" is not supported"#
            ))
            .with_scim_type("invalidPath"));
        }
    }
    if matches!(sort_order, Some(order) if order.eq_ignore_ascii_case("descending")) {
        resources.reverse();
    }
    Ok(())
}

pub(super) fn apply_user_sort(
    resources: &mut [ScimUserResource],
    sort_by: Option<&str>,
    sort_order: Option<&str>,
) -> Result<(), ScimError> {
    validate_sort_order(sort_order)?;
    match sort_by {
        Some(sort_by) => sort_user_resources(resources, sort_by, sort_order),
        None => Ok(()),
    }
}

pub(super) fn sort_group_resources(
    resources: &mut [ScimGroupResource],
    sort_by: &str,
    sort_order: Option<&str>,
) -> Result<(), ScimError> {
    validate_sort_order(sort_order)?;
    match sort_by {
        "id" => resources.sort_by(|left, right| left.id.cmp(&right.id)),
        "displayName" => {
            resources.sort_by(|left, right| left.display_name.cmp(&right.display_name))
        }
        "externalId" => resources.sort_by(|left, right| left.external_id.cmp(&right.external_id)),
        _ => {
            return Err(ScimError::bad_request(format!(
                r#"Sorting by "{sort_by}" is not supported"#
            ))
            .with_scim_type("invalidPath"));
        }
    }
    if matches!(sort_order, Some(order) if order.eq_ignore_ascii_case("descending")) {
        resources.reverse();
    }
    Ok(())
}

pub(super) fn validate_sort_order(sort_order: Option<&str>) -> Result<(), ScimError> {
    match sort_order {
        None => Ok(()),
        Some(order) if order.eq_ignore_ascii_case("ascending") => Ok(()),
        Some(order) if order.eq_ignore_ascii_case("descending") => Ok(()),
        Some(_) => Err(
            ScimError::bad_request("sortOrder must be ascending or descending")
                .with_scim_type("invalidValue"),
        ),
    }
}

fn validate_optional_start_index(start_index: Option<usize>) -> Result<(), ScimError> {
    if start_index == Some(0) {
        Err(
            ScimError::bad_request("startIndex must be greater than or equal to 1")
                .with_scim_type("invalidValue"),
        )
    } else {
        Ok(())
    }
}

pub(super) fn sort_json_resources(
    resources: &mut [serde_json::Value],
    sort_by: &str,
    sort_order: Option<&str>,
) -> Result<(), ScimError> {
    match sort_by {
        "id" | "userName" | "displayName" | "externalId" => {
            resources.sort_by(|left, right| {
                json_sort_value(left, sort_by).cmp(&json_sort_value(right, sort_by))
            });
        }
        _ => {
            return Err(ScimError::bad_request(format!(
                r#"Sorting by "{sort_by}" is not supported"#
            ))
            .with_scim_type("invalidPath"));
        }
    }
    if matches!(sort_order, Some(order) if order.eq_ignore_ascii_case("descending")) {
        resources.reverse();
    }
    Ok(())
}

fn json_sort_value(resource: &serde_json::Value, field: &str) -> String {
    resource
        .get(field)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

pub(super) fn percent_decode_component(value: &str) -> String {
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

pub(super) fn json<T: Serialize>(
    status: StatusCode,
    body: &T,
) -> Result<ApiResponse, OpenAuthError> {
    let body = serde_json::to_vec(body).map_err(|error| OpenAuthError::Api(error.to_string()))?;
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .map_err(|error| OpenAuthError::Api(error.to_string()))
}

pub(super) fn json_error(
    status: StatusCode,
    code: &str,
    message: &str,
) -> Result<ApiResponse, OpenAuthError> {
    json(
        status,
        &serde_json::json!({
            "code": code,
            "message": message,
        }),
    )
}

pub(super) fn hook_error(error: ScimHookError) -> Result<ApiResponse, OpenAuthError> {
    json_error(error.status, &error.code, &error.message)
}

pub(super) fn default_provider_matches(
    provider: &DefaultScimProvider,
    provider_id: &str,
    organization_id: Option<&str>,
    base_token: &str,
) -> bool {
    provider.provider_id == provider_id
        && provider.organization_id.as_deref() == organization_id
        && plain_token_matches(&provider.scim_token, base_token)
}

pub(super) async fn provider_matches(
    provider: &ScimProviderRecord,
    storage: &ScimTokenStorage,
    base_token: &str,
    secret: &str,
) -> Result<bool, OpenAuthError> {
    token_matches(&provider.scim_token, storage, base_token, secret).await
}

pub(super) async fn token_matches(
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

pub(super) fn plain_token_matches(stored: &str, candidate: &str) -> bool {
    stored.len() == candidate.len() && stored.as_bytes().ct_eq(candidate.as_bytes()).into()
}

pub(super) fn team_from_record(record: DbRecord) -> Result<ScimTeamRecord, OpenAuthError> {
    Ok(ScimTeamRecord {
        id: required_string(&record, "id")?.to_owned(),
        name: required_string(&record, "name")?.to_owned(),
        created_at: required_timestamp(&record, "created_at")?,
        updated_at: optional_timestamp(&record, "updated_at")?,
    })
}

pub(super) fn validate_scim_user_identity(
    user_name: &str,
    emails: &[ScimEmail],
) -> Result<String, ScimError> {
    crate::validation::validate_scim_user_identity(user_name, emails)
}

pub(super) fn validate_emails(emails: &[ScimEmail]) -> Result<(), ScimError> {
    crate::validation::validate_emails(emails)
}

pub(super) fn validate_multivalued_primary_attributes(
    attributes: &std::collections::BTreeMap<String, serde_json::Value>,
) -> Result<(), ScimError> {
    for attribute in [
        "phoneNumbers",
        "ims",
        "photos",
        "addresses",
        "entitlements",
        "roles",
    ] {
        let Some(values) = attributes
            .get(attribute)
            .and_then(serde_json::Value::as_array)
        else {
            continue;
        };
        let primary_count = values
            .iter()
            .filter(|value| {
                value
                    .get("primary")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false)
            })
            .count();
        if primary_count > 1 {
            return Err(ScimError::bad_request(format!(
                "Only one {attribute} value can be primary"
            ))
            .with_scim_type("invalidValue"));
        }
    }
    Ok(())
}

pub(super) fn is_valid_email(value: &str) -> bool {
    crate::validation::is_valid_email(value)
}

pub(super) async fn update_account_id(
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

pub(super) fn account_from_record(record: DbRecord) -> Result<Account, OpenAuthError> {
    Ok(Account {
        id: required_string(&record, "id")?.to_owned(),
        provider_id: required_string(&record, "provider_id")?.to_owned(),
        account_id: required_string(&record, "account_id")?.to_owned(),
        user_id: required_string(&record, "user_id")?.to_owned(),
        access_token: optional_string(&record, "access_token")?,
        refresh_token: optional_string(&record, "refresh_token")?,
        id_token: optional_string(&record, "id_token")?,
        access_token_expires_at: optional_timestamp(&record, "access_token_expires_at")?,
        refresh_token_expires_at: optional_timestamp(&record, "refresh_token_expires_at")?,
        scope: optional_string(&record, "scope")?,
        password: optional_string(&record, "password")?,
        created_at: required_timestamp(&record, "created_at")?,
        updated_at: required_timestamp(&record, "updated_at")?,
    })
}

pub(super) fn user_from_record(record: DbRecord) -> Result<User, OpenAuthError> {
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

pub(super) fn required_string<'a>(
    record: &'a DbRecord,
    field: &str,
) -> Result<&'a str, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(value),
        Some(_) => Err(OpenAuthError::Adapter(format!(
            "user field `{field}` must be string"
        ))),
        None => Err(OpenAuthError::Adapter(format!("user is missing `{field}`"))),
    }
}

pub(super) fn required_bool(record: &DbRecord, field: &str) -> Result<bool, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Boolean(value)) => Ok(*value),
        Some(_) => Err(OpenAuthError::Adapter(format!(
            "user field `{field}` must be boolean"
        ))),
        None => Err(OpenAuthError::Adapter(format!("user is missing `{field}`"))),
    }
}

pub(super) fn required_timestamp(
    record: &DbRecord,
    field: &str,
) -> Result<OffsetDateTime, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Timestamp(value)) => Ok(*value),
        Some(_) => Err(OpenAuthError::Adapter(format!(
            "user field `{field}` must be timestamp"
        ))),
        None => Err(OpenAuthError::Adapter(format!("user is missing `{field}`"))),
    }
}

pub(super) fn optional_string(
    record: &DbRecord,
    field: &str,
) -> Result<Option<String>, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(Some(value.to_owned())),
        Some(DbValue::Null) | None => Ok(None),
        Some(_) => Err(OpenAuthError::Adapter(format!(
            "user field `{field}` must be string or null"
        ))),
    }
}

pub(super) fn optional_timestamp(
    record: &DbRecord,
    field: &str,
) -> Result<Option<OffsetDateTime>, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Timestamp(value)) => Ok(Some(*value)),
        Some(DbValue::Null) | None => Ok(None),
        Some(_) => Err(OpenAuthError::Adapter(format!(
            "user field `{field}` must be timestamp or null"
        ))),
    }
}

pub(super) fn optional_json(
    record: &DbRecord,
    field: &str,
) -> Result<Option<serde_json::Value>, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Json(value)) => Ok(Some(value.clone())),
        Some(DbValue::String(value)) => serde_json::from_str(value)
            .map(Some)
            .map_err(|error| OpenAuthError::Adapter(error.to_string())),
        Some(DbValue::Null) | None => Ok(None),
        Some(_) => Err(OpenAuthError::Adapter(format!(
            "user field `{field}` must be json, string, or null"
        ))),
    }
}
