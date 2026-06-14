use rustauth_core::db::{DbAdapter, DbRecord, DbValue, FindOne, Update, User, Where};
use rustauth_core::error::RustAuthError;
use serde_json::{json, Map, Value};
use time::OffsetDateTime;

use crate::errors::StripeErrorCode;
use crate::metadata::CustomerMetadata;
use crate::options::{
    CustomerCreateContext, CustomerCreateInput, CustomerCreateParamsInput,
    OrganizationCustomerCreateInput, OrganizationCustomerCreateParamsInput, StripeOptions,
};
use crate::stripe_api::{StripeApiError, StripeClient};
use crate::utils::escape_stripe_search_value;

#[derive(Debug)]
pub enum CustomerEnsureError {
    Stripe(StripeApiError),
    OrganizationNotFound,
    Other(RustAuthError),
}

impl From<RustAuthError> for CustomerEnsureError {
    fn from(error: RustAuthError) -> Self {
        Self::Other(error)
    }
}

pub async fn ensure_user_customer(
    adapter: &dyn DbAdapter,
    options: &StripeOptions,
    hook_context: CustomerCreateContext,
    user: &User,
    request_metadata: Option<Value>,
) -> Result<String, CustomerEnsureError> {
    ensure_user_customer_from_user(adapter, options, hook_context, user, request_metadata).await
}

pub async fn ensure_user_customer_from_record(
    adapter: &dyn DbAdapter,
    options: &StripeOptions,
    hook_context: CustomerCreateContext,
    user: &DbRecord,
) -> Result<Option<String>, RustAuthError> {
    if record_string(user, "stripe_customer_id").is_some() {
        return Ok(record_string(user, "stripe_customer_id").map(str::to_owned));
    }
    let Some(user) = user_from_record(user) else {
        return Ok(None);
    };
    ensure_user_customer_from_user(adapter, options, hook_context, &user, None)
        .await
        .map(Some)
        .map_err(customer_ensure_error_to_rustauth)
}

fn customer_ensure_error_to_rustauth(error: CustomerEnsureError) -> RustAuthError {
    match error {
        CustomerEnsureError::Stripe(stripe_error) => RustAuthError::Api(stripe_error.to_string()),
        CustomerEnsureError::OrganizationNotFound => {
            RustAuthError::Api(StripeErrorCode::OrganizationNotFound.message().to_owned())
        }
        CustomerEnsureError::Other(error) => error,
    }
}

pub async fn sync_user_customer_email_from_record(
    stripe_client: &StripeClient,
    user: &DbRecord,
) -> Result<(), RustAuthError> {
    let Some(customer_id) = record_string(user, "stripe_customer_id") else {
        return Ok(());
    };
    let Some(email) = record_string(user, "email") else {
        return Ok(());
    };
    let customer = stripe_client
        .retrieve_customer(customer_id)
        .await
        .map_err(|error| RustAuthError::Api(error.to_string()))?;
    if customer
        .get("deleted")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(());
    }
    if customer.get("email").and_then(Value::as_str) != Some(email) {
        stripe_client
            .update_customer(customer_id, json!({ "email": email }))
            .await
            .map_err(|error| RustAuthError::Api(error.to_string()))?;
    }
    Ok(())
}

pub async fn sync_organization_customer_name_from_record(
    stripe_client: &StripeClient,
    organization: &DbRecord,
) -> Result<(), RustAuthError> {
    let Some(customer_id) = record_string(organization, "stripe_customer_id") else {
        return Ok(());
    };
    let Some(name) = record_string(organization, "name") else {
        return Ok(());
    };
    stripe_client
        .update_customer(customer_id, json!({ "name": name }))
        .await
        .map_err(|error| RustAuthError::Api(error.to_string()))?;
    Ok(())
}

pub async fn organization_customer_id(
    adapter: &dyn DbAdapter,
    organization_id: &str,
) -> Result<Option<String>, RustAuthError> {
    Ok(adapter
        .find_one(FindOne::new("organization").where_clause(Where::new(
            "id",
            DbValue::String(organization_id.to_owned()),
        )))
        .await?
        .and_then(|record| record_string(&record, "stripe_customer_id").map(str::to_owned)))
}

pub async fn ensure_organization_customer(
    adapter: &dyn DbAdapter,
    options: &StripeOptions,
    hook_context: CustomerCreateContext,
    organization_id: &str,
    request_metadata: Option<Value>,
) -> Result<String, CustomerEnsureError> {
    let Some(organization) = adapter
        .find_one(FindOne::new("organization").where_clause(Where::new(
            "id",
            DbValue::String(organization_id.to_owned()),
        )))
        .await
        .map_err(CustomerEnsureError::Other)?
    else {
        return Err(CustomerEnsureError::OrganizationNotFound);
    };
    if let Some(customer_id) = record_string(&organization, "stripe_customer_id") {
        return Ok(customer_id.to_owned());
    }
    if let Some(customer) = find_existing_organization_customer(
        &options.stripe_client,
        &hook_context.logger,
        organization_id,
    )
    .await?
    {
        let customer_id = customer_id(&customer)?;
        persist_organization_customer_id(adapter, organization_id, &customer_id).await?;
        call_organization_customer_create_hook(options, hook_context, organization, customer)
            .await?;
        return Ok(customer_id);
    }

    let mut extra_params = Value::Object(Map::new());
    if let Some(get_params) = options
        .organization
        .as_ref()
        .and_then(|organization| organization.get_customer_create_params.as_ref())
    {
        extra_params = get_params(
            OrganizationCustomerCreateParamsInput {
                organization: record_to_json(&organization),
            },
            hook_context.clone(),
        )
        .await?;
    }
    let customer_params =
        organization_customer_create_params(&organization, extra_params, request_metadata)?;
    let customer = options
        .stripe_client
        .create_customer(customer_params)
        .await
        .map_err(CustomerEnsureError::Stripe)?;
    let customer_id = customer_id(&customer)?;
    persist_organization_customer_id(adapter, organization_id, &customer_id).await?;
    call_organization_customer_create_hook(options, hook_context, organization, customer).await?;
    Ok(customer_id)
}

async fn ensure_user_customer_from_user(
    adapter: &dyn DbAdapter,
    options: &StripeOptions,
    hook_context: CustomerCreateContext,
    user: &User,
    request_metadata: Option<Value>,
) -> Result<String, CustomerEnsureError> {
    if let Some(customer_id) = stored_user_customer_id(adapter, &user.id).await? {
        return Ok(customer_id);
    }

    if let Some(customer) = find_existing_user_customer(
        &options.stripe_client,
        &hook_context.logger,
        &user.id,
        &user.email,
    )
    .await?
    {
        let customer_id = customer_id(&customer)?;
        persist_user_customer_id(adapter, &user.id, &customer_id).await?;
        call_user_customer_create_hook(options, hook_context, user.clone(), customer).await?;
        return Ok(customer_id);
    }

    let mut extra_params = Value::Object(Map::new());
    if let Some(get_params) = &options.get_customer_create_params {
        extra_params = get_params(
            CustomerCreateParamsInput { user: user.clone() },
            hook_context.clone(),
        )
        .await?;
    }
    let customer_params = customer_create_params(user, extra_params, request_metadata)?;
    let customer = options
        .stripe_client
        .create_customer(customer_params)
        .await
        .map_err(CustomerEnsureError::Stripe)?;
    let customer_id = customer_id(&customer)?;
    persist_user_customer_id(adapter, &user.id, &customer_id).await?;
    call_user_customer_create_hook(options, hook_context, user.clone(), customer).await?;
    Ok(customer_id)
}

async fn call_user_customer_create_hook(
    options: &StripeOptions,
    hook_context: CustomerCreateContext,
    user: User,
    stripe_customer: Value,
) -> Result<(), RustAuthError> {
    if let Some(hook) = &options.on_customer_create {
        hook(
            CustomerCreateInput {
                stripe_customer,
                user,
            },
            hook_context,
        )
        .await?;
    }
    Ok(())
}

fn customer_create_params(
    user: &User,
    extra_params: Value,
    request_metadata: Option<Value>,
) -> Result<Value, RustAuthError> {
    let mut object = match extra_params {
        Value::Null => Map::new(),
        Value::Object(object) => object,
        _ => {
            return Err(RustAuthError::Api(
                "customer create params must be a JSON object".to_owned(),
            ));
        }
    };
    let metadata = object.remove("metadata").unwrap_or(Value::Null);
    object.insert("email".to_owned(), Value::String(user.email.clone()));
    object.insert("name".to_owned(), Value::String(user.name.clone()));
    let mut customer_metadata = CustomerMetadata::user(&user.id).merge_user_metadata(metadata);
    if let Some(request_metadata) = request_metadata {
        customer_metadata = customer_metadata.merge_user_metadata(request_metadata);
    }
    object.insert("metadata".to_owned(), json!(customer_metadata.into_map()));
    Ok(Value::Object(object))
}

fn customer_id(customer: &Value) -> Result<String, RustAuthError> {
    customer
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| RustAuthError::Api(StripeErrorCode::UnableToCreateCustomer.to_string()))
        .map(str::to_owned)
}

async fn find_existing_organization_customer(
    stripe_client: &StripeClient,
    logger: &rustauth_core::env::logger::Logger,
    organization_id: &str,
) -> Result<Option<Value>, CustomerEnsureError> {
    let escaped_organization_id = escape_stripe_search_value(organization_id);
    let query = format!(
        "metadata[\"organizationId\"]:\"{escaped_organization_id}\" AND metadata[\"customerType\"]:\"organization\""
    );
    match stripe_client
        .find_customer_from_search(&query, |customer| {
            matches_organization_customer(customer, organization_id)
        })
        .await
    {
        Ok(found) => Ok(found),
        Err(error) => {
            logger.warn(
                "Stripe customers.search failed, falling back to customers.list",
                &[&error.to_string()],
            );
            stripe_client
                .find_customer(json!({}), |customer| {
                    matches_organization_customer(customer, organization_id)
                })
                .await
                .map_err(CustomerEnsureError::Stripe)
        }
    }
}

fn matches_organization_customer(customer: &Value, organization_id: &str) -> bool {
    let Some(metadata) = customer.get("metadata") else {
        return false;
    };
    metadata.get("organizationId").and_then(Value::as_str) == Some(organization_id)
        && metadata.get("customerType").and_then(Value::as_str) == Some("organization")
}

fn organization_customer_create_params(
    organization: &DbRecord,
    extra_params: Value,
    request_metadata: Option<Value>,
) -> Result<Value, RustAuthError> {
    let mut object = match extra_params {
        Value::Null => Map::new(),
        Value::Object(object) => object,
        _ => {
            return Err(RustAuthError::Api(
                "organization customer create params must be a JSON object".to_owned(),
            ));
        }
    };
    let organization_id = record_string(organization, "id")
        .ok_or_else(|| RustAuthError::Api(StripeErrorCode::OrganizationNotFound.to_string()))?;
    let organization_name = record_string(organization, "name")
        .ok_or_else(|| RustAuthError::Api(StripeErrorCode::OrganizationNotFound.to_string()))?;
    let metadata = object.remove("metadata").unwrap_or(Value::Null);
    object.insert(
        "name".to_owned(),
        Value::String(organization_name.to_owned()),
    );
    let mut customer_metadata =
        CustomerMetadata::organization(organization_id).merge_user_metadata(metadata);
    if let Some(request_metadata) = request_metadata {
        customer_metadata = customer_metadata.merge_user_metadata(request_metadata);
    }
    object.insert("metadata".to_owned(), json!(customer_metadata.into_map()));
    Ok(Value::Object(object))
}

async fn stored_user_customer_id(
    adapter: &dyn DbAdapter,
    user_id: &str,
) -> Result<Option<String>, RustAuthError> {
    Ok(adapter
        .find_one(
            FindOne::new("user")
                .where_clause(Where::new("id", DbValue::String(user_id.to_owned()))),
        )
        .await?
        .and_then(|record| record_string(&record, "stripe_customer_id").map(str::to_owned)))
}

async fn find_existing_user_customer(
    stripe_client: &StripeClient,
    logger: &rustauth_core::env::logger::Logger,
    user_id: &str,
    email: &str,
) -> Result<Option<Value>, CustomerEnsureError> {
    let escaped_email = escape_stripe_search_value(email);
    let query =
        format!("email:\"{escaped_email}\" AND -metadata[\"customerType\"]:\"organization\"");
    match stripe_client
        .find_customer_from_search(&query, |customer| matches_user_customer(customer, user_id))
        .await
    {
        Ok(found) => Ok(found),
        Err(error) => {
            logger.warn(
                "Stripe customers.search failed, falling back to customers.list",
                &[&error.to_string()],
            );
            return stripe_client
                .find_customer(json!({ "email": email }), |customer| {
                    matches_user_customer(customer, user_id)
                })
                .await
                .map_err(CustomerEnsureError::Stripe);
        }
    }
}

/// Returns true when `customer` is safe to link to `user_id`.
///
/// Skips organization customers and refuses any customer whose
/// `metadata.userId` identifies a different RustAuth user, only allowing reuse
/// of the user's own customer or a metadata-less dashboard customer.
fn matches_user_customer(customer: &Value, user_id: &str) -> bool {
    let metadata = customer.get("metadata");
    let customer_type = metadata
        .and_then(|metadata| metadata.get("customerType"))
        .and_then(Value::as_str);
    if customer_type == Some("organization") {
        return false;
    }
    !matches!(
        metadata
            .and_then(|metadata| metadata.get("userId"))
            .and_then(Value::as_str),
        Some(existing) if existing != user_id
    )
}

async fn persist_user_customer_id(
    adapter: &dyn DbAdapter,
    user_id: &str,
    customer_id: &str,
) -> Result<(), RustAuthError> {
    adapter
        .update(
            Update::new("user")
                .where_clause(Where::new("id", DbValue::String(user_id.to_owned())))
                .data(
                    "stripe_customer_id",
                    DbValue::String(customer_id.to_owned()),
                ),
        )
        .await?;
    Ok(())
}

async fn persist_organization_customer_id(
    adapter: &dyn DbAdapter,
    organization_id: &str,
    customer_id: &str,
) -> Result<(), RustAuthError> {
    adapter
        .update(
            Update::new("organization")
                .where_clause(Where::new(
                    "id",
                    DbValue::String(organization_id.to_owned()),
                ))
                .data(
                    "stripe_customer_id",
                    DbValue::String(customer_id.to_owned()),
                ),
        )
        .await?;
    Ok(())
}

async fn call_organization_customer_create_hook(
    options: &StripeOptions,
    hook_context: CustomerCreateContext,
    organization: DbRecord,
    stripe_customer: Value,
) -> Result<(), RustAuthError> {
    if let Some(hook) = options
        .organization
        .as_ref()
        .and_then(|organization| organization.on_customer_create.as_ref())
    {
        hook(
            OrganizationCustomerCreateInput {
                stripe_customer,
                organization: record_to_json(&organization),
            },
            hook_context,
        )
        .await?;
    }
    Ok(())
}

fn record_to_json(record: &DbRecord) -> Value {
    Value::Object(
        record
            .iter()
            .map(|(key, value)| (key.clone(), db_value_to_json(value)))
            .collect(),
    )
}

fn db_value_to_json(value: &DbValue) -> Value {
    match value {
        DbValue::String(value) => Value::String(value.clone()),
        DbValue::Number(value) => json!(value),
        DbValue::Boolean(value) => json!(value),
        DbValue::Timestamp(value) => Value::String(value.to_string()),
        DbValue::Json(value) => value.clone(),
        DbValue::StringArray(value) => json!(value),
        DbValue::NumberArray(value) => json!(value),
        DbValue::Record(value) => record_to_json(value),
        DbValue::RecordArray(values) => Value::Array(values.iter().map(record_to_json).collect()),
        DbValue::Null => Value::Null,
    }
}

fn record_string<'a>(record: &'a DbRecord, field: &str) -> Option<&'a str> {
    match record.get(field) {
        Some(DbValue::String(value)) => Some(value.as_str()),
        _ => None,
    }
}

fn record_bool(record: &DbRecord, field: &str) -> Option<bool> {
    match record.get(field) {
        Some(DbValue::Boolean(value)) => Some(*value),
        _ => None,
    }
}

fn record_timestamp(record: &DbRecord, field: &str) -> Option<OffsetDateTime> {
    match record.get(field) {
        Some(DbValue::Timestamp(value)) => Some(*value),
        _ => None,
    }
}

fn user_from_record(record: &DbRecord) -> Option<User> {
    Some(User {
        id: record_string(record, "id")?.to_owned(),
        name: record_string(record, "name")?.to_owned(),
        email: record_string(record, "email")?.to_owned(),
        email_verified: record_bool(record, "email_verified").unwrap_or(false),
        image: record_string(record, "image").map(str::to_owned),
        username: record_string(record, "username").map(str::to_owned),
        display_username: record_string(record, "display_username").map(str::to_owned),
        created_at: record_timestamp(record, "created_at").unwrap_or_else(OffsetDateTime::now_utc),
        updated_at: record_timestamp(record, "updated_at").unwrap_or_else(OffsetDateTime::now_utc),
    })
}
