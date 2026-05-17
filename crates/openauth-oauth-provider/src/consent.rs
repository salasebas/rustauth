use openauth_core::db::{DbAdapter, DbRecord, DbValue, Delete, FindOne, Update, Where};
use openauth_core::error::OpenAuthError;

use crate::models::OAuthConsent;
use crate::schema::OAUTH_CONSENT_MODEL;
use crate::utils::{create_query, now, random_id, string, string_array, timestamp};

/// Input for creating or updating an OAuth consent grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentGrantInput {
    pub client_id: String,
    pub user_id: Option<String>,
    pub reference_id: Option<String>,
    pub scopes: Vec<String>,
}

pub fn has_granted_scopes(consent: &OAuthConsent, requested: &[String]) -> bool {
    requested
        .iter()
        .all(|scope| consent.scopes.iter().any(|granted| granted == scope))
}

pub async fn find_consent(
    adapter: &dyn DbAdapter,
    user_id: &str,
    client_id: &str,
) -> Result<Option<OAuthConsent>, OpenAuthError> {
    adapter
        .find_one(consent_by_user_client_query(user_id, client_id))
        .await?
        .map(consent_from_record)
        .transpose()
}

pub async fn upsert_consent(
    adapter: &dyn DbAdapter,
    input: ConsentGrantInput,
) -> Result<OAuthConsent, OpenAuthError> {
    let existing = match input.user_id.as_deref() {
        Some(user_id) => find_consent(adapter, user_id, &input.client_id).await?,
        None => None,
    };
    let timestamp = now();
    if let Some(existing) = existing {
        let mut record = DbRecord::new();
        optional_string(&mut record, "reference_id", input.reference_id);
        record.insert("scopes".to_owned(), DbValue::StringArray(input.scopes));
        record.insert("updated_at".to_owned(), DbValue::Timestamp(timestamp));
        let id = existing.id;
        return adapter
            .update(apply_data(
                Update::new(OAUTH_CONSENT_MODEL).where_clause(string_where("id", &id)),
                record,
            ))
            .await?
            .map(consent_from_record)
            .transpose()?
            .ok_or_else(|| OpenAuthError::Adapter("oauth consent disappeared".to_owned()));
    }

    let consent = OAuthConsent {
        id: random_id("oauth_consent"),
        client_id: input.client_id,
        user_id: input.user_id,
        reference_id: input.reference_id,
        scopes: input.scopes,
        created_at: timestamp,
        updated_at: timestamp,
    };
    let record = adapter
        .create(create_query(
            OAUTH_CONSENT_MODEL,
            consent_to_record(&consent),
        ))
        .await?;
    consent_from_record(record)
}

pub async fn delete_consent(
    adapter: &dyn DbAdapter,
    user_id: &str,
    client_id: &str,
) -> Result<(), OpenAuthError> {
    adapter
        .delete(
            Delete::new(OAUTH_CONSENT_MODEL)
                .where_clause(string_where("user_id", user_id))
                .where_clause(string_where("client_id", client_id)),
        )
        .await?;
    Ok(())
}

fn consent_by_user_client_query(user_id: &str, client_id: &str) -> FindOne {
    FindOne::new(OAUTH_CONSENT_MODEL)
        .where_clause(string_where("user_id", user_id))
        .where_clause(string_where("client_id", client_id))
}

fn consent_to_record(consent: &OAuthConsent) -> DbRecord {
    let mut record = DbRecord::new();
    record.insert("id".to_owned(), DbValue::String(consent.id.clone()));
    record.insert(
        "client_id".to_owned(),
        DbValue::String(consent.client_id.clone()),
    );
    optional_string(&mut record, "user_id", consent.user_id.clone());
    optional_string(&mut record, "reference_id", consent.reference_id.clone());
    record.insert(
        "scopes".to_owned(),
        DbValue::StringArray(consent.scopes.clone()),
    );
    record.insert(
        "created_at".to_owned(),
        DbValue::Timestamp(consent.created_at),
    );
    record.insert(
        "updated_at".to_owned(),
        DbValue::Timestamp(consent.updated_at),
    );
    record
}

pub(crate) fn consent_from_record(record: DbRecord) -> Result<OAuthConsent, OpenAuthError> {
    Ok(OAuthConsent {
        id: required_string(&record, "id")?,
        client_id: required_string(&record, "client_id")?,
        user_id: string(&record, "user_id"),
        reference_id: string(&record, "reference_id"),
        scopes: string_array(&record, "scopes").unwrap_or_default(),
        created_at: required_timestamp(&record, "created_at")?,
        updated_at: required_timestamp(&record, "updated_at")?,
    })
}

fn apply_data(mut query: Update, data: DbRecord) -> Update {
    for (field, value) in data {
        query = query.data(field, value);
    }
    query
}

fn optional_string(record: &mut DbRecord, field: &str, value: Option<String>) {
    record.insert(
        field.to_owned(),
        value.map(DbValue::String).unwrap_or(DbValue::Null),
    );
}

fn required_string(record: &DbRecord, field: &str) -> Result<String, OpenAuthError> {
    string(record, field)
        .ok_or_else(|| OpenAuthError::Adapter(format!("oauth consent missing {field}")))
}

fn required_timestamp(
    record: &DbRecord,
    field: &str,
) -> Result<time::OffsetDateTime, OpenAuthError> {
    timestamp(record, field)
        .ok_or_else(|| OpenAuthError::Adapter(format!("oauth consent missing {field}")))
}

fn string_where(field: &str, value: &str) -> Where {
    Where::new(field, DbValue::String(value.to_owned()))
}
