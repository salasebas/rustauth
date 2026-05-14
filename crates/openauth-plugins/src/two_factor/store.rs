use openauth_core::crypto::random::generate_random_string;
use openauth_core::db::{
    Create, DbAdapter, DbRecord, DbValue, Delete, FindOne, Update, User, Where,
};
use openauth_core::error::OpenAuthError;
use openauth_core::user::DbUserStore;

const USER_MODEL: &str = "user";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TwoFactorRecord {
    pub id: String,
    pub user_id: String,
    pub secret: String,
    pub backup_codes: String,
    pub verified: Option<bool>,
}

#[derive(Clone, Copy)]
pub struct TwoFactorStore<'a> {
    adapter: &'a dyn DbAdapter,
    table: &'a str,
}

impl<'a> TwoFactorStore<'a> {
    pub fn new(adapter: &'a dyn DbAdapter, table: &'a str) -> Self {
        Self { adapter, table }
    }

    pub async fn find_by_user(
        &self,
        user_id: &str,
    ) -> Result<Option<TwoFactorRecord>, OpenAuthError> {
        self.adapter
            .find_one(
                FindOne::new(self.table)
                    .where_clause(Where::new("user_id", DbValue::String(user_id.to_owned()))),
            )
            .await?
            .map(record_from_db)
            .transpose()
    }

    pub async fn upsert_for_user(
        &self,
        user_id: &str,
        secret: String,
        backup_codes: String,
        verified: bool,
    ) -> Result<TwoFactorRecord, OpenAuthError> {
        if let Some(existing) = self.find_by_user(user_id).await? {
            let Some(record) = self
                .adapter
                .update(
                    Update::new(self.table)
                        .where_clause(Where::new("id", DbValue::String(existing.id)))
                        .data("secret", DbValue::String(secret))
                        .data("backup_codes", DbValue::String(backup_codes))
                        .data("verified", DbValue::Boolean(verified)),
                )
                .await?
            else {
                return Err(OpenAuthError::Adapter(
                    "two factor update failed".to_owned(),
                ));
            };
            return record_from_db(record);
        }

        let record = self
            .adapter
            .create(
                Create::new(self.table)
                    .data("id", DbValue::String(generate_random_string(32)))
                    .data("user_id", DbValue::String(user_id.to_owned()))
                    .data("secret", DbValue::String(secret))
                    .data("backup_codes", DbValue::String(backup_codes))
                    .data("verified", DbValue::Boolean(verified))
                    .force_allow_id(),
            )
            .await?;
        record_from_db(record)
    }

    pub async fn mark_verified(&self, id: &str) -> Result<(), OpenAuthError> {
        self.adapter
            .update(
                Update::new(self.table)
                    .where_clause(Where::new("id", DbValue::String(id.to_owned())))
                    .data("verified", DbValue::Boolean(true)),
            )
            .await?;
        Ok(())
    }

    pub async fn update_backup_codes_if_current(
        &self,
        id: &str,
        current: &str,
        next: String,
    ) -> Result<bool, OpenAuthError> {
        let updated = self
            .adapter
            .update(
                Update::new(self.table)
                    .where_clause(Where::new("id", DbValue::String(id.to_owned())))
                    .where_clause(Where::new(
                        "backup_codes",
                        DbValue::String(current.to_owned()),
                    ))
                    .data("backup_codes", DbValue::String(next)),
            )
            .await?;
        Ok(updated.is_some())
    }

    pub async fn delete_for_user(&self, user_id: &str) -> Result<(), OpenAuthError> {
        self.adapter
            .delete(
                Delete::new(self.table)
                    .where_clause(Where::new("user_id", DbValue::String(user_id.to_owned()))),
            )
            .await
    }
}

pub async fn find_user_raw(
    adapter: &dyn DbAdapter,
    user_id: &str,
) -> Result<Option<DbRecord>, OpenAuthError> {
    adapter
        .find_one(
            FindOne::new(USER_MODEL)
                .where_clause(Where::new("id", DbValue::String(user_id.to_owned()))),
        )
        .await
}

pub async fn user_two_factor_enabled(
    adapter: &dyn DbAdapter,
    user_id: &str,
) -> Result<bool, OpenAuthError> {
    Ok(find_user_raw(adapter, user_id)
        .await?
        .and_then(|record| match record.get("two_factor_enabled") {
            Some(DbValue::Boolean(value)) => Some(*value),
            _ => None,
        })
        .unwrap_or(false))
}

pub async fn update_user_two_factor_enabled(
    adapter: &dyn DbAdapter,
    user_id: &str,
    enabled: bool,
) -> Result<User, OpenAuthError> {
    adapter
        .update(
            Update::new(USER_MODEL)
                .where_clause(Where::new("id", DbValue::String(user_id.to_owned())))
                .data("two_factor_enabled", DbValue::Boolean(enabled)),
        )
        .await?;
    DbUserStore::new(adapter)
        .find_user_by_id(user_id)
        .await?
        .ok_or_else(|| OpenAuthError::Adapter("user not found".to_owned()))
}

pub async fn credential_password_hash(
    adapter: &dyn DbAdapter,
    user_id: &str,
) -> Result<Option<String>, OpenAuthError> {
    Ok(DbUserStore::new(adapter)
        .find_credential_account(user_id)
        .await?
        .and_then(|account| account.password))
}

fn record_from_db(record: DbRecord) -> Result<TwoFactorRecord, OpenAuthError> {
    Ok(TwoFactorRecord {
        id: required_string(&record, "id")?.to_owned(),
        user_id: required_string(&record, "user_id")?.to_owned(),
        secret: required_string(&record, "secret")?.to_owned(),
        backup_codes: required_string(&record, "backup_codes")?.to_owned(),
        verified: optional_bool(&record, "verified")?,
    })
}

fn required_string<'a>(record: &'a DbRecord, field: &str) -> Result<&'a str, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(value),
        Some(_) => Err(OpenAuthError::Adapter(format!(
            "two factor field `{field}` must be string"
        ))),
        None => Err(OpenAuthError::Adapter(format!(
            "two factor record is missing `{field}`"
        ))),
    }
}

fn optional_bool(record: &DbRecord, field: &str) -> Result<Option<bool>, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Boolean(value)) => Ok(Some(*value)),
        Some(DbValue::Null) | None => Ok(None),
        Some(_) => Err(OpenAuthError::Adapter(format!(
            "two factor field `{field}` must be boolean"
        ))),
    }
}
