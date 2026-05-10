//! Database-backed user and credential account helpers.

use time::OffsetDateTime;

use crate::crypto::random::generate_random_string;
use crate::db::{
    Account, Create, DbAdapter, DbRecord, DbValue, Delete, FindMany, FindOne, Update, User, Where,
};
use crate::error::OpenAuthError;

const USER_MODEL: &str = "user";
const ACCOUNT_MODEL: &str = "account";
const CREDENTIAL_PROVIDER_ID: &str = "credential";
const DEFAULT_ID_LENGTH: usize = 32;

const USER_FIELDS: [&str; 7] = [
    "id",
    "name",
    "email",
    "email_verified",
    "image",
    "created_at",
    "updated_at",
];

const ACCOUNT_FIELDS: [&str; 13] = [
    "id",
    "provider_id",
    "account_id",
    "user_id",
    "access_token",
    "refresh_token",
    "id_token",
    "access_token_expires_at",
    "refresh_token_expires_at",
    "scope",
    "password",
    "created_at",
    "updated_at",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateUserInput {
    pub id: Option<String>,
    pub name: String,
    pub email: String,
    pub email_verified: bool,
    pub image: Option<String>,
}

impl CreateUserInput {
    pub fn new(name: impl Into<String>, email: impl Into<String>) -> Self {
        Self {
            id: None,
            name: name.into(),
            email: email.into(),
            email_verified: false,
            image: None,
        }
    }

    #[must_use]
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    #[must_use]
    pub fn email_verified(mut self, email_verified: bool) -> Self {
        self.email_verified = email_verified;
        self
    }

    #[must_use]
    pub fn image(mut self, image: impl Into<String>) -> Self {
        self.image = Some(image.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateCredentialAccountInput {
    pub id: Option<String>,
    pub user_id: String,
    pub password_hash: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpdateUserInput {
    pub name: Option<String>,
    pub image: Option<Option<String>>,
}

impl UpdateUserInput {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    #[must_use]
    pub fn image(mut self, image: Option<String>) -> Self {
        self.image = Some(image);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.name.is_none() && self.image.is_none()
    }
}

impl CreateCredentialAccountInput {
    pub fn new(user_id: impl Into<String>, password_hash: impl Into<String>) -> Self {
        Self {
            id: None,
            user_id: user_id.into(),
            password_hash: password_hash.into(),
        }
    }

    #[must_use]
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserWithAccounts {
    pub user: User,
    pub accounts: Vec<Account>,
}

#[derive(Clone, Copy)]
pub struct DbUserStore<'a> {
    adapter: &'a dyn DbAdapter,
}

impl<'a> DbUserStore<'a> {
    pub fn new(adapter: &'a dyn DbAdapter) -> Self {
        Self { adapter }
    }

    pub async fn create_user(&self, input: CreateUserInput) -> Result<User, OpenAuthError> {
        let now = OffsetDateTime::now_utc();
        let id = input
            .id
            .unwrap_or_else(|| generate_random_string(DEFAULT_ID_LENGTH));

        let record = self
            .adapter
            .create(
                Create::new(USER_MODEL)
                    .data("id", DbValue::String(id))
                    .data("name", DbValue::String(input.name))
                    .data("email", DbValue::String(normalize_email(&input.email)))
                    .data("email_verified", DbValue::Boolean(input.email_verified))
                    .data("image", optional_string(input.image))
                    .data("created_at", DbValue::Timestamp(now))
                    .data("updated_at", DbValue::Timestamp(now))
                    .select(USER_FIELDS)
                    .force_allow_id(),
            )
            .await?;

        user_from_record(record)
    }

    pub async fn create_credential_account(
        &self,
        input: CreateCredentialAccountInput,
    ) -> Result<Account, OpenAuthError> {
        let now = OffsetDateTime::now_utc();
        let id = input
            .id
            .unwrap_or_else(|| generate_random_string(DEFAULT_ID_LENGTH));
        let account_id = input.user_id.clone();

        let record = self
            .adapter
            .create(
                Create::new(ACCOUNT_MODEL)
                    .data("id", DbValue::String(id))
                    .data(
                        "provider_id",
                        DbValue::String(CREDENTIAL_PROVIDER_ID.to_owned()),
                    )
                    .data("account_id", DbValue::String(account_id))
                    .data("user_id", DbValue::String(input.user_id))
                    .data("access_token", DbValue::Null)
                    .data("refresh_token", DbValue::Null)
                    .data("id_token", DbValue::Null)
                    .data("access_token_expires_at", DbValue::Null)
                    .data("refresh_token_expires_at", DbValue::Null)
                    .data("scope", DbValue::Null)
                    .data("password", DbValue::String(input.password_hash))
                    .data("created_at", DbValue::Timestamp(now))
                    .data("updated_at", DbValue::Timestamp(now))
                    .select(ACCOUNT_FIELDS)
                    .force_allow_id(),
            )
            .await?;

        account_from_record(record)
    }

    pub async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, OpenAuthError> {
        let record = self
            .adapter
            .find_one(
                FindOne::new(USER_MODEL)
                    .where_clause(Where::new("email", DbValue::String(normalize_email(email))))
                    .select(USER_FIELDS),
            )
            .await?;

        record.map(user_from_record).transpose()
    }

    pub async fn find_user_by_id(&self, user_id: &str) -> Result<Option<User>, OpenAuthError> {
        let record = self
            .adapter
            .find_one(
                FindOne::new(USER_MODEL)
                    .where_clause(Where::new("id", DbValue::String(user_id.to_owned())))
                    .select(USER_FIELDS),
            )
            .await?;

        record.map(user_from_record).transpose()
    }

    pub async fn find_user_by_email_with_accounts(
        &self,
        email: &str,
    ) -> Result<Option<UserWithAccounts>, OpenAuthError> {
        let Some(user) = self.find_user_by_email(email).await? else {
            return Ok(None);
        };
        let accounts = self.list_accounts_for_user(&user.id).await?;
        Ok(Some(UserWithAccounts { user, accounts }))
    }

    pub async fn list_accounts_for_user(
        &self,
        user_id: &str,
    ) -> Result<Vec<Account>, OpenAuthError> {
        self.adapter
            .find_many(
                FindMany::new(ACCOUNT_MODEL)
                    .where_clause(Where::new("user_id", DbValue::String(user_id.to_owned())))
                    .select(ACCOUNT_FIELDS),
            )
            .await?
            .into_iter()
            .map(account_from_record)
            .collect()
    }

    pub async fn find_credential_account(
        &self,
        user_id: &str,
    ) -> Result<Option<Account>, OpenAuthError> {
        let record = self
            .adapter
            .find_one(
                FindOne::new(ACCOUNT_MODEL)
                    .where_clause(Where::new("user_id", DbValue::String(user_id.to_owned())))
                    .where_clause(Where::new(
                        "provider_id",
                        DbValue::String(CREDENTIAL_PROVIDER_ID.to_owned()),
                    ))
                    .select(ACCOUNT_FIELDS),
            )
            .await?;

        record.map(account_from_record).transpose()
    }

    pub async fn update_user(
        &self,
        user_id: &str,
        input: UpdateUserInput,
    ) -> Result<Option<User>, OpenAuthError> {
        if input.is_empty() {
            return self.find_user_by_id(user_id).await;
        }
        let mut query = Update::new(USER_MODEL)
            .where_clause(Where::new("id", DbValue::String(user_id.to_owned())))
            .data("updated_at", DbValue::Timestamp(OffsetDateTime::now_utc()));
        if let Some(name) = input.name {
            query = query.data("name", DbValue::String(name));
        }
        if let Some(image) = input.image {
            query = query.data("image", optional_string(image));
        }

        self.adapter
            .update(query)
            .await?
            .map(user_from_record)
            .transpose()
    }

    pub async fn update_credential_password(
        &self,
        user_id: &str,
        password_hash: &str,
    ) -> Result<Option<Account>, OpenAuthError> {
        self.adapter
            .update(
                Update::new(ACCOUNT_MODEL)
                    .where_clause(Where::new("user_id", DbValue::String(user_id.to_owned())))
                    .where_clause(Where::new(
                        "provider_id",
                        DbValue::String(CREDENTIAL_PROVIDER_ID.to_owned()),
                    ))
                    .data("password", DbValue::String(password_hash.to_owned()))
                    .data("updated_at", DbValue::Timestamp(OffsetDateTime::now_utc())),
            )
            .await?
            .map(account_from_record)
            .transpose()
    }

    pub async fn delete_account(&self, account_id: &str) -> Result<(), OpenAuthError> {
        self.adapter
            .delete(
                Delete::new(ACCOUNT_MODEL)
                    .where_clause(Where::new("id", DbValue::String(account_id.to_owned()))),
            )
            .await
    }
}

fn normalize_email(email: &str) -> String {
    email.to_lowercase()
}

fn optional_string(value: Option<String>) -> DbValue {
    value.map(DbValue::String).unwrap_or(DbValue::Null)
}

fn user_from_record(record: DbRecord) -> Result<User, OpenAuthError> {
    Ok(User {
        id: required_string(&record, "id")?.to_owned(),
        name: required_string(&record, "name")?.to_owned(),
        email: required_string(&record, "email")?.to_owned(),
        email_verified: required_bool(&record, "email_verified")?,
        image: optional_string_field(&record, "image")?,
        created_at: required_timestamp(&record, "created_at")?,
        updated_at: required_timestamp(&record, "updated_at")?,
    })
}

fn account_from_record(record: DbRecord) -> Result<Account, OpenAuthError> {
    Ok(Account {
        id: required_string(&record, "id")?.to_owned(),
        provider_id: required_string(&record, "provider_id")?.to_owned(),
        account_id: required_string(&record, "account_id")?.to_owned(),
        user_id: required_string(&record, "user_id")?.to_owned(),
        access_token: optional_string_field(&record, "access_token")?,
        refresh_token: optional_string_field(&record, "refresh_token")?,
        id_token: optional_string_field(&record, "id_token")?,
        access_token_expires_at: optional_timestamp_field(&record, "access_token_expires_at")?,
        refresh_token_expires_at: optional_timestamp_field(&record, "refresh_token_expires_at")?,
        scope: optional_string_field(&record, "scope")?,
        password: optional_string_field(&record, "password")?,
        created_at: required_timestamp(&record, "created_at")?,
        updated_at: required_timestamp(&record, "updated_at")?,
    })
}

fn required_string<'a>(record: &'a DbRecord, field: &str) -> Result<&'a str, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(value),
        Some(_) => Err(invalid_field(field, "string")),
        None => Err(missing_field(field)),
    }
}

fn required_bool(record: &DbRecord, field: &str) -> Result<bool, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Boolean(value)) => Ok(*value),
        Some(_) => Err(invalid_field(field, "boolean")),
        None => Err(missing_field(field)),
    }
}

fn required_timestamp(record: &DbRecord, field: &str) -> Result<OffsetDateTime, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Timestamp(value)) => Ok(*value),
        Some(_) => Err(invalid_field(field, "timestamp")),
        None => Err(missing_field(field)),
    }
}

fn optional_string_field(record: &DbRecord, field: &str) -> Result<Option<String>, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(Some(value.to_owned())),
        Some(DbValue::Null) | None => Ok(None),
        Some(_) => Err(invalid_field(field, "string or null")),
    }
}

fn optional_timestamp_field(
    record: &DbRecord,
    field: &str,
) -> Result<Option<OffsetDateTime>, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Timestamp(value)) => Ok(Some(*value)),
        Some(DbValue::Null) | None => Ok(None),
        Some(_) => Err(invalid_field(field, "timestamp or null")),
    }
}

fn missing_field(field: &str) -> OpenAuthError {
    OpenAuthError::Adapter(format!("record is missing `{field}`"))
}

fn invalid_field(field: &str, expected: &str) -> OpenAuthError {
    OpenAuthError::Adapter(format!("record field `{field}` must be {expected}"))
}
