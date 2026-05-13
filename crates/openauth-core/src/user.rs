//! Database-backed user and credential account helpers.

use time::OffsetDateTime;

use crate::crypto::random::generate_random_string;
use crate::db::{
    Account, Create, DbAdapter, DbRecord, DbValue, Delete, DeleteMany, FindMany, FindOne,
    JoinOption, Update, User, Where,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateOAuthAccountInput {
    pub id: Option<String>,
    pub provider_id: String,
    pub account_id: String,
    pub user_id: String,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub access_token_expires_at: Option<OffsetDateTime>,
    pub refresh_token_expires_at: Option<OffsetDateTime>,
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpdateAccountInput {
    pub access_token: Option<Option<String>>,
    pub refresh_token: Option<Option<String>>,
    pub id_token: Option<Option<String>>,
    pub access_token_expires_at: Option<Option<OffsetDateTime>>,
    pub refresh_token_expires_at: Option<Option<OffsetDateTime>>,
    pub scope: Option<Option<String>>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthUserLookup {
    pub user: User,
    pub accounts: Vec<Account>,
    pub linked_account: Option<Account>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateOAuthUserResult {
    pub user: User,
    pub account: Account,
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

    pub async fn link_account(
        &self,
        input: CreateOAuthAccountInput,
    ) -> Result<Account, OpenAuthError> {
        let now = OffsetDateTime::now_utc();
        let id = input
            .id
            .unwrap_or_else(|| generate_random_string(DEFAULT_ID_LENGTH));

        let record = self
            .adapter
            .create(
                Create::new(ACCOUNT_MODEL)
                    .data("id", DbValue::String(id))
                    .data("provider_id", DbValue::String(input.provider_id))
                    .data("account_id", DbValue::String(input.account_id))
                    .data("user_id", DbValue::String(input.user_id))
                    .data("access_token", optional_string(input.access_token))
                    .data("refresh_token", optional_string(input.refresh_token))
                    .data("id_token", optional_string(input.id_token))
                    .data(
                        "access_token_expires_at",
                        optional_timestamp(input.access_token_expires_at),
                    )
                    .data(
                        "refresh_token_expires_at",
                        optional_timestamp(input.refresh_token_expires_at),
                    )
                    .data("scope", optional_string(input.scope))
                    .data("password", DbValue::Null)
                    .data("created_at", DbValue::Timestamp(now))
                    .data("updated_at", DbValue::Timestamp(now))
                    .select(ACCOUNT_FIELDS)
                    .force_allow_id(),
            )
            .await?;

        account_from_record(record)
    }

    pub async fn create_oauth_user(
        &self,
        user: CreateUserInput,
        mut account: CreateOAuthAccountInput,
    ) -> Result<CreateOAuthUserResult, OpenAuthError> {
        let user = self.create_user(user).await?;
        account.user_id = user.id.clone();
        let account = self.link_account(account).await?;
        Ok(CreateOAuthUserResult { user, account })
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
        let Some(mut record) = self
            .adapter
            .find_one(
                FindOne::new(USER_MODEL)
                    .where_clause(Where::new("email", DbValue::String(normalize_email(email))))
                    .select(USER_FIELDS)
                    .join(ACCOUNT_MODEL, JoinOption::enabled()),
            )
            .await?
        else {
            return Ok(None);
        };

        let joined_accounts = record.shift_remove(ACCOUNT_MODEL);
        let user = user_from_record(record)?;
        let accounts = match joined_accounts {
            Some(DbValue::RecordArray(accounts)) => accounts
                .into_iter()
                .map(account_from_record)
                .collect::<Result<Vec<_>, _>>()?,
            Some(DbValue::Null) => Vec::new(),
            None => self.list_accounts_for_user(&user.id).await?,
            Some(_) => {
                return Err(OpenAuthError::Adapter(
                    "joined account result must be an array".to_owned(),
                ));
            }
        };
        Ok(Some(UserWithAccounts { user, accounts }))
    }

    pub async fn find_oauth_user(
        &self,
        email: &str,
        account_id: &str,
        provider_id: &str,
    ) -> Result<Option<OAuthUserLookup>, OpenAuthError> {
        let linked_account = self
            .find_account_by_provider_account(account_id, provider_id)
            .await?;
        let user = if let Some(account) = &linked_account {
            self.find_user_by_id(&account.user_id).await?
        } else {
            self.find_user_by_email(email).await?
        };
        let Some(user) = user else {
            return Ok(None);
        };
        let accounts = self.list_accounts_for_user(&user.id).await?;
        Ok(Some(OAuthUserLookup {
            user,
            accounts,
            linked_account,
        }))
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

    pub async fn find_account_by_provider_account(
        &self,
        account_id: &str,
        provider_id: &str,
    ) -> Result<Option<Account>, OpenAuthError> {
        let record = self
            .adapter
            .find_one(
                FindOne::new(ACCOUNT_MODEL)
                    .where_clause(Where::new(
                        "account_id",
                        DbValue::String(account_id.to_owned()),
                    ))
                    .where_clause(Where::new(
                        "provider_id",
                        DbValue::String(provider_id.to_owned()),
                    ))
                    .select(ACCOUNT_FIELDS),
            )
            .await?;

        record.map(account_from_record).transpose()
    }

    pub async fn update_account(
        &self,
        account_id: &str,
        input: UpdateAccountInput,
    ) -> Result<Option<Account>, OpenAuthError> {
        let mut query = Update::new(ACCOUNT_MODEL)
            .where_clause(Where::new("id", DbValue::String(account_id.to_owned())))
            .data("updated_at", DbValue::Timestamp(OffsetDateTime::now_utc()));
        if let Some(value) = input.access_token {
            query = query.data("access_token", optional_string(value));
        }
        if let Some(value) = input.refresh_token {
            query = query.data("refresh_token", optional_string(value));
        }
        if let Some(value) = input.id_token {
            query = query.data("id_token", optional_string(value));
        }
        if let Some(value) = input.access_token_expires_at {
            query = query.data("access_token_expires_at", optional_timestamp(value));
        }
        if let Some(value) = input.refresh_token_expires_at {
            query = query.data("refresh_token_expires_at", optional_timestamp(value));
        }
        if let Some(value) = input.scope {
            query = query.data("scope", optional_string(value));
        }

        self.adapter
            .update(query)
            .await?
            .map(account_from_record)
            .transpose()
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

    pub async fn update_user_email_verified(
        &self,
        user_id: &str,
        email_verified: bool,
    ) -> Result<Option<User>, OpenAuthError> {
        self.adapter
            .update(
                Update::new(USER_MODEL)
                    .where_clause(Where::new("id", DbValue::String(user_id.to_owned())))
                    .data("email_verified", DbValue::Boolean(email_verified))
                    .data("updated_at", DbValue::Timestamp(OffsetDateTime::now_utc())),
            )
            .await?
            .map(user_from_record)
            .transpose()
    }

    pub async fn update_user_email(
        &self,
        user_id: &str,
        email: &str,
        email_verified: bool,
    ) -> Result<Option<User>, OpenAuthError> {
        self.adapter
            .update(
                Update::new(USER_MODEL)
                    .where_clause(Where::new("id", DbValue::String(user_id.to_owned())))
                    .data("email", DbValue::String(normalize_email(email)))
                    .data("email_verified", DbValue::Boolean(email_verified))
                    .data("updated_at", DbValue::Timestamp(OffsetDateTime::now_utc())),
            )
            .await?
            .map(user_from_record)
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

    pub async fn delete_user_accounts(&self, user_id: &str) -> Result<u64, OpenAuthError> {
        self.adapter
            .delete_many(
                DeleteMany::new(ACCOUNT_MODEL)
                    .where_clause(Where::new("user_id", DbValue::String(user_id.to_owned()))),
            )
            .await
    }

    pub async fn delete_user(&self, user_id: &str) -> Result<(), OpenAuthError> {
        self.adapter
            .delete(
                Delete::new(USER_MODEL)
                    .where_clause(Where::new("id", DbValue::String(user_id.to_owned()))),
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

fn optional_timestamp(value: Option<OffsetDateTime>) -> DbValue {
    value.map(DbValue::Timestamp).unwrap_or(DbValue::Null)
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
