//! Database-backed user and credential account helpers.

mod input;
mod record;

use time::OffsetDateTime;

use crate::crypto::random::generate_random_string;
use crate::db::{
    Account, Create, DbAdapter, DbValue, Delete, DeleteMany, FindMany, FindOne, JoinOption, Update,
    User, Where,
};
use crate::error::OpenAuthError;
pub use input::{
    CreateCredentialAccountInput, CreateOAuthAccountInput, CreateUserInput, UpdateAccountInput,
    UpdateUserInput,
};
use record::{
    account_from_record, user_from_record, ACCOUNT_FIELDS, USER_FIELDS, USER_FIELDS_WITH_USERNAME,
};

pub(super) const USER_MODEL: &str = "user";
pub(super) const ACCOUNT_MODEL: &str = "account";
const CREDENTIAL_PROVIDER_ID: &str = "credential";
const DEFAULT_ID_LENGTH: usize = 32;

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

        let include_username_fields = input.username.is_some() || input.display_username.is_some();
        let mut query = Create::new(USER_MODEL)
            .data("id", DbValue::String(id))
            .data("name", DbValue::String(input.name))
            .data("email", DbValue::String(normalize_email(&input.email)))
            .data("email_verified", DbValue::Boolean(input.email_verified))
            .data("image", optional_string(input.image))
            .data("created_at", DbValue::Timestamp(now))
            .data("updated_at", DbValue::Timestamp(now))
            .force_allow_id();
        if include_username_fields {
            query = query
                .data("username", optional_string(input.username))
                .data("display_username", optional_string(input.display_username))
                .select(USER_FIELDS_WITH_USERNAME);
        } else {
            query = query.select(USER_FIELDS);
        }

        for (field, value) in input.additional_fields {
            query = query.data(field, value);
        }

        let record = self.adapter.create(query).await?;

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

    pub async fn find_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<User>, OpenAuthError> {
        let record = self
            .adapter
            .find_one(
                FindOne::new(USER_MODEL)
                    .where_clause(Where::new("username", DbValue::String(username.to_owned())))
                    .select(USER_FIELDS_WITH_USERNAME),
            )
            .await?;

        record.map(user_from_record).transpose()
    }

    pub async fn find_user_by_username_with_accounts(
        &self,
        username: &str,
    ) -> Result<Option<UserWithAccounts>, OpenAuthError> {
        let Some(user) = self.find_user_by_username(username).await? else {
            return Ok(None);
        };
        let accounts = self.list_accounts_for_user(&user.id).await?;
        Ok(Some(UserWithAccounts { user, accounts }))
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
        if let Some(username) = input.username {
            query = query.data("username", optional_string(username));
        }
        if let Some(display_username) = input.display_username {
            query = query.data("display_username", optional_string(display_username));
        }
        for (field, value) in input.fields {
            query = query.data(field, value);
        }
        for (field, value) in input.additional_fields {
            query = query.data(field, value);
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
