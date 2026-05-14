use std::collections::HashMap;

use openauth_core::db::{
    run_transaction_without_native_support, Account, AdapterFuture, Count, Create, DbAdapter,
    DbRecord, DbValue, Delete, DeleteMany, FindMany, FindOne, TransactionCallback, Update,
    UpdateMany, User, Where, WhereOperator,
};
use openauth_core::error::OpenAuthError;
use openauth_core::user::{CreateCredentialAccountInput, CreateUserInput, DbUserStore};
use time::OffsetDateTime;
use tokio::sync::Mutex;

#[derive(Default)]
struct InMemoryUserAdapter {
    users: Mutex<HashMap<String, DbRecord>>,
    accounts: Mutex<HashMap<String, DbRecord>>,
    creates: Mutex<Vec<Create>>,
    find_many: Mutex<Vec<FindMany>>,
}

impl InMemoryUserAdapter {
    async fn insert_user(&self, user: User) {
        self.users
            .lock()
            .await
            .insert(user.email.clone(), user_record(user));
    }

    async fn insert_account(&self, account: Account) {
        self.accounts
            .lock()
            .await
            .insert(account.id.clone(), account_record(account));
    }
}

impl DbAdapter for InMemoryUserAdapter {
    fn id(&self) -> &str {
        "memory-user"
    }

    fn create<'a>(&'a self, query: Create) -> AdapterFuture<'a, DbRecord> {
        Box::pin(async move {
            self.creates.lock().await.push(query.clone());
            match query.model.as_str() {
                "user" => {
                    let email = string_field(&query.data, "email")?.to_owned();
                    self.users.lock().await.insert(email, query.data.clone());
                    Ok(query.data)
                }
                "account" => {
                    let id = string_field(&query.data, "id")?.to_owned();
                    self.accounts.lock().await.insert(id, query.data.clone());
                    Ok(query.data)
                }
                model => Err(OpenAuthError::Adapter(format!(
                    "unexpected create model `{model}`"
                ))),
            }
        })
    }

    fn find_one<'a>(&'a self, query: FindOne) -> AdapterFuture<'a, Option<DbRecord>> {
        Box::pin(async move {
            match query.model.as_str() {
                "user" => {
                    let email = string_filter(&query.where_clauses, "email")?;
                    Ok(self.users.lock().await.get(email).cloned())
                }
                "account" => {
                    let user_id = string_filter(&query.where_clauses, "user_id")?;
                    let provider_id = string_filter(&query.where_clauses, "provider_id")?;
                    Ok(self
                        .accounts
                        .lock()
                        .await
                        .values()
                        .find(|record| {
                            matches!(record.get("user_id"), Some(DbValue::String(value)) if value == user_id)
                                && matches!(record.get("provider_id"), Some(DbValue::String(value)) if value == provider_id)
                        })
                        .cloned())
                }
                model => Err(OpenAuthError::Adapter(format!(
                    "unexpected find_one model `{model}`"
                ))),
            }
        })
    }

    fn find_many<'a>(&'a self, query: FindMany) -> AdapterFuture<'a, Vec<DbRecord>> {
        Box::pin(async move {
            self.find_many.lock().await.push(query.clone());
            match query.model.as_str() {
                "account" => {
                    let user_id = string_filter(&query.where_clauses, "user_id")?;
                    Ok(self
                        .accounts
                        .lock()
                        .await
                        .values()
                        .filter(|record| {
                            matches!(record.get("user_id"), Some(DbValue::String(value)) if value == user_id)
                        })
                        .cloned()
                        .collect())
                }
                model => Err(OpenAuthError::Adapter(format!(
                    "unexpected find_many model `{model}`"
                ))),
            }
        })
    }

    fn count<'a>(&'a self, _query: Count) -> AdapterFuture<'a, u64> {
        Box::pin(async { Ok(0) })
    }

    fn update<'a>(&'a self, _query: Update) -> AdapterFuture<'a, Option<DbRecord>> {
        Box::pin(async { Ok(None) })
    }

    fn update_many<'a>(&'a self, _query: UpdateMany) -> AdapterFuture<'a, u64> {
        Box::pin(async { Ok(0) })
    }

    fn delete<'a>(&'a self, _query: Delete) -> AdapterFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn delete_many<'a>(&'a self, _query: DeleteMany) -> AdapterFuture<'a, u64> {
        Box::pin(async { Ok(0) })
    }

    fn transaction<'a>(&'a self, callback: TransactionCallback<'a>) -> AdapterFuture<'a, ()> {
        run_transaction_without_native_support(self, callback)
    }
}

#[tokio::test]
async fn db_user_store_creates_user_with_lowercase_email() -> Result<(), OpenAuthError> {
    let adapter = InMemoryUserAdapter::default();
    let store = DbUserStore::new(&adapter);

    let user = store
        .create_user(
            CreateUserInput::new("Ada Lovelace", "ADA@EXAMPLE.COM")
                .id("user_1")
                .image("https://example.com/ada.png"),
        )
        .await?;

    assert_eq!(user.id, "user_1");
    assert_eq!(user.email, "ada@example.com");
    assert!(!user.email_verified);
    assert_eq!(user.image.as_deref(), Some("https://example.com/ada.png"));

    let creates = adapter.creates.lock().await;
    let Some(create) = creates.first() else {
        return Err(OpenAuthError::Adapter("missing user create".to_owned()));
    };
    assert_eq!(create.model, "user");
    assert!(create.force_allow_id);
    assert_eq!(
        create.data.get("email"),
        Some(&DbValue::String("ada@example.com".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn db_user_store_creates_user_with_username_fields() -> Result<(), OpenAuthError> {
    let adapter = InMemoryUserAdapter::default();
    let store = DbUserStore::new(&adapter);

    let user = store
        .create_user(
            CreateUserInput::new("Ada Lovelace", "ada@example.com")
                .id("user_1")
                .username("ada_lovelace")
                .display_username("Ada Lovelace"),
        )
        .await?;

    assert_eq!(user.username.as_deref(), Some("ada_lovelace"));
    assert_eq!(user.display_username.as_deref(), Some("Ada Lovelace"));
    let creates = adapter.creates.lock().await;
    let create = creates
        .first()
        .ok_or_else(|| OpenAuthError::Adapter("missing user create".to_owned()))?;
    assert_eq!(
        create.data.get("username"),
        Some(&DbValue::String("ada_lovelace".to_owned()))
    );
    assert_eq!(
        create.data.get("display_username"),
        Some(&DbValue::String("Ada Lovelace".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn db_user_store_creates_credential_account() -> Result<(), OpenAuthError> {
    let adapter = InMemoryUserAdapter::default();
    let store = DbUserStore::new(&adapter);

    let account = store
        .create_credential_account(
            CreateCredentialAccountInput::new("user_1", "salt:hash").id("account_1"),
        )
        .await?;

    assert_eq!(account.id, "account_1");
    assert_eq!(account.user_id, "user_1");
    assert_eq!(account.account_id, "user_1");
    assert_eq!(account.provider_id, "credential");
    assert_eq!(account.password.as_deref(), Some("salt:hash"));
    Ok(())
}

#[tokio::test]
async fn db_user_store_finds_user_by_email_with_accounts() -> Result<(), OpenAuthError> {
    let adapter = InMemoryUserAdapter::default();
    let now = OffsetDateTime::now_utc();
    adapter
        .insert_user(User {
            id: "user_1".to_owned(),
            name: "Ada".to_owned(),
            email: "ada@example.com".to_owned(),
            email_verified: true,
            image: None,
            username: None,
            display_username: None,
            created_at: now,
            updated_at: now,
        })
        .await;
    adapter
        .insert_account(Account {
            id: "account_1".to_owned(),
            provider_id: "credential".to_owned(),
            account_id: "user_1".to_owned(),
            user_id: "user_1".to_owned(),
            access_token: None,
            refresh_token: None,
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: None,
            password: Some("salt:hash".to_owned()),
            created_at: now,
            updated_at: now,
        })
        .await;

    let found = DbUserStore::new(&adapter)
        .find_user_by_email_with_accounts("ADA@EXAMPLE.COM")
        .await?;

    let Some(found) = found else {
        return Err(OpenAuthError::Adapter("missing user".to_owned()));
    };
    assert_eq!(found.user.id, "user_1");
    assert_eq!(found.accounts.len(), 1);
    assert_eq!(found.accounts[0].provider_id, "credential");
    Ok(())
}

#[tokio::test]
async fn db_user_store_finds_credential_account_for_user() -> Result<(), OpenAuthError> {
    let adapter = InMemoryUserAdapter::default();
    let now = OffsetDateTime::now_utc();
    adapter
        .insert_account(Account {
            id: "account_1".to_owned(),
            provider_id: "credential".to_owned(),
            account_id: "user_1".to_owned(),
            user_id: "user_1".to_owned(),
            access_token: None,
            refresh_token: None,
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: None,
            password: Some("salt:hash".to_owned()),
            created_at: now,
            updated_at: now,
        })
        .await;

    let account = DbUserStore::new(&adapter)
        .find_credential_account("user_1")
        .await?;

    let Some(account) = account else {
        return Err(OpenAuthError::Adapter("missing account".to_owned()));
    };
    assert_eq!(account.provider_id, "credential");
    assert_eq!(account.user_id, "user_1");
    Ok(())
}

fn user_record(user: User) -> DbRecord {
    let mut record = DbRecord::new();
    record.insert("id".to_owned(), DbValue::String(user.id));
    record.insert("name".to_owned(), DbValue::String(user.name));
    record.insert("email".to_owned(), DbValue::String(user.email));
    record.insert(
        "email_verified".to_owned(),
        DbValue::Boolean(user.email_verified),
    );
    record.insert(
        "image".to_owned(),
        user.image.map(DbValue::String).unwrap_or(DbValue::Null),
    );
    record.insert("created_at".to_owned(), DbValue::Timestamp(user.created_at));
    record.insert("updated_at".to_owned(), DbValue::Timestamp(user.updated_at));
    record
}

fn account_record(account: Account) -> DbRecord {
    let mut record = DbRecord::new();
    record.insert("id".to_owned(), DbValue::String(account.id));
    record.insert(
        "provider_id".to_owned(),
        DbValue::String(account.provider_id),
    );
    record.insert("account_id".to_owned(), DbValue::String(account.account_id));
    record.insert("user_id".to_owned(), DbValue::String(account.user_id));
    record.insert(
        "access_token".to_owned(),
        account
            .access_token
            .map(DbValue::String)
            .unwrap_or(DbValue::Null),
    );
    record.insert(
        "refresh_token".to_owned(),
        account
            .refresh_token
            .map(DbValue::String)
            .unwrap_or(DbValue::Null),
    );
    record.insert(
        "id_token".to_owned(),
        account
            .id_token
            .map(DbValue::String)
            .unwrap_or(DbValue::Null),
    );
    record.insert(
        "access_token_expires_at".to_owned(),
        account
            .access_token_expires_at
            .map(DbValue::Timestamp)
            .unwrap_or(DbValue::Null),
    );
    record.insert(
        "refresh_token_expires_at".to_owned(),
        account
            .refresh_token_expires_at
            .map(DbValue::Timestamp)
            .unwrap_or(DbValue::Null),
    );
    record.insert(
        "scope".to_owned(),
        account.scope.map(DbValue::String).unwrap_or(DbValue::Null),
    );
    record.insert(
        "password".to_owned(),
        account
            .password
            .map(DbValue::String)
            .unwrap_or(DbValue::Null),
    );
    record.insert(
        "created_at".to_owned(),
        DbValue::Timestamp(account.created_at),
    );
    record.insert(
        "updated_at".to_owned(),
        DbValue::Timestamp(account.updated_at),
    );
    record
}

fn string_filter<'a>(where_clauses: &'a [Where], field: &str) -> Result<&'a str, OpenAuthError> {
    where_clauses
        .iter()
        .find_map(|where_clause| {
            match (
                where_clause.field.as_str(),
                where_clause.operator,
                &where_clause.value,
            ) {
                (candidate, WhereOperator::Eq, DbValue::String(value)) if candidate == field => {
                    Some(value.as_str())
                }
                _ => None,
            }
        })
        .ok_or_else(|| OpenAuthError::Adapter(format!("missing {field} filter")))
}

fn string_field<'a>(record: &'a DbRecord, field: &str) -> Result<&'a str, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(value),
        _ => Err(OpenAuthError::Adapter(format!(
            "missing string field `{field}`"
        ))),
    }
}
