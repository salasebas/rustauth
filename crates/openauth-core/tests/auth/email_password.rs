use std::collections::HashMap;

use openauth_core::auth::email_password::{
    AuthFlowErrorCode, EmailPasswordAuth, EmailPasswordConfig, SignInInput, SignUpInput,
};
use openauth_core::db::{
    run_transaction_without_native_support, Account, AdapterFuture, Count, Create, DbAdapter,
    DbRecord, DbValue, Delete, DeleteMany, FindMany, FindOne, TransactionCallback, Update,
    UpdateMany, User, Where, WhereOperator,
};
use openauth_core::error::OpenAuthError;
use time::OffsetDateTime;
use tokio::sync::Mutex;

#[derive(Default)]
struct AuthAdapter {
    users: Mutex<HashMap<String, DbRecord>>,
    accounts: Mutex<HashMap<String, DbRecord>>,
    sessions: Mutex<HashMap<String, DbRecord>>,
}

impl AuthAdapter {
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

impl DbAdapter for AuthAdapter {
    fn id(&self) -> &str {
        "auth-memory"
    }

    fn create<'a>(&'a self, query: Create) -> AdapterFuture<'a, DbRecord> {
        Box::pin(async move {
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
                "session" => {
                    let token = string_field(&query.data, "token")?.to_owned();
                    self.sessions.lock().await.insert(token, query.data.clone());
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
                _ => Ok(None),
            }
        })
    }

    fn find_many<'a>(&'a self, query: FindMany) -> AdapterFuture<'a, Vec<DbRecord>> {
        Box::pin(async move {
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
                _ => Ok(Vec::new()),
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
async fn sign_up_creates_user_credential_account_and_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = AuthAdapter::default();
    let auth = EmailPasswordAuth::new(&adapter, config(), fake_hash_password, fake_verify_password);

    let result = auth
        .sign_up(
            SignUpInput::new("Ada", "ADA@EXAMPLE.COM", "secret123")
                .image("https://example.com/ada.png")
                .ip_address("192.0.2.1")
                .user_agent("test-agent"),
        )
        .await?;

    assert_eq!(result.user.email, "ada@example.com");
    assert_eq!(result.session.user_id, result.user.id);
    assert_eq!(result.session.ip_address.as_deref(), Some("192.0.2.1"));
    assert_eq!(result.session.user_agent.as_deref(), Some("test-agent"));
    assert_eq!(adapter.users.lock().await.len(), 1);
    assert_eq!(adapter.accounts.lock().await.len(), 1);
    assert_eq!(adapter.sessions.lock().await.len(), 1);
    Ok(())
}

#[tokio::test]
async fn sign_up_rejects_duplicate_email() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = AuthAdapter::default();
    let now = OffsetDateTime::now_utc();
    adapter
        .insert_user(user("user_1", "Ada", "ada@example.com", true, now))
        .await;

    let error =
        EmailPasswordAuth::new(&adapter, config(), fake_hash_password, fake_verify_password)
            .sign_up(SignUpInput::new("Ada", "ADA@example.com", "secret123"))
            .await
            .err();

    assert_eq!(
        error.as_ref().map(|error| error.code()),
        Some(AuthFlowErrorCode::UserAlreadyExists)
    );
    assert!(adapter.sessions.lock().await.is_empty());
    Ok(())
}

#[tokio::test]
async fn sign_in_creates_session_for_valid_credentials() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = AuthAdapter::default();
    let now = OffsetDateTime::now_utc();
    adapter
        .insert_user(user("user_1", "Ada", "ada@example.com", true, now))
        .await;
    adapter
        .insert_account(credential_account(
            "account_1",
            "user_1",
            "hash:secret123",
            now,
        ))
        .await;

    let result =
        EmailPasswordAuth::new(&adapter, config(), fake_hash_password, fake_verify_password)
            .sign_in(SignInInput::new("ADA@example.com", "secret123"))
            .await?;

    assert_eq!(result.user.id, "user_1");
    assert_eq!(result.session.user_id, "user_1");
    assert_eq!(adapter.sessions.lock().await.len(), 1);
    Ok(())
}

#[tokio::test]
async fn sign_in_rejects_invalid_credentials_without_creating_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = AuthAdapter::default();
    let now = OffsetDateTime::now_utc();
    adapter
        .insert_user(user("user_1", "Ada", "ada@example.com", true, now))
        .await;
    adapter
        .insert_account(credential_account(
            "account_1",
            "user_1",
            "hash:secret123",
            now,
        ))
        .await;

    let error =
        EmailPasswordAuth::new(&adapter, config(), fake_hash_password, fake_verify_password)
            .sign_in(SignInInput::new("ada@example.com", "wrong"))
            .await
            .err();

    assert_eq!(
        error.as_ref().map(|error| error.code()),
        Some(AuthFlowErrorCode::InvalidEmailOrPassword)
    );
    assert!(adapter.sessions.lock().await.is_empty());
    Ok(())
}

#[tokio::test]
async fn sign_in_rejects_unverified_email_when_required() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = AuthAdapter::default();
    let now = OffsetDateTime::now_utc();
    adapter
        .insert_user(user("user_1", "Ada", "ada@example.com", false, now))
        .await;
    adapter
        .insert_account(credential_account(
            "account_1",
            "user_1",
            "hash:secret123",
            now,
        ))
        .await;

    let error = EmailPasswordAuth::new(
        &adapter,
        EmailPasswordConfig {
            require_email_verification: true,
            ..config()
        },
        fake_hash_password,
        fake_verify_password,
    )
    .sign_in(SignInInput::new("ada@example.com", "secret123"))
    .await
    .err();

    assert_eq!(
        error.as_ref().map(|error| error.code()),
        Some(AuthFlowErrorCode::EmailNotVerified)
    );
    assert!(adapter.sessions.lock().await.is_empty());
    Ok(())
}

fn config() -> EmailPasswordConfig {
    EmailPasswordConfig {
        session_expires_in: 60 * 60 * 24 * 7,
        dont_remember_session_expires_in: 60 * 60 * 24,
        min_password_length: 8,
        max_password_length: 128,
        require_email_verification: false,
    }
}

fn fake_hash_password(password: &str) -> Result<String, OpenAuthError> {
    Ok(format!("hash:{password}"))
}

fn fake_verify_password(hash: &str, password: &str) -> Result<bool, OpenAuthError> {
    Ok(hash == format!("hash:{password}"))
}

fn user(id: &str, name: &str, email: &str, email_verified: bool, now: OffsetDateTime) -> User {
    User {
        id: id.to_owned(),
        name: name.to_owned(),
        email: email.to_owned(),
        email_verified,
        image: None,
        created_at: now,
        updated_at: now,
    }
}

fn credential_account(id: &str, user_id: &str, password: &str, now: OffsetDateTime) -> Account {
    Account {
        id: id.to_owned(),
        provider_id: "credential".to_owned(),
        account_id: user_id.to_owned(),
        user_id: user_id.to_owned(),
        access_token: None,
        refresh_token: None,
        id_token: None,
        access_token_expires_at: None,
        refresh_token_expires_at: None,
        scope: None,
        password: Some(password.to_owned()),
        created_at: now,
        updated_at: now,
    }
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
    record.insert("access_token".to_owned(), DbValue::Null);
    record.insert("refresh_token".to_owned(), DbValue::Null);
    record.insert("id_token".to_owned(), DbValue::Null);
    record.insert("access_token_expires_at".to_owned(), DbValue::Null);
    record.insert("refresh_token_expires_at".to_owned(), DbValue::Null);
    record.insert("scope".to_owned(), DbValue::Null);
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
