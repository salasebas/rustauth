use openauth_core::db::{
    Account, Create, DbAdapter, DbRecord, DbValue, Delete, DeleteMany, FindMany, FindOne, Sort,
    SortDirection, Update, Where, WhereOperator,
};
use openauth_core::error::OpenAuthError;
use openauth_core::user::{CreateCredentialAccountInput, DbUserStore};
use time::{Duration, OffsetDateTime};

use super::models::{
    admin_session_from_record, admin_user_from_record, AdminSession, AdminUser, CreateUserBody,
};

const USER_MODEL: &str = "user";
const SESSION_MODEL: &str = "session";
const ACCOUNT_MODEL: &str = "account";
const USER_FIELDS: [&str; 11] = [
    "id",
    "name",
    "email",
    "email_verified",
    "image",
    "created_at",
    "updated_at",
    "role",
    "banned",
    "ban_reason",
    "ban_expires",
];
const SESSION_FIELDS: [&str; 9] = [
    "id",
    "user_id",
    "expires_at",
    "token",
    "ip_address",
    "user_agent",
    "created_at",
    "updated_at",
    "impersonated_by",
];

#[derive(Clone, Copy)]
pub struct AdminStore<'a> {
    adapter: &'a dyn DbAdapter,
}

pub struct ListUsers {
    pub users: Vec<AdminUser>,
    pub total: u64,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Default)]
pub struct ListUsersQuery {
    pub search_value: Option<String>,
    pub search_field: Option<String>,
    pub search_operator: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub sort_by: Option<String>,
    pub sort_direction: Option<String>,
    pub filter_field: Option<String>,
    pub filter_value: Option<DbValue>,
    pub filter_operator: Option<String>,
}

impl<'a> AdminStore<'a> {
    pub fn new(adapter: &'a dyn DbAdapter) -> Self {
        Self { adapter }
    }

    pub async fn create_user(
        &self,
        body: CreateUserBody,
        role: String,
        password_hash: Option<String>,
    ) -> Result<AdminUser, OpenAuthError> {
        let now = OffsetDateTime::now_utc();
        let id = openauth_core::crypto::random::generate_random_string(32);
        let mut query = Create::new(USER_MODEL)
            .data("id", DbValue::String(id))
            .data("name", DbValue::String(body.name))
            .data("email", DbValue::String(body.email.to_lowercase()))
            .data("email_verified", DbValue::Boolean(false))
            .data("image", DbValue::Null)
            .data("created_at", DbValue::Timestamp(now))
            .data("updated_at", DbValue::Timestamp(now))
            .data("role", DbValue::String(role))
            .data("banned", DbValue::Boolean(false))
            .data("ban_reason", DbValue::Null)
            .data("ban_expires", DbValue::Null)
            .select(USER_FIELDS)
            .force_allow_id();
        for (field, value) in body.data {
            query = query.data(field, json_to_db_value(value));
        }
        let record = self.adapter.create(query).await?;
        let user = admin_user_from_record(record)?;
        if let Some(password_hash) = password_hash {
            DbUserStore::new(self.adapter)
                .create_credential_account(
                    CreateCredentialAccountInput::new(user.id.clone(), password_hash)
                        .id(openauth_core::crypto::random::generate_random_string(32)),
                )
                .await?;
        }
        Ok(user)
    }

    pub async fn find_user_by_id(&self, user_id: &str) -> Result<Option<AdminUser>, OpenAuthError> {
        self.adapter
            .find_one(
                FindOne::new(USER_MODEL)
                    .where_clause(Where::new("id", DbValue::String(user_id.to_owned())))
                    .select(USER_FIELDS),
            )
            .await?
            .map(admin_user_from_record)
            .transpose()
    }

    pub async fn find_user_by_email(
        &self,
        email: &str,
    ) -> Result<Option<AdminUser>, OpenAuthError> {
        self.adapter
            .find_one(
                FindOne::new(USER_MODEL)
                    .where_clause(Where::new("email", DbValue::String(email.to_lowercase())))
                    .select(USER_FIELDS),
            )
            .await?
            .map(admin_user_from_record)
            .transpose()
    }

    pub async fn list_users(&self, input: ListUsersQuery) -> Result<ListUsers, OpenAuthError> {
        let clauses = list_where_clauses(&input);
        let mut query = FindMany::new(USER_MODEL).select(USER_FIELDS);
        for clause in &clauses {
            query = query.where_clause(clause.clone());
        }
        if let Some(limit) = input.limit {
            query = query.limit(limit);
        }
        if let Some(offset) = input.offset {
            query = query.offset(offset);
        }
        if let Some(sort_by) = input.sort_by {
            query = query.sort_by(Sort::new(
                sort_by,
                match input.sort_direction.as_deref() {
                    Some("desc") => SortDirection::Desc,
                    _ => SortDirection::Asc,
                },
            ));
        }
        let users = self
            .adapter
            .find_many(query)
            .await?
            .into_iter()
            .map(admin_user_from_record)
            .collect::<Result<Vec<_>, _>>()?;
        let mut count = openauth_core::db::Count::new(USER_MODEL);
        for clause in clauses {
            count = count.where_clause(clause);
        }
        let total = self.adapter.count(count).await?;
        Ok(ListUsers {
            users,
            total,
            limit: input.limit,
            offset: input.offset,
        })
    }

    pub async fn update_role(
        &self,
        user_id: &str,
        role: String,
    ) -> Result<Option<AdminUser>, OpenAuthError> {
        self.update_user_fields(
            user_id,
            DbRecord::from([("role".to_owned(), DbValue::String(role))]),
        )
        .await
    }

    pub async fn update_user_fields(
        &self,
        user_id: &str,
        mut data: DbRecord,
    ) -> Result<Option<AdminUser>, OpenAuthError> {
        data.insert(
            "updated_at".to_owned(),
            DbValue::Timestamp(OffsetDateTime::now_utc()),
        );
        let mut query =
            Update::new(USER_MODEL).where_clause(Where::new("id", DbValue::String(user_id.into())));
        for (field, value) in data {
            query = query.data(field, value);
        }
        self.adapter
            .update(query)
            .await?
            .map(admin_user_from_record)
            .transpose()
    }

    pub async fn ban_user(
        &self,
        user_id: &str,
        reason: String,
        expires_at: Option<OffsetDateTime>,
    ) -> Result<Option<AdminUser>, OpenAuthError> {
        let user = self
            .update_user_fields(
                user_id,
                DbRecord::from([
                    ("banned".to_owned(), DbValue::Boolean(true)),
                    ("ban_reason".to_owned(), DbValue::String(reason)),
                    (
                        "ban_expires".to_owned(),
                        expires_at.map(DbValue::Timestamp).unwrap_or(DbValue::Null),
                    ),
                ]),
            )
            .await?;
        self.delete_user_sessions(user_id).await?;
        Ok(user)
    }

    pub async fn unban_user(&self, user_id: &str) -> Result<Option<AdminUser>, OpenAuthError> {
        self.update_user_fields(
            user_id,
            DbRecord::from([
                ("banned".to_owned(), DbValue::Boolean(false)),
                ("ban_reason".to_owned(), DbValue::Null),
                ("ban_expires".to_owned(), DbValue::Null),
            ]),
        )
        .await
    }

    pub async fn create_session(
        &self,
        user_id: &str,
        expires_at: OffsetDateTime,
        impersonated_by: Option<String>,
    ) -> Result<AdminSession, OpenAuthError> {
        let now = OffsetDateTime::now_utc();
        let record = self
            .adapter
            .create(
                Create::new(SESSION_MODEL)
                    .data(
                        "id",
                        DbValue::String(openauth_core::crypto::random::generate_random_string(32)),
                    )
                    .data("user_id", DbValue::String(user_id.to_owned()))
                    .data("expires_at", DbValue::Timestamp(expires_at))
                    .data(
                        "token",
                        DbValue::String(openauth_core::crypto::random::generate_random_string(32)),
                    )
                    .data("ip_address", DbValue::Null)
                    .data("user_agent", DbValue::Null)
                    .data("created_at", DbValue::Timestamp(now))
                    .data("updated_at", DbValue::Timestamp(now))
                    .data(
                        "impersonated_by",
                        impersonated_by
                            .map(DbValue::String)
                            .unwrap_or(DbValue::Null),
                    )
                    .select(SESSION_FIELDS)
                    .force_allow_id(),
            )
            .await?;
        admin_session_from_record(record)
    }

    pub async fn find_session(
        &self,
        token: &str,
    ) -> Result<Option<(AdminSession, AdminUser)>, OpenAuthError> {
        let Some(record) = self
            .adapter
            .find_one(
                FindOne::new(SESSION_MODEL)
                    .where_clause(Where::new("token", DbValue::String(token.to_owned())))
                    .select(SESSION_FIELDS),
            )
            .await?
        else {
            return Ok(None);
        };
        let session = admin_session_from_record(record)?;
        if session.expires_at <= OffsetDateTime::now_utc() {
            return Ok(None);
        }
        let Some(user) = self.find_user_by_id(&session.user_id).await? else {
            return Ok(None);
        };
        Ok(Some((session, user)))
    }

    pub async fn list_user_sessions(
        &self,
        user_id: &str,
    ) -> Result<Vec<AdminSession>, OpenAuthError> {
        let now = OffsetDateTime::now_utc();
        self.adapter
            .find_many(
                FindMany::new(SESSION_MODEL)
                    .where_clause(Where::new("user_id", DbValue::String(user_id.to_owned())))
                    .select(SESSION_FIELDS),
            )
            .await?
            .into_iter()
            .map(admin_session_from_record)
            .filter_map(|result| match result {
                Ok(session) if session.expires_at > now => Some(Ok(session)),
                Ok(_) => None,
                Err(error) => Some(Err(error)),
            })
            .collect()
    }

    pub async fn delete_session(&self, token: &str) -> Result<(), OpenAuthError> {
        self.adapter
            .delete(
                Delete::new(SESSION_MODEL)
                    .where_clause(Where::new("token", DbValue::String(token.to_owned()))),
            )
            .await
    }

    pub async fn delete_user_sessions(&self, user_id: &str) -> Result<u64, OpenAuthError> {
        self.adapter
            .delete_many(
                DeleteMany::new(SESSION_MODEL)
                    .where_clause(Where::new("user_id", DbValue::String(user_id.to_owned()))),
            )
            .await
    }

    pub async fn delete_user(&self, user_id: &str) -> Result<(), OpenAuthError> {
        self.delete_user_sessions(user_id).await?;
        self.adapter
            .delete_many(
                DeleteMany::new(ACCOUNT_MODEL)
                    .where_clause(Where::new("user_id", DbValue::String(user_id.to_owned()))),
            )
            .await?;
        self.adapter
            .delete(
                Delete::new(USER_MODEL)
                    .where_clause(Where::new("id", DbValue::String(user_id.to_owned()))),
            )
            .await
    }

    pub async fn set_password(
        &self,
        user_id: &str,
        password_hash: String,
    ) -> Result<Option<Account>, OpenAuthError> {
        let store = DbUserStore::new(self.adapter);
        match store
            .update_credential_password(user_id, &password_hash)
            .await?
        {
            Some(account) => Ok(Some(account)),
            None => store
                .create_credential_account(CreateCredentialAccountInput::new(
                    user_id.to_owned(),
                    password_hash,
                ))
                .await
                .map(Some),
        }
    }
}

pub fn role_value(value: serde_json::Value) -> Result<DbValue, OpenAuthError> {
    match value {
        serde_json::Value::String(role) => Ok(DbValue::String(role)),
        serde_json::Value::Array(roles) => roles
            .into_iter()
            .map(|value| match value {
                serde_json::Value::String(role) => Ok(role),
                _ => Err(OpenAuthError::Api(
                    "role array values must be strings".to_owned(),
                )),
            })
            .collect::<Result<Vec<_>, _>>()
            .map(|roles| DbValue::String(roles.join(","))),
        _ => Err(OpenAuthError::Api(
            "role must be a string or string array".to_owned(),
        )),
    }
}

pub fn json_to_db_value(value: serde_json::Value) -> DbValue {
    match value {
        serde_json::Value::Null => DbValue::Null,
        serde_json::Value::Bool(value) => DbValue::Boolean(value),
        serde_json::Value::Number(value) => value
            .as_i64()
            .map(DbValue::Number)
            .unwrap_or_else(|| DbValue::Json(serde_json::Value::Number(value))),
        serde_json::Value::String(value) => DbValue::String(value),
        other => DbValue::Json(other),
    }
}

fn list_where_clauses(input: &ListUsersQuery) -> Vec<Where> {
    let mut clauses = Vec::new();
    if let Some(search_value) = &input.search_value {
        clauses.push(
            Where::new(
                input.search_field.as_deref().unwrap_or("email"),
                DbValue::String(search_value.clone()),
            )
            .operator(match input.search_operator.as_deref() {
                Some("starts_with") => WhereOperator::StartsWith,
                Some("ends_with") => WhereOperator::EndsWith,
                _ => WhereOperator::Contains,
            })
            .insensitive(),
        );
    }
    if let Some(filter_value) = &input.filter_value {
        clauses.push(
            Where::new(
                filter_field(input.filter_field.as_deref()),
                filter_value.clone(),
            )
            .operator(where_operator(input.filter_operator.as_deref())),
        );
    }
    clauses
}

fn where_operator(operator: Option<&str>) -> WhereOperator {
    match operator {
        Some("ne") => WhereOperator::Ne,
        Some("lt") => WhereOperator::Lt,
        Some("lte") => WhereOperator::Lte,
        Some("gt") => WhereOperator::Gt,
        Some("gte") => WhereOperator::Gte,
        Some("contains") => WhereOperator::Contains,
        Some("starts_with") => WhereOperator::StartsWith,
        Some("ends_with") => WhereOperator::EndsWith,
        Some("in") => WhereOperator::In,
        Some("not_in") => WhereOperator::NotIn,
        _ => WhereOperator::Eq,
    }
}

fn filter_field(field: Option<&str>) -> &str {
    match field {
        Some("_id") => "id",
        Some(field) => field,
        None => "email",
    }
}

pub fn ban_expires_from_now(seconds: i64) -> Option<OffsetDateTime> {
    (seconds > 0).then(|| OffsetDateTime::now_utc() + Duration::seconds(seconds))
}
