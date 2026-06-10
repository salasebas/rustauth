use std::sync::Arc;

use http::{header, Method, Request};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::cookies::sign_cookie_value;
use openauth_core::db::{Create, DbAdapter, DbRecord, DbValue, MemoryAdapter, User};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{
    AdvancedOptions, CookieCacheOptions, OpenAuthOptions, SessionOptions,
};
use openauth_core::session::{CreateSessionInput, DbSessionStore};
use openauth_core::test_utils::{fast_hash_password, with_integration_test_defaults};
use openauth_plugins::multi_session::{multi_session_with, MultiSessionConfig};
use serde_json::Value;
use time::{Duration, OffsetDateTime};

pub struct Fixture {
    pub adapter: Arc<MemoryAdapter>,
    router: AuthRouter,
}

impl Fixture {
    pub async fn new(config: MultiSessionConfig) -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_options(config, OpenAuthOptions::default()).await
    }

    pub async fn with_cookie_cache(
        config: MultiSessionConfig,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_options(
            config,
            OpenAuthOptions {
                session: SessionOptions {
                    cookie_cache: CookieCacheOptions {
                        enabled: true,
                        ..CookieCacheOptions::default()
                    },
                    ..SessionOptions::default()
                },
                ..OpenAuthOptions::default()
            },
        )
        .await
    }

    pub async fn with_options(
        config: MultiSessionConfig,
        options: OpenAuthOptions,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let adapter = Arc::new(MemoryAdapter::new());
        seed_user(&adapter, "user_1", "Ada", "ada@example.com").await?;
        seed_user(&adapter, "user_2", "Grace", "grace@example.com").await?;
        let context = create_auth_context_with_adapter(
            with_integration_test_defaults(OpenAuthOptions {
                secret: Some(secret().to_owned()),
                plugins: vec![multi_session_with(config)],
                advanced: AdvancedOptions {
                    disable_csrf_check: true,
                    disable_origin_check: true,
                    ..AdvancedOptions::default()
                },
                ..options
            }),
            adapter.clone(),
        )?;
        let router = AuthRouter::with_async_endpoints(
            context,
            Vec::new(),
            core_auth_async_endpoints(adapter.clone()),
        )?;
        Ok(Self { adapter, router })
    }

    pub async fn sign_in(
        &self,
        email: &str,
        password: &str,
        cookie: Option<&str>,
    ) -> Result<http::Response<Vec<u8>>, OpenAuthError> {
        self.sign_in_with_body(
            &format!(r#"{{"email":"{email}","password":"{password}"}}"#),
            cookie,
        )
        .await
    }

    pub async fn sign_in_with_body(
        &self,
        body: &str,
        cookie: Option<&str>,
    ) -> Result<http::Response<Vec<u8>>, OpenAuthError> {
        self.request(Method::POST, "/api/auth/sign-in/email", body, cookie)
            .await
    }

    pub async fn sign_up(
        &self,
        email: &str,
        cookie: Option<&str>,
    ) -> Result<http::Response<Vec<u8>>, OpenAuthError> {
        self.request(
            Method::POST,
            "/api/auth/sign-up/email",
            &format!(r#"{{"name":"Linus","email":"{email}","password":"secret123"}}"#),
            cookie,
        )
        .await
    }

    pub async fn create_expired_session(
        &self,
        user_id: &str,
        token: &str,
    ) -> Result<(), OpenAuthError> {
        DbSessionStore::new(self.adapter.as_ref())
            .create_session(
                CreateSessionInput::new(user_id, OffsetDateTime::now_utc() - Duration::hours(1))
                    .token(token),
            )
            .await?;
        Ok(())
    }

    pub async fn request(
        &self,
        method: Method,
        path: &str,
        body: &str,
        cookie: Option<&str>,
    ) -> Result<http::Response<Vec<u8>>, OpenAuthError> {
        self.router
            .handle_async(
                json_request(method, path, body, cookie)
                    .map_err(|error| OpenAuthError::Api(error.to_string()))?,
            )
            .await
    }

    pub fn openapi_schema(&self) -> Value {
        self.router.openapi_schema()
    }
}

async fn seed_user(
    adapter: &MemoryAdapter,
    id: &str,
    name: &str,
    email: &str,
) -> Result<(), OpenAuthError> {
    let now = OffsetDateTime::now_utc();
    adapter
        .create(create_query("user", user_record(id, name, email, now)))
        .await?;
    adapter
        .create(create_query(
            "account",
            credential_account_record(id, &fast_hash_password("secret123")?, now),
        ))
        .await?;
    Ok(())
}

fn json_request(
    method: Method,
    path: &str,
    body: &str,
    cookie: Option<&str>,
) -> Result<Request<Vec<u8>>, http::Error> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://localhost:3000{path}"));
    if !body.is_empty() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(body.as_bytes().to_vec())
}

fn user_record(id: &str, name: &str, email: &str, now: OffsetDateTime) -> DbRecord {
    let user = User {
        id: id.to_owned(),
        name: name.to_owned(),
        email: email.to_owned(),
        email_verified: true,
        image: None,
        username: None,
        display_username: None,
        created_at: now,
        updated_at: now,
    };
    let mut record = DbRecord::new();
    record.insert("id".to_owned(), DbValue::String(user.id));
    record.insert("name".to_owned(), DbValue::String(user.name));
    record.insert("email".to_owned(), DbValue::String(user.email));
    record.insert("email_verified".to_owned(), DbValue::Boolean(true));
    record.insert("image".to_owned(), DbValue::Null);
    record.insert("username".to_owned(), DbValue::Null);
    record.insert("display_username".to_owned(), DbValue::Null);
    record.insert("created_at".to_owned(), DbValue::Timestamp(user.created_at));
    record.insert("updated_at".to_owned(), DbValue::Timestamp(user.updated_at));
    record
}

fn credential_account_record(user_id: &str, password_hash: &str, now: OffsetDateTime) -> DbRecord {
    let mut record = DbRecord::new();
    record.insert(
        "id".to_owned(),
        DbValue::String(format!("account_{user_id}")),
    );
    record.insert(
        "provider_id".to_owned(),
        DbValue::String("credential".to_owned()),
    );
    record.insert("account_id".to_owned(), DbValue::String(user_id.to_owned()));
    record.insert("user_id".to_owned(), DbValue::String(user_id.to_owned()));
    record.insert("access_token".to_owned(), DbValue::Null);
    record.insert("refresh_token".to_owned(), DbValue::Null);
    record.insert("id_token".to_owned(), DbValue::Null);
    record.insert("access_token_expires_at".to_owned(), DbValue::Null);
    record.insert("refresh_token_expires_at".to_owned(), DbValue::Null);
    record.insert("scope".to_owned(), DbValue::Null);
    record.insert(
        "password".to_owned(),
        DbValue::String(password_hash.to_owned()),
    );
    record.insert("created_at".to_owned(), DbValue::Timestamp(now));
    record.insert("updated_at".to_owned(), DbValue::Timestamp(now));
    record
}

fn create_query(model: &str, record: DbRecord) -> Create {
    record
        .into_iter()
        .fold(Create::new(model), |query, (field, value)| {
            query.data(field, value)
        })
}

pub fn response_token(
    response: &http::Response<Vec<u8>>,
) -> Result<String, Box<dyn std::error::Error>> {
    let body: Value = serde_json::from_slice(response.body())?;
    body["token"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "missing token".into())
}

pub fn set_cookie_values(response: &http::Response<Vec<u8>>) -> Vec<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok().map(str::to_owned))
        .collect()
}

pub fn cookie_header_from_response(response: &http::Response<Vec<u8>>) -> String {
    set_cookie_values(response)
        .into_iter()
        .filter_map(|cookie| cookie.split_once(';').map(|(pair, _)| pair.to_owned()))
        .collect::<Vec<_>>()
        .join("; ")
}

pub fn merge_cookie_headers(headers: &[&str]) -> String {
    headers
        .iter()
        .flat_map(|header| header.split("; "))
        .filter(|cookie| !cookie.is_empty())
        .collect::<Vec<_>>()
        .join("; ")
}

pub fn multi_cookie_name(token: &str) -> String {
    format!("open-auth.session_token_multi-{}", token.to_lowercase())
}

pub fn signed_multi_cookie(token: &str) -> Result<String, OpenAuthError> {
    Ok(format!(
        "{}={}",
        multi_cookie_name(token),
        sign_cookie_value(token, secret())?
    ))
}

fn secret() -> &'static str {
    "test-secret-123456789012345678901234"
}
