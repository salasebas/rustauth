use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use http::{header, Method, Request, StatusCode};
use openauth_core::api::AuthRouter;
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::cookies::{get_cookies, set_session_cookie, Cookie, SessionCookieOptions};
use openauth_core::db::{DbFieldType, DbValue, MemoryAdapter};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{
    AdvancedOptions, OpenAuthOptions, SecondaryStorage, SecondaryStorageFuture,
};
use openauth_core::session::{CreateSessionInput, DbSessionStore};
use openauth_core::user::{CreateUserInput, DbUserStore};
use openauth_plugins::device_authorization::{
    device_authorization_with_options, DeviceAuthorizationOptions,
};
use serde_json::Value;
use time::{Duration, OffsetDateTime};

mod code;
mod decision;
mod options;
mod schema;
mod token;
mod verify;

type TestAdapter = MemoryAdapter;

fn router(
    adapter: Arc<TestAdapter>,
    options: DeviceAuthorizationOptions,
) -> Result<AuthRouter, OpenAuthError> {
    router_with_openauth_options(adapter, options, OpenAuthOptions::default())
}

fn router_with_openauth_options(
    adapter: Arc<TestAdapter>,
    plugin_options: DeviceAuthorizationOptions,
    mut auth_options: OpenAuthOptions,
) -> Result<AuthRouter, OpenAuthError> {
    auth_options.plugins = vec![device_authorization_with_options(plugin_options)];
    auth_options.secret = Some(secret().to_owned());
    auth_options.base_url = Some("http://localhost:3000".to_owned());
    auth_options.advanced = AdvancedOptions {
        disable_csrf_check: true,
        disable_origin_check: true,
        ..auth_options.advanced
    };
    let context = create_auth_context_with_adapter(auth_options, adapter)?;
    AuthRouter::with_async_endpoints(context, Vec::new(), Vec::new())
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

fn form_request(
    method: Method,
    path: &str,
    body: &str,
    cookie: Option<&str>,
) -> Result<Request<Vec<u8>>, http::Error> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://localhost:3000{path}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(body.as_bytes().to_vec())
}

async fn create_device_code(
    router: &AuthRouter,
    client_id: &str,
    scope: Option<&str>,
) -> Result<Value, Box<dyn std::error::Error>> {
    let body = match scope {
        Some(scope) => format!(r#"{{"client_id":"{client_id}","scope":"{scope}"}}"#),
        None => format!(r#"{{"client_id":"{client_id}"}}"#),
    };
    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/device/code",
            &body,
            None,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(serde_json::from_slice(response.body())?)
}

async fn create_user_session(
    adapter: &TestAdapter,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let user = DbUserStore::new(adapter)
        .create_user(
            CreateUserInput::new("Ada", "ada@example.com")
                .id("user_1")
                .email_verified(true),
        )
        .await?;
    let session = DbSessionStore::new(adapter)
        .create_session(
            CreateSessionInput::new(
                user.id.clone(),
                OffsetDateTime::now_utc() + Duration::days(7),
            )
            .token("session_token_1"),
        )
        .await?;
    Ok((user.id, signed_session_cookie(&session.token)?))
}

fn signed_session_cookie(token: &str) -> Result<String, OpenAuthError> {
    let cookies = set_session_cookie(
        &get_cookies(&OpenAuthOptions {
            secret: Some(secret().to_owned()),
            ..OpenAuthOptions::default()
        })?,
        secret(),
        token,
        SessionCookieOptions::default(),
    )?;
    Ok(cookie_header(&cookies))
}

fn cookie_header(cookies: &[Cookie]) -> String {
    cookies
        .iter()
        .map(|cookie| format!("{}={}", cookie.name, cookie.value))
        .collect::<Vec<_>>()
        .join("; ")
}

fn secret() -> &'static str {
    "test-secret-123456789012345678901234"
}

fn string_field<'a>(body: &'a Value, name: &str) -> &'a str {
    body[name].as_str().unwrap_or_default()
}

async fn device_record(adapter: &TestAdapter) -> Option<indexmap::IndexMap<String, DbValue>> {
    adapter.records("deviceCode").await.into_iter().next()
}

#[derive(Default)]
struct TestSecondaryStorage {
    values: Mutex<HashMap<String, String>>,
}

impl TestSecondaryStorage {
    fn value(&self, key: &str) -> Result<Option<String>, OpenAuthError> {
        Ok(self
            .values
            .lock()
            .map_err(|_| OpenAuthError::Api("secondary storage lock poisoned".to_owned()))?
            .get(key)
            .cloned())
    }
}

impl SecondaryStorage for TestSecondaryStorage {
    fn get<'a>(&'a self, key: &'a str) -> SecondaryStorageFuture<'a, Option<String>> {
        Box::pin(async move { self.value(key) })
    }

    fn set<'a>(
        &'a self,
        key: &'a str,
        value: String,
        _ttl_seconds: Option<u64>,
    ) -> SecondaryStorageFuture<'a, ()> {
        Box::pin(async move {
            self.values
                .lock()
                .map_err(|_| OpenAuthError::Api("secondary storage lock poisoned".to_owned()))?
                .insert(key.to_owned(), value);
            Ok(())
        })
    }

    fn set_if_not_exists<'a>(
        &'a self,
        key: &'a str,
        value: String,
        _ttl_seconds: Option<u64>,
    ) -> SecondaryStorageFuture<'a, bool> {
        Box::pin(async move {
            let mut values = self
                .values
                .lock()
                .map_err(|_| OpenAuthError::Api("secondary storage lock poisoned".to_owned()))?;
            if values.contains_key(key) {
                return Ok(false);
            }
            values.insert(key.to_owned(), value);
            Ok(true)
        })
    }

    fn delete<'a>(&'a self, key: &'a str) -> SecondaryStorageFuture<'a, ()> {
        Box::pin(async move {
            self.values
                .lock()
                .map_err(|_| OpenAuthError::Api("secondary storage lock poisoned".to_owned()))?
                .remove(key);
            Ok(())
        })
    }

    fn take<'a>(&'a self, key: &'a str) -> SecondaryStorageFuture<'a, Option<String>> {
        Box::pin(async move {
            Ok(self
                .values
                .lock()
                .map_err(|_| OpenAuthError::Api("secondary storage lock poisoned".to_owned()))?
                .remove(key))
        })
    }

    fn compare_and_set<'a>(
        &'a self,
        key: &'a str,
        expected: Option<String>,
        value: String,
        ttl_seconds: Option<u64>,
    ) -> SecondaryStorageFuture<'a, bool> {
        Box::pin(async move {
            let mut values = self
                .values
                .lock()
                .map_err(|_| OpenAuthError::Api("secondary storage lock poisoned".to_owned()))?;
            if values.get(key).cloned() != expected {
                return Ok(false);
            }
            if ttl_seconds == Some(0) {
                values.remove(key);
            } else {
                values.insert(key.to_owned(), value);
            }
            Ok(true)
        })
    }

    fn delete_if_value<'a>(
        &'a self,
        key: &'a str,
        expected: Option<String>,
    ) -> SecondaryStorageFuture<'a, bool> {
        Box::pin(async move {
            let Some(expected) = expected else {
                return Ok(false);
            };
            let mut values = self
                .values
                .lock()
                .map_err(|_| OpenAuthError::Api("secondary storage lock poisoned".to_owned()))?;
            if values.get(key).map(String::as_str) != Some(expected.as_str()) {
                return Ok(false);
            }
            values.remove(key);
            Ok(true)
        })
    }
}
