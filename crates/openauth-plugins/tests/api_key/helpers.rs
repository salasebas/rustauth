use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use http::{header, Method, Request, StatusCode};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::db::{DbAdapter, MemoryAdapter};
use openauth_core::options::{
    BackgroundTaskFuture, BackgroundTaskRunner, OpenAuthOptions, SecondaryStorage,
};
use serde_json::{json, Value};

pub struct TestResponse {
    pub status: StatusCode,
    pub body: Value,
    pub set_cookie: Option<String>,
}

pub struct SignedUp {
    pub cookie: String,
    pub user_id: String,
}

pub fn test_router(
    adapter: Arc<MemoryAdapter>,
    plugin: openauth_core::plugin::AuthPlugin,
) -> Result<AuthRouter, Box<dyn std::error::Error>> {
    test_router_with_plugins(adapter, vec![plugin])
}

pub fn test_router_with_plugins(
    adapter: Arc<MemoryAdapter>,
    plugins: Vec<openauth_core::plugin::AuthPlugin>,
) -> Result<AuthRouter, Box<dyn std::error::Error>> {
    let adapter_dyn: Arc<dyn DbAdapter> = adapter;
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            plugins,
            base_url: Some("http://localhost:3000".to_owned()),
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            ..OpenAuthOptions::default()
        },
        adapter_dyn.clone(),
    )?;
    Ok(AuthRouter::with_async_endpoints(
        context,
        Vec::new(),
        core_auth_async_endpoints(adapter_dyn),
    )?)
}

pub async fn sign_up(
    router: &AuthRouter,
    name: &str,
    email: &str,
) -> Result<SignedUp, Box<dyn std::error::Error>> {
    let response = request_json(
        router,
        Method::POST,
        "/api/auth/sign-up/email",
        json!({"name":name,"email":email,"password":"secret123"}),
        None,
        None,
    )
    .await?;
    assert_eq!(response.status, StatusCode::OK);
    let user_id = response.body["user"]["id"]
        .as_str()
        .ok_or("missing user id")?
        .to_owned();
    Ok(SignedUp {
        cookie: response.set_cookie.ok_or("missing session cookie")?,
        user_id,
    })
}

pub async fn request_json(
    router: &AuthRouter,
    method: Method,
    path: &str,
    body: Value,
    cookie: Option<&str>,
    header_pair: Option<(&str, &str)>,
) -> Result<TestResponse, Box<dyn std::error::Error>> {
    let payload = if matches!(body, Value::Null) {
        Vec::new()
    } else {
        serde_json::to_vec(&body)?
    };
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://localhost:3000{path}"));
    if !payload.is_empty() {
        builder = builder
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, "http://localhost:3000");
    }
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    if let Some((name, value)) = header_pair {
        builder = builder.header(name, value);
    }
    let response = router.handle_async(builder.body(payload)?).await?;
    let status = response.status();
    let set_cookie = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with("better-auth.session_token="))
        .and_then(|value| value.split(';').next().map(str::to_owned));
    let body = if response.body().is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(response.body())?
    };
    Ok(TestResponse {
        status,
        body,
        set_cookie,
    })
}

#[derive(Default)]
pub struct TestSecondaryStorage {
    values: Mutex<BTreeMap<String, String>>,
    deleted: Mutex<Vec<String>>,
    ttl: Mutex<BTreeMap<String, Option<u64>>>,
    delay_millis: AtomicU64,
    active_gets: AtomicUsize,
    max_active_gets: AtomicUsize,
}

impl TestSecondaryStorage {
    pub fn with_get_delay(delay_millis: u64) -> Self {
        Self {
            delay_millis: AtomicU64::new(delay_millis),
            ..Self::default()
        }
    }

    pub fn deleted_keys(&self) -> Vec<String> {
        self.deleted
            .lock()
            .map(|keys| keys.clone())
            .unwrap_or_default()
    }

    pub fn ttl_for(&self, key: &str) -> Option<Option<u64>> {
        self.ttl.lock().ok().and_then(|ttl| ttl.get(key).copied())
    }

    pub fn max_active_gets(&self) -> usize {
        self.max_active_gets.load(Ordering::SeqCst)
    }

    async fn maybe_delay_get(&self) {
        let active = self.active_gets.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_active_gets.fetch_max(active, Ordering::SeqCst);
        let delay = self.delay_millis.load(Ordering::SeqCst);
        if delay > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
        }
        self.active_gets.fetch_sub(1, Ordering::SeqCst);
    }
}

impl SecondaryStorage for TestSecondaryStorage {
    fn get<'a>(
        &'a self,
        key: &'a str,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Option<String>, openauth_core::error::OpenAuthError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.maybe_delay_get().await;
            Ok(self
                .values
                .lock()
                .map_err(|error| openauth_core::error::OpenAuthError::Adapter(error.to_string()))?
                .get(key)
                .cloned())
        })
    }

    fn set<'a>(
        &'a self,
        key: &'a str,
        value: String,
        ttl_seconds: Option<u64>,
    ) -> Pin<Box<dyn Future<Output = Result<(), openauth_core::error::OpenAuthError>> + Send + 'a>>
    {
        Box::pin(async move {
            self.values
                .lock()
                .map_err(|error| openauth_core::error::OpenAuthError::Adapter(error.to_string()))?
                .insert(key.to_owned(), value);
            self.ttl
                .lock()
                .map_err(|error| openauth_core::error::OpenAuthError::Adapter(error.to_string()))?
                .insert(key.to_owned(), ttl_seconds);
            Ok(())
        })
    }

    fn delete<'a>(
        &'a self,
        key: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), openauth_core::error::OpenAuthError>> + Send + 'a>>
    {
        Box::pin(async move {
            self.values
                .lock()
                .map_err(|error| openauth_core::error::OpenAuthError::Adapter(error.to_string()))?
                .remove(key);
            self.deleted
                .lock()
                .map_err(|error| openauth_core::error::OpenAuthError::Adapter(error.to_string()))?
                .push(key.to_owned());
            Ok(())
        })
    }
}

#[derive(Default)]
pub struct CountingBackgroundRunner {
    calls: AtomicUsize,
}

impl CountingBackgroundRunner {
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl BackgroundTaskRunner for CountingBackgroundRunner {
    fn spawn(&self, task: BackgroundTaskFuture) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        tokio::spawn(task);
    }
}
