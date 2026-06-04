use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use http::{header, Method, Request, StatusCode};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::db::{AdapterCapabilities, DbSchema, TransactionCallback};
use openauth_core::db::{
    AdapterFuture, Count, Create, DbAdapter, DbRecord, Delete, DeleteMany, FindMany, FindOne,
    MemoryAdapter, SchemaCreation, Update, UpdateMany,
};
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
    test_router_with_adapter(adapter, vec![plugin])
}

pub fn test_router_with_plugins(
    adapter: Arc<MemoryAdapter>,
    plugins: Vec<openauth_core::plugin::AuthPlugin>,
) -> Result<AuthRouter, Box<dyn std::error::Error>> {
    test_router_with_adapter(adapter, plugins)
}

pub fn test_router_with_adapter(
    adapter: Arc<dyn DbAdapter>,
    plugins: Vec<openauth_core::plugin::AuthPlugin>,
) -> Result<AuthRouter, Box<dyn std::error::Error>> {
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            plugins,
            base_url: Some("http://localhost:3000".to_owned()),
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            ..OpenAuthOptions::default()
        },
        adapter.clone(),
    )?;
    Ok(AuthRouter::with_async_endpoints(
        context,
        Vec::new(),
        core_auth_async_endpoints(adapter),
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
    let headers = header_pair.into_iter().collect::<Vec<_>>();
    request_json_with_headers(router, method, path, body, cookie, &headers).await
}

/// Drive a request through the trusted server-side entry point
/// ([`AuthRouter::handle_async_server`]) instead of the internet-facing router,
/// so server-only inputs (explicit `userId`, rate limit / refill / permissions
/// overrides) are honored as they would be for trusted backend callers.
pub async fn server_request_json(
    router: &AuthRouter,
    method: Method,
    path: &str,
    body: Value,
    cookie: Option<&str>,
    header_pair: Option<(&str, &str)>,
) -> Result<TestResponse, Box<dyn std::error::Error>> {
    let headers = header_pair.into_iter().collect::<Vec<_>>();
    dispatch_json(router, method, path, body, cookie, &headers, true).await
}

pub async fn request_json_with_headers(
    router: &AuthRouter,
    method: Method,
    path: &str,
    body: Value,
    cookie: Option<&str>,
    headers: &[(&str, &str)],
) -> Result<TestResponse, Box<dyn std::error::Error>> {
    dispatch_json(router, method, path, body, cookie, headers, false).await
}

async fn dispatch_json(
    router: &AuthRouter,
    method: Method,
    path: &str,
    body: Value,
    cookie: Option<&str>,
    headers: &[(&str, &str)],
    server_side: bool,
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
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder.body(payload)?;
    let response = if server_side {
        router.handle_async_server(request).await?
    } else {
        router.handle_async(request).await?
    };
    let status = response.status();
    let set_cookie = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with("open-auth.session_token="))
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

pub struct TestSecondaryStorage {
    values: Mutex<BTreeMap<String, String>>,
    deleted: Mutex<Vec<String>>,
    ttl: Mutex<BTreeMap<String, Option<u64>>>,
    delay_millis: AtomicU64,
    active_gets: AtomicUsize,
    max_active_gets: AtomicUsize,
    ref_gate_threshold: AtomicUsize,
    ref_gate_count: AtomicUsize,
    ref_gate: tokio::sync::Semaphore,
}

impl Default for TestSecondaryStorage {
    fn default() -> Self {
        Self {
            values: Mutex::new(BTreeMap::new()),
            deleted: Mutex::new(Vec::new()),
            ttl: Mutex::new(BTreeMap::new()),
            delay_millis: AtomicU64::new(0),
            active_gets: AtomicUsize::new(0),
            max_active_gets: AtomicUsize::new(0),
            ref_gate_threshold: AtomicUsize::new(0),
            ref_gate_count: AtomicUsize::new(0),
            ref_gate: tokio::sync::Semaphore::new(0),
        }
    }
}

impl TestSecondaryStorage {
    pub fn with_get_delay(delay_millis: u64) -> Self {
        Self {
            delay_millis: AtomicU64::new(delay_millis),
            ..Self::default()
        }
    }

    /// Builds storage that releases concurrent `api-key:by-ref:*` reads only
    /// once `threshold` of them are in flight at the same time (with a timeout
    /// fallback so a correctly serialized caller never deadlocks). This forces
    /// the lost-update race when index mutations are not serialized.
    pub fn with_ref_index_gate(threshold: usize) -> Self {
        let storage = Self::default();
        storage
            .ref_gate_threshold
            .store(threshold, Ordering::SeqCst);
        storage
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

    pub fn insert_raw(&self, key: impl Into<String>, value: impl Into<String>) {
        if let Ok(mut values) = self.values.lock() {
            values.insert(key.into(), value.into());
        }
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

    /// Holds a read of an `api-key:by-ref:*` key until `ref_gate_threshold`
    /// concurrent reads of such keys have arrived, then releases them together.
    /// A timeout fallback keeps a serialized caller (one read at a time) from
    /// blocking forever, so the same gate works whether or not the store under
    /// test serializes index mutations.
    async fn gate_ref_get(&self, key: &str) {
        let threshold = self.ref_gate_threshold.load(Ordering::SeqCst);
        if threshold == 0 || !key.starts_with("api-key:by-ref:") {
            return;
        }
        let arrived = self.ref_gate_count.fetch_add(1, Ordering::SeqCst) + 1;
        if arrived >= threshold {
            self.ref_gate.add_permits(threshold);
        } else {
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(250),
                self.ref_gate.acquire(),
            )
            .await;
        }
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
            let value = self
                .values
                .lock()
                .map_err(|error| openauth_core::error::OpenAuthError::Adapter(error.to_string()))?
                .get(key)
                .cloned();
            // Release the snapshot only once enough concurrent readers have taken
            // theirs, so every gated reader observes the same pre-write value.
            self.gate_ref_get(key).await;
            Ok(value)
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

    fn set_if_not_exists<'a>(
        &'a self,
        key: &'a str,
        value: String,
        ttl_seconds: Option<u64>,
    ) -> Pin<Box<dyn Future<Output = Result<bool, openauth_core::error::OpenAuthError>> + Send + 'a>>
    {
        Box::pin(async move {
            let mut values = self
                .values
                .lock()
                .map_err(|error| openauth_core::error::OpenAuthError::Adapter(error.to_string()))?;
            if values.contains_key(key) {
                return Ok(false);
            }
            values.insert(key.to_owned(), value);
            drop(values);
            self.ttl
                .lock()
                .map_err(|error| openauth_core::error::OpenAuthError::Adapter(error.to_string()))?
                .insert(key.to_owned(), ttl_seconds);
            Ok(true)
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

#[derive(Clone)]
pub struct DelayedUpdateAdapter {
    inner: Arc<MemoryAdapter>,
    delay: std::time::Duration,
}

impl DelayedUpdateAdapter {
    pub fn new(inner: Arc<MemoryAdapter>, delay: std::time::Duration) -> Self {
        Self { inner, delay }
    }
}

impl DbAdapter for DelayedUpdateAdapter {
    fn id(&self) -> &str {
        "delayed-update-memory"
    }

    fn capabilities(&self) -> AdapterCapabilities {
        self.inner.capabilities()
    }

    fn create<'a>(&'a self, query: Create) -> AdapterFuture<'a, DbRecord> {
        self.inner.create(query)
    }

    fn find_one<'a>(&'a self, query: FindOne) -> AdapterFuture<'a, Option<DbRecord>> {
        self.inner.find_one(query)
    }

    fn find_many<'a>(&'a self, query: FindMany) -> AdapterFuture<'a, Vec<DbRecord>> {
        self.inner.find_many(query)
    }

    fn count<'a>(&'a self, query: Count) -> AdapterFuture<'a, u64> {
        self.inner.count(query)
    }

    fn update<'a>(&'a self, query: Update) -> AdapterFuture<'a, Option<DbRecord>> {
        Box::pin(async move {
            tokio::time::sleep(self.delay).await;
            self.inner.update(query).await
        })
    }

    fn update_many<'a>(&'a self, query: UpdateMany) -> AdapterFuture<'a, u64> {
        self.inner.update_many(query)
    }

    fn delete<'a>(&'a self, query: Delete) -> AdapterFuture<'a, ()> {
        self.inner.delete(query)
    }

    fn delete_many<'a>(&'a self, query: DeleteMany) -> AdapterFuture<'a, u64> {
        self.inner.delete_many(query)
    }

    fn transaction<'a>(&'a self, callback: TransactionCallback<'a>) -> AdapterFuture<'a, ()> {
        self.inner.transaction(callback)
    }

    fn create_schema<'a>(
        &'a self,
        schema: &'a DbSchema,
        file: Option<&'a str>,
    ) -> AdapterFuture<'a, Option<SchemaCreation>> {
        self.inner.create_schema(schema, file)
    }

    fn run_migrations<'a>(&'a self, schema: &'a DbSchema) -> AdapterFuture<'a, ()> {
        self.inner.run_migrations(schema)
    }
}
