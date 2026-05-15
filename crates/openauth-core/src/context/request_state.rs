use std::any::Any;
use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use crate::db::{Session, User};
use crate::error::OpenAuthError;
use serde_json::Value;

tokio::task_local! {
    static REQUEST_STATE: RefCell<RequestStateStore>;
}

static NEXT_KEY: AtomicU64 = AtomicU64::new(1);

/// Request-scoped state storage.
#[derive(Default)]
pub struct RequestStateStore {
    values: HashMap<RequestStateKey, Box<dyn Any + Send>>,
}

impl RequestStateStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestStateKey(u64);

impl RequestStateKey {
    fn new() -> Self {
        Self(NEXT_KEY.fetch_add(1, Ordering::Relaxed))
    }
}

/// Request-scoped typed value.
pub struct RequestState<T> {
    key: RequestStateKey,
    init: Arc<dyn Fn() -> T + Send + Sync>,
}

impl<T> Clone for RequestState<T> {
    fn clone(&self) -> Self {
        Self {
            key: self.key,
            init: Arc::clone(&self.init),
        }
    }
}

impl<T> RequestState<T>
where
    T: Clone + Send + 'static,
{
    /// Get the value for this request, lazily initializing it when absent.
    pub fn get(&self) -> Result<T, OpenAuthError> {
        with_current_store(|store| {
            if let Some(value) = store.values.get(&self.key) {
                return value
                    .downcast_ref::<T>()
                    .cloned()
                    .ok_or(OpenAuthError::RequestStateTypeMismatch);
            }

            let value = (self.init)();
            store.values.insert(self.key, Box::new(value.clone()));
            Ok(value)
        })
    }

    /// Set the value for this request.
    pub fn set(&self, value: T) -> Result<(), OpenAuthError> {
        with_current_store(|store| {
            store.values.insert(self.key, Box::new(value));
            Ok(())
        })
    }

    /// Unique key for debugging or custom stores.
    pub fn key(&self) -> RequestStateKey {
        self.key
    }
}

/// Define a typed request-scoped state value.
pub fn define_request_state<T>(init: impl Fn() -> T + Send + Sync + 'static) -> RequestState<T>
where
    T: Clone + Send + 'static,
{
    RequestState {
        key: RequestStateKey::new(),
        init: Arc::new(init),
    }
}

static CURRENT_SESSION_USER: OnceLock<RequestState<Option<Value>>> = OnceLock::new();
static CURRENT_NEW_SESSION: OnceLock<RequestState<Option<NewSession>>> = OnceLock::new();
static CURRENT_REQUEST_PATH: OnceLock<RequestState<Option<String>>> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSession {
    pub session: Session,
    pub user: User,
}

fn current_session_user_state() -> &'static RequestState<Option<Value>> {
    CURRENT_SESSION_USER.get_or_init(|| define_request_state(|| None))
}

fn current_request_path_state() -> &'static RequestState<Option<String>> {
    CURRENT_REQUEST_PATH.get_or_init(|| define_request_state(|| None))
}

/// Store the current session user JSON for after-response hooks in this request.
pub fn set_current_session_user(user: Value) -> Result<(), OpenAuthError> {
    current_session_user_state().set(Some(user))
}

/// Read the current session user JSON for this request, when an endpoint resolved one.
pub fn current_session_user() -> Result<Option<Value>, OpenAuthError> {
    current_session_user_state().get()
}

fn current_new_session_state() -> &'static RequestState<Option<NewSession>> {
    CURRENT_NEW_SESSION.get_or_init(|| define_request_state(|| None))
}

pub fn set_current_new_session(session: Session, user: User) -> Result<(), OpenAuthError> {
    current_new_session_state().set(Some(NewSession { session, user }))
}

pub fn current_new_session() -> Result<Option<NewSession>, OpenAuthError> {
    current_new_session_state().get()
}

/// Store the normalized endpoint path for hooks running in this request.
pub fn set_current_request_path(path: impl Into<String>) -> Result<(), OpenAuthError> {
    current_request_path_state().set(Some(path.into()))
}

/// Read the normalized endpoint path for this request, when available.
pub fn current_request_path() -> Result<Option<String>, OpenAuthError> {
    current_request_path_state().get()
}

/// Run a future inside a fresh request state scope.
pub async fn run_with_request_state<F>(future: F) -> F::Output
where
    F: Future,
{
    REQUEST_STATE
        .scope(RefCell::new(RequestStateStore::new()), future)
        .await
}

/// Returns true when the current async task has request state.
pub fn has_request_state() -> bool {
    REQUEST_STATE.try_with(|_| ()).is_ok()
}

fn with_current_store<T>(
    operation: impl FnOnce(&mut RequestStateStore) -> Result<T, OpenAuthError>,
) -> Result<T, OpenAuthError> {
    REQUEST_STATE
        .try_with(|store| operation(&mut store.borrow_mut()))
        .map_err(|_| OpenAuthError::RequestStateMissing)?
}
