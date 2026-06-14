use std::any::Any;
use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use crate::db::{Session, User};
use crate::error::RustAuthError;
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
    pub fn get(&self) -> Result<T, RustAuthError> {
        with_current_store(|store| {
            if let Some(value) = store.values.get(&self.key) {
                return value
                    .downcast_ref::<T>()
                    .cloned()
                    .ok_or(RustAuthError::RequestStateTypeMismatch);
            }

            let value = (self.init)();
            store.values.insert(self.key, Box::new(value.clone()));
            Ok(value)
        })
    }

    /// Set the value for this request.
    pub fn set(&self, value: T) -> Result<(), RustAuthError> {
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
static CURRENT_SESSION: OnceLock<RequestState<Option<CurrentSession>>> = OnceLock::new();
static CURRENT_NEW_SESSION: OnceLock<RequestState<Option<NewSession>>> = OnceLock::new();
static CURRENT_REQUEST_PATH: OnceLock<RequestState<Option<String>>> = OnceLock::new();
static REQUEST_IS_EXTERNAL: OnceLock<RequestState<bool>> = OnceLock::new();
static SHOULD_SKIP_SESSION_REFRESH: OnceLock<RequestState<bool>> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSession {
    pub session: Session,
    pub user: User,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentSession {
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
pub fn set_current_session_user(user: Value) -> Result<(), RustAuthError> {
    current_session_user_state().set(Some(user))
}

/// Read the current session user JSON for this request, when an endpoint resolved one.
pub fn current_session_user() -> Result<Option<Value>, RustAuthError> {
    current_session_user_state().get()
}

fn current_session_state() -> &'static RequestState<Option<CurrentSession>> {
    CURRENT_SESSION.get_or_init(|| define_request_state(|| None))
}

pub fn set_current_session(session: Session, user: User) -> Result<(), RustAuthError> {
    current_session_state().set(Some(CurrentSession { session, user }))
}

pub fn current_session() -> Result<Option<CurrentSession>, RustAuthError> {
    current_session_state().get()
}

fn current_new_session_state() -> &'static RequestState<Option<NewSession>> {
    CURRENT_NEW_SESSION.get_or_init(|| define_request_state(|| None))
}

pub fn set_current_new_session(session: Session, user: User) -> Result<(), RustAuthError> {
    current_new_session_state().set(Some(NewSession { session, user }))
}

pub fn current_new_session() -> Result<Option<NewSession>, RustAuthError> {
    current_new_session_state().get()
}

/// Store the normalized endpoint path for hooks running in this request.
pub fn set_current_request_path(path: impl Into<String>) -> Result<(), RustAuthError> {
    current_request_path_state().set(Some(path.into()))
}

/// Read the normalized endpoint path for this request, when available.
pub fn current_request_path() -> Result<Option<String>, RustAuthError> {
    current_request_path_state().get()
}

fn request_is_external_state() -> &'static RequestState<bool> {
    REQUEST_IS_EXTERNAL.get_or_init(|| define_request_state(|| false))
}

fn should_skip_session_refresh_state() -> &'static RequestState<bool> {
    SHOULD_SKIP_SESSION_REFRESH.get_or_init(|| define_request_state(|| false))
}

/// Mark whether the current request originated from the internet-facing HTTP
/// router. Trusted server-side invocations leave this `false`.
pub fn set_request_external(external: bool) -> Result<(), RustAuthError> {
    request_is_external_state().set(external)
}

/// Returns true only when the current request is known to originate from the
/// internet-facing HTTP router. Absent request state is treated as a trusted
/// server-side call (`false`).
pub fn is_external_request() -> bool {
    if !has_request_state() {
        return false;
    }
    request_is_external_state().get().unwrap_or(false)
}

/// Mark whether session resolution should skip refresh for the current request.
pub fn set_should_skip_session_refresh(skip: bool) -> Result<(), RustAuthError> {
    should_skip_session_refresh_state().set(skip)
}

/// Returns true when the current request explicitly disables session refresh.
pub fn should_skip_session_refresh() -> bool {
    if !has_request_state() {
        return false;
    }
    should_skip_session_refresh_state().get().unwrap_or(false)
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
    operation: impl FnOnce(&mut RequestStateStore) -> Result<T, RustAuthError>,
) -> Result<T, RustAuthError> {
    REQUEST_STATE
        .try_with(|store| operation(&mut store.borrow_mut()))
        .map_err(|_| RustAuthError::RequestStateMissing)?
}
