use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use http::{header, Method, Request, StatusCode};
use rustauth_core::api::{core_auth_async_endpoints, AuthRouter};
use rustauth_core::context::create_auth_context_with_adapter;
use rustauth_core::cookies::{set_session_cookie, Cookie, SessionCookieOptions};
use rustauth_core::db::{Create, DbAdapter, DbValue, Delete, FindOne, MemoryAdapter, Where};
use rustauth_core::options::{AdvancedOptions, RateLimitOptions, RustAuthOptions};
use rustauth_core::session::{CreateSessionInput, DbSessionStore};
use rustauth_core::user::{CreateCredentialAccountInput, CreateUserInput, DbUserStore};
use rustauth_plugins::organization::{organization, OrganizationOptions};
use rustauth_scim::store::{CreateScimProviderInput, ScimProviderStore};
use rustauth_scim::token::encode_bearer_token;
use rustauth_scim::{
    scim, DefaultScimProvider, ScimAuditEventKind, ScimAuditEventResolver, ScimBulkMode,
    ScimDeprovisionMode, ScimHookError, ScimOptions, ScimTokenStorage,
};
use serde_json::Value;
use time::{Duration, OffsetDateTime};

const SECRET: &str = "secret-a-at-least-32-chars-long!!";

mod audit;
mod auth;
mod bulk;
mod bulk_atomic;
mod concurrency;
mod deprovision;
mod groups;
mod groups_auth;
mod groups_native_team_boundary;
mod groups_scope;
mod isolation;
mod management;
mod metadata;
mod organization;
mod parity_gaps;
mod projection_scope;
mod provisioning;
mod search;
mod support;
mod users;

use support::*;
