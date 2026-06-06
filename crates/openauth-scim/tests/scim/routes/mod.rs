use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use http::{header, Method, Request, StatusCode};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::cookies::{set_session_cookie, Cookie, SessionCookieOptions};
use openauth_core::db::{Create, DbAdapter, DbValue, Delete, FindOne, MemoryAdapter, Where};
use openauth_core::options::{AdvancedOptions, OpenAuthOptions, RateLimitOptions};
use openauth_core::session::{CreateSessionInput, DbSessionStore};
use openauth_core::user::{CreateCredentialAccountInput, CreateUserInput, DbUserStore};
use openauth_plugins::organization::{organization_with_options, OrganizationOptions};
use openauth_scim::store::{CreateScimProviderInput, ScimProviderStore};
use openauth_scim::token::encode_bearer_token;
use openauth_scim::{
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
