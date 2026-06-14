use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use rustauth_core::db::User;
use rustauth_core::error::RustAuthError;

use super::models::Organization;
use super::options::OrganizationOptions;
use super::store::OrganizationStore;

pub type OrganizationLimitFuture =
    Pin<Box<dyn Future<Output = Result<bool, RustAuthError>> + Send>>;
pub type OrganizationLimitCallback = Arc<dyn Fn(User) -> OrganizationLimitFuture + Send + Sync>;

pub type MembershipLimitFuture = Pin<Box<dyn Future<Output = Result<usize, RustAuthError>> + Send>>;
pub type MembershipLimitCallback =
    Arc<dyn Fn(MembershipLimitContext) -> MembershipLimitFuture + Send + Sync>;

#[derive(Clone)]
pub struct MembershipLimitContext {
    pub user: User,
    pub organization: Organization,
}

/// Maximum organizations a user may create.
#[derive(Clone)]
pub enum OrganizationLimit {
    Fixed(usize),
    Dynamic(OrganizationLimitCallback),
}

impl OrganizationLimit {
    pub async fn is_reached(
        &self,
        user: &User,
        current_count: usize,
    ) -> Result<bool, RustAuthError> {
        match self {
            Self::Fixed(limit) => Ok(current_count >= *limit),
            Self::Dynamic(callback) => (callback)(user.clone()).await,
        }
    }
}

/// Maximum members allowed in an organization.
#[derive(Clone)]
pub enum MembershipLimit {
    Fixed(usize),
    Dynamic(MembershipLimitCallback),
}

impl Default for MembershipLimit {
    fn default() -> Self {
        Self::Fixed(100)
    }
}

impl MembershipLimit {
    pub async fn resolve(&self, context: MembershipLimitContext) -> Result<usize, RustAuthError> {
        match self {
            Self::Fixed(limit) => Ok(*limit),
            Self::Dynamic(callback) => (callback)(context).await,
        }
    }
}

pub async fn membership_limit_reached(
    options: &OrganizationOptions,
    store: &OrganizationStore<'_>,
    organization_id: &str,
    user: &User,
) -> Result<bool, RustAuthError> {
    let Some(organization) = store.organization_by_id(organization_id).await? else {
        return Ok(false);
    };
    let limit = options
        .membership_limit
        .resolve(MembershipLimitContext {
            user: user.clone(),
            organization,
        })
        .await?;
    Ok(store.count_members(organization_id).await? as usize >= limit)
}
