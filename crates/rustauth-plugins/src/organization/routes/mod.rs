mod input;
mod invitation_actions;
mod invitation_queries;
mod invitations;
mod member_queries;
mod members;
mod members_leave;
mod metadata;
mod org;
mod org_queries;
mod permissions;
mod roles;
mod session;
mod team_members;
mod team_queries;
mod teams;
mod validation;

use rustauth_core::api::AsyncAuthEndpoint;

use super::options::OrganizationOptions;

pub fn endpoints(options: OrganizationOptions) -> Vec<AsyncAuthEndpoint> {
    let mut endpoints = Vec::new();
    endpoints.extend(org::endpoints(options.clone()));
    endpoints.extend(org_queries::endpoints(options.clone()));
    endpoints.extend(members::endpoints(options.clone()));
    endpoints.extend(member_queries::endpoints(options.clone()));
    endpoints.extend(invitations::endpoints(options.clone()));
    endpoints.extend(invitation_queries::endpoints(options.clone()));
    endpoints.extend(permissions::endpoints(options.clone()));
    endpoints.push(session::set_active());
    endpoints.extend(teams::endpoints(options.clone()));
    endpoints.extend(team_queries::endpoints(options.clone()));
    endpoints.extend(roles::endpoints(options));
    endpoints
}

fn resolve_organization_id(explicit: Option<String>, active: Option<&str>) -> Option<String> {
    explicit.or_else(|| active.map(str::to_owned))
}
