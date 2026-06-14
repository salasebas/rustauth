use rustauth_core::db::TableOptions;
use rustauth_core::outbound::OutboundSendFuture;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use time::Duration;

use crate::access::{AccessControl, Role};

use super::hooks::OrganizationHooks;
use super::limits::{MembershipLimit, OrganizationLimit};
use super::{Invitation, Member, Organization};

pub type SendInvitationEmailHook = Arc<dyn Fn(InvitationEmail) -> OutboundSendFuture + Send + Sync>;

pub type CustomCreateDefaultTeamFuture = std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = Result<DefaultTeamSpec, rustauth_core::error::RustAuthError>,
            > + Send,
    >,
>;
pub type CustomCreateDefaultTeamHook =
    Arc<dyn Fn(Organization) -> CustomCreateDefaultTeamFuture + Send + Sync>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DefaultTeamSpec {
    pub name: String,
}

#[derive(Clone)]
pub struct OrganizationOptions {
    pub allow_user_to_create_organization: bool,
    pub organization_limit: Option<OrganizationLimit>,
    pub creator_role: String,
    pub membership_limit: MembershipLimit,
    pub invitation_expires_in: Duration,
    pub invitation_limit: usize,
    pub cancel_pending_invitations_on_re_invite: bool,
    pub require_email_verification_on_invitation: bool,
    pub disable_organization_deletion: bool,
    pub hooks: OrganizationHooks,
    pub send_invitation_email: Option<SendInvitationEmailHook>,
    pub teams: TeamOptions,
    pub dynamic_access_control: DynamicAccessControlOptions,
    pub access_control: Option<AccessControl>,
    pub roles: Option<BTreeMap<String, Role>>,
    pub custom_roles: BTreeMap<String, serde_json::Value>,
    pub schema: OrganizationSchemaOptions,
}

#[derive(Clone)]
pub struct TeamOptions {
    pub enabled: bool,
    pub create_default_team: bool,
    pub custom_create_default_team: Option<CustomCreateDefaultTeamHook>,
    pub maximum_teams: Option<usize>,
    pub maximum_members_per_team: Option<usize>,
    pub allow_removing_all_teams: bool,
}

impl std::fmt::Debug for TeamOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TeamOptions")
            .field("enabled", &self.enabled)
            .field("create_default_team", &self.create_default_team)
            .field(
                "custom_create_default_team",
                &self
                    .custom_create_default_team
                    .as_ref()
                    .map(|_| "<custom-create-default-team>"),
            )
            .field("maximum_teams", &self.maximum_teams)
            .field("maximum_members_per_team", &self.maximum_members_per_team)
            .field("allow_removing_all_teams", &self.allow_removing_all_teams)
            .finish()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DynamicAccessControlOptions {
    pub enabled: bool,
    pub maximum_roles_per_organization: Option<usize>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OrganizationSchemaOptions {
    pub organization: TableOptions,
    pub member: TableOptions,
    pub invitation: TableOptions,
    pub team: TableOptions,
    pub team_member: TableOptions,
    pub organization_role: TableOptions,
}

#[derive(Debug, Clone)]
pub struct InvitationEmail {
    pub id: String,
    pub role: String,
    pub email: String,
    pub organization: Organization,
    pub invitation: Invitation,
    pub inviter: Member,
}

impl Default for OrganizationOptions {
    fn default() -> Self {
        Self {
            allow_user_to_create_organization: true,
            organization_limit: None,
            creator_role: "owner".to_owned(),
            membership_limit: MembershipLimit::default(),
            invitation_expires_in: Duration::hours(48),
            invitation_limit: 100,
            cancel_pending_invitations_on_re_invite: false,
            require_email_verification_on_invitation: false,
            disable_organization_deletion: false,
            hooks: OrganizationHooks::default(),
            send_invitation_email: None,
            teams: TeamOptions::default(),
            dynamic_access_control: DynamicAccessControlOptions::default(),
            access_control: None,
            roles: None,
            custom_roles: BTreeMap::new(),
            schema: OrganizationSchemaOptions::default(),
        }
    }
}

impl Default for TeamOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            create_default_team: true,
            custom_create_default_team: None,
            maximum_teams: None,
            maximum_members_per_team: None,
            allow_removing_all_teams: false,
        }
    }
}

impl OrganizationOptions {
    pub fn builder() -> OrganizationOptionsBuilder {
        OrganizationOptionsBuilder::default()
    }

    pub(crate) fn to_metadata(&self) -> Value {
        json!({
            "allowUserToCreateOrganization": self.allow_user_to_create_organization,
            "organizationLimit": self.organization_limit.as_ref().map(|_| "<organization-limit>"),
            "creatorRole": self.creator_role,
            "membershipLimit": match &self.membership_limit {
                MembershipLimit::Fixed(limit) => json!(limit),
                MembershipLimit::Dynamic(_) => json!("<membership-limit>"),
            },
            "invitationExpiresIn": self.invitation_expires_in.whole_seconds(),
            "invitationLimit": self.invitation_limit,
            "cancelPendingInvitationsOnReInvite": self.cancel_pending_invitations_on_re_invite,
            "requireEmailVerificationOnInvitation": self.require_email_verification_on_invitation,
            "disableOrganizationDeletion": self.disable_organization_deletion,
            "teams": {
                "enabled": self.teams.enabled,
                "defaultTeam": {
                    "enabled": self.teams.create_default_team,
                    "customCreateDefaultTeam": self.teams.custom_create_default_team.is_some(),
                },
                "maximumTeams": self.teams.maximum_teams,
                "maximumMembersPerTeam": self.teams.maximum_members_per_team,
                "allowRemovingAllTeams": self.teams.allow_removing_all_teams,
            },
            "dynamicAccessControl": {
                "enabled": self.dynamic_access_control.enabled,
                "maximumRolesPerOrganization": self.dynamic_access_control.maximum_roles_per_organization,
            },
            "ac": self.access_control.is_some(),
            "roles": self.roles.as_ref().map(|roles| roles.keys().collect::<Vec<_>>()),
            "customRoles": self.custom_roles,
        })
    }
}

#[derive(Clone, Default)]
pub struct OrganizationOptionsBuilder {
    options: OrganizationOptions,
}

impl OrganizationOptionsBuilder {
    pub fn allow_user_to_create_organization(mut self, allow: bool) -> Self {
        self.options.allow_user_to_create_organization = allow;
        self
    }

    pub fn organization_limit(mut self, limit: usize) -> Self {
        self.options.organization_limit = Some(OrganizationLimit::Fixed(limit));
        self
    }

    pub fn organization_limit_dynamic(
        mut self,
        callback: super::limits::OrganizationLimitCallback,
    ) -> Self {
        self.options.organization_limit = Some(OrganizationLimit::Dynamic(callback));
        self
    }

    pub fn creator_role(mut self, role: impl Into<String>) -> Self {
        self.options.creator_role = role.into();
        self
    }

    pub fn membership_limit(mut self, limit: usize) -> Self {
        self.options.membership_limit = MembershipLimit::Fixed(limit);
        self
    }

    pub fn membership_limit_dynamic(
        mut self,
        callback: super::limits::MembershipLimitCallback,
    ) -> Self {
        self.options.membership_limit = MembershipLimit::Dynamic(callback);
        self
    }

    pub fn invitation_expires_in(mut self, expires_in: Duration) -> Self {
        self.options.invitation_expires_in = expires_in;
        self
    }

    pub fn invitation_limit(mut self, limit: usize) -> Self {
        self.options.invitation_limit = limit;
        self
    }

    pub fn cancel_pending_invitations_on_re_invite(mut self, cancel: bool) -> Self {
        self.options.cancel_pending_invitations_on_re_invite = cancel;
        self
    }

    pub fn require_email_verification_on_invitation(mut self, require: bool) -> Self {
        self.options.require_email_verification_on_invitation = require;
        self
    }

    pub fn disable_organization_deletion(mut self, disable: bool) -> Self {
        self.options.disable_organization_deletion = disable;
        self
    }

    pub fn hooks(mut self, hooks: OrganizationHooks) -> Self {
        self.options.hooks = hooks;
        self
    }

    pub fn send_invitation_email(mut self, hook: SendInvitationEmailHook) -> Self {
        self.options.send_invitation_email = Some(hook);
        self
    }

    pub fn teams(mut self, teams: TeamOptions) -> Self {
        self.options.teams = teams;
        self
    }

    pub fn dynamic_access_control(mut self, options: DynamicAccessControlOptions) -> Self {
        self.options.dynamic_access_control = options;
        self
    }

    pub fn access_control(mut self, access_control: AccessControl) -> Self {
        self.options.access_control = Some(access_control);
        self
    }

    pub fn roles(mut self, roles: BTreeMap<String, Role>) -> Self {
        self.options.roles = Some(roles);
        self
    }

    pub fn custom_role(mut self, role: impl Into<String>, permissions: serde_json::Value) -> Self {
        self.options.custom_roles.insert(role.into(), permissions);
        self
    }

    pub fn schema(mut self, schema: OrganizationSchemaOptions) -> Self {
        self.options.schema = schema;
        self
    }

    pub fn build(self) -> OrganizationOptions {
        self.options
    }
}
