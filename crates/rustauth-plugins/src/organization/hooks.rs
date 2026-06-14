//! Organization hook callbacks.

use std::sync::Arc;

use rustauth_core::db::User;
use rustauth_core::error::RustAuthError;

use time::OffsetDateTime;

use super::{Invitation, Member, Organization, Team, TeamMember};

#[derive(Clone, Default)]
pub struct OrganizationHooks {
    pub before_create_organization: Option<BeforeCreateOrganizationHook>,
    pub after_create_organization: Option<AfterCreateOrganizationHook>,
    pub before_update_organization: Option<BeforeUpdateOrganizationHook>,
    pub after_update_organization: Option<AfterUpdateOrganizationHook>,
    pub before_delete_organization: Option<BeforeDeleteOrganizationHook>,
    pub after_delete_organization: Option<AfterDeleteOrganizationHook>,
    pub before_add_member: Option<BeforeAddMemberHook>,
    pub after_add_member: Option<AfterAddMemberHook>,
    pub before_remove_member: Option<BeforeRemoveMemberHook>,
    pub after_remove_member: Option<AfterRemoveMemberHook>,
    pub before_update_member_role: Option<BeforeUpdateMemberRoleHook>,
    pub after_update_member_role: Option<AfterUpdateMemberRoleHook>,
    pub before_create_invitation: Option<BeforeCreateInvitationHook>,
    pub after_create_invitation: Option<AfterCreateInvitationHook>,
    pub before_accept_invitation: Option<BeforeAcceptInvitationHook>,
    pub after_accept_invitation: Option<AfterAcceptInvitationHook>,
    pub before_reject_invitation: Option<BeforeRejectInvitationHook>,
    pub after_reject_invitation: Option<AfterRejectInvitationHook>,
    pub before_cancel_invitation: Option<BeforeCancelInvitationHook>,
    pub after_cancel_invitation: Option<AfterCancelInvitationHook>,
    pub before_create_team: Option<BeforeCreateTeamHook>,
    pub after_create_team: Option<AfterCreateTeamHook>,
    pub before_update_team: Option<BeforeUpdateTeamHook>,
    pub after_update_team: Option<AfterUpdateTeamHook>,
    pub before_delete_team: Option<BeforeDeleteTeamHook>,
    pub after_delete_team: Option<AfterDeleteTeamHook>,
    pub before_add_team_member: Option<BeforeAddTeamMemberHook>,
    pub after_add_team_member: Option<AfterAddTeamMemberHook>,
    pub before_remove_team_member: Option<BeforeRemoveTeamMemberHook>,
    pub after_remove_team_member: Option<AfterRemoveTeamMemberHook>,
}

pub type BeforeCreateOrganizationHook = Arc<
    dyn Fn(&BeforeCreateOrganization) -> Result<OrganizationHookData, RustAuthError> + Send + Sync,
>;
pub type AfterCreateOrganizationHook =
    Arc<dyn Fn(&AfterCreateOrganization) -> Result<(), RustAuthError> + Send + Sync>;
pub type BeforeUpdateOrganizationHook = Arc<
    dyn Fn(&BeforeUpdateOrganization) -> Result<OrganizationUpdateData, RustAuthError>
        + Send
        + Sync,
>;
pub type AfterUpdateOrganizationHook =
    Arc<dyn Fn(&AfterUpdateOrganization) -> Result<(), RustAuthError> + Send + Sync>;
pub type BeforeDeleteOrganizationHook =
    Arc<dyn Fn(&BeforeDeleteOrganization) -> Result<(), RustAuthError> + Send + Sync>;
pub type AfterDeleteOrganizationHook =
    Arc<dyn Fn(&AfterDeleteOrganization) -> Result<(), RustAuthError> + Send + Sync>;
pub type BeforeAddMemberHook =
    Arc<dyn Fn(&BeforeAddMember) -> Result<MemberHookData, RustAuthError> + Send + Sync>;
pub type AfterAddMemberHook =
    Arc<dyn Fn(&AfterAddMember) -> Result<(), RustAuthError> + Send + Sync>;
pub type BeforeRemoveMemberHook =
    Arc<dyn Fn(&BeforeRemoveMember) -> Result<(), RustAuthError> + Send + Sync>;
pub type AfterRemoveMemberHook =
    Arc<dyn Fn(&AfterRemoveMember) -> Result<(), RustAuthError> + Send + Sync>;
pub type BeforeUpdateMemberRoleHook = Arc<
    dyn Fn(&BeforeUpdateMemberRole) -> Result<MemberRoleUpdateData, RustAuthError> + Send + Sync,
>;
pub type AfterUpdateMemberRoleHook =
    Arc<dyn Fn(&AfterUpdateMemberRole) -> Result<(), RustAuthError> + Send + Sync>;
pub type BeforeCreateInvitationHook =
    Arc<dyn Fn(&BeforeCreateInvitation) -> Result<InvitationHookData, RustAuthError> + Send + Sync>;
pub type AfterCreateInvitationHook =
    Arc<dyn Fn(&AfterCreateInvitation) -> Result<(), RustAuthError> + Send + Sync>;
pub type BeforeAcceptInvitationHook =
    Arc<dyn Fn(&BeforeAcceptInvitation) -> Result<(), RustAuthError> + Send + Sync>;
pub type AfterAcceptInvitationHook =
    Arc<dyn Fn(&AfterAcceptInvitation) -> Result<(), RustAuthError> + Send + Sync>;
pub type BeforeRejectInvitationHook =
    Arc<dyn Fn(&BeforeRejectInvitation) -> Result<(), RustAuthError> + Send + Sync>;
pub type AfterRejectInvitationHook =
    Arc<dyn Fn(&AfterRejectInvitation) -> Result<(), RustAuthError> + Send + Sync>;
pub type BeforeCancelInvitationHook =
    Arc<dyn Fn(&BeforeCancelInvitation) -> Result<(), RustAuthError> + Send + Sync>;
pub type AfterCancelInvitationHook =
    Arc<dyn Fn(&AfterCancelInvitation) -> Result<(), RustAuthError> + Send + Sync>;
pub type BeforeCreateTeamHook =
    Arc<dyn Fn(&BeforeCreateTeam) -> Result<TeamHookData, RustAuthError> + Send + Sync>;
pub type AfterCreateTeamHook =
    Arc<dyn Fn(&AfterCreateTeam) -> Result<(), RustAuthError> + Send + Sync>;
pub type BeforeUpdateTeamHook =
    Arc<dyn Fn(&BeforeUpdateTeam) -> Result<TeamHookData, RustAuthError> + Send + Sync>;
pub type AfterUpdateTeamHook =
    Arc<dyn Fn(&AfterUpdateTeam) -> Result<(), RustAuthError> + Send + Sync>;
pub type BeforeDeleteTeamHook =
    Arc<dyn Fn(&BeforeDeleteTeam) -> Result<(), RustAuthError> + Send + Sync>;
pub type AfterDeleteTeamHook =
    Arc<dyn Fn(&AfterDeleteTeam) -> Result<(), RustAuthError> + Send + Sync>;
pub type BeforeAddTeamMemberHook =
    Arc<dyn Fn(&BeforeAddTeamMember) -> Result<TeamMemberHookData, RustAuthError> + Send + Sync>;
pub type AfterAddTeamMemberHook =
    Arc<dyn Fn(&AfterAddTeamMember) -> Result<(), RustAuthError> + Send + Sync>;
pub type BeforeRemoveTeamMemberHook =
    Arc<dyn Fn(&BeforeRemoveTeamMember) -> Result<(), RustAuthError> + Send + Sync>;
pub type AfterRemoveTeamMemberHook =
    Arc<dyn Fn(&AfterRemoveTeamMember) -> Result<(), RustAuthError> + Send + Sync>;

#[derive(Debug, Clone)]
pub struct BeforeCreateOrganization {
    pub organization: OrganizationHookData,
    pub user: User,
}

#[derive(Debug, Clone)]
pub struct OrganizationHookData {
    pub name: String,
    pub slug: String,
}

#[derive(Debug, Clone)]
pub struct AfterCreateOrganization {
    pub organization: Organization,
    pub member: Member,
    pub user: User,
}

#[derive(Debug, Clone, Default)]
pub struct OrganizationUpdateData {
    pub name: Option<String>,
    pub slug: Option<String>,
    pub logo: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct BeforeUpdateOrganization {
    pub organization: Organization,
    pub user: User,
    pub data: OrganizationUpdateData,
}

#[derive(Debug, Clone)]
pub struct AfterUpdateOrganization {
    pub organization: Organization,
    pub user: User,
}

#[derive(Debug, Clone)]
pub struct BeforeDeleteOrganization {
    pub organization: Organization,
    pub user: User,
}

#[derive(Debug, Clone)]
pub struct AfterDeleteOrganization {
    pub organization: Organization,
    pub user: User,
}

#[derive(Debug, Clone)]
pub struct BeforeAddMember {
    pub organization: Organization,
    pub user: User,
    pub member: MemberHookData,
}

#[derive(Debug, Clone)]
pub struct MemberHookData {
    pub organization_id: String,
    pub user_id: String,
    pub role: String,
}

#[derive(Debug, Clone)]
pub struct AfterAddMember {
    pub organization: Organization,
    pub member: Member,
    pub user: User,
}

#[derive(Debug, Clone)]
pub struct BeforeRemoveMember {
    pub organization: Organization,
    pub member: Member,
    pub user: User,
}

#[derive(Debug, Clone)]
pub struct AfterRemoveMember {
    pub organization: Organization,
    pub member: Member,
    pub user: User,
}

#[derive(Debug, Clone)]
pub struct MemberRoleUpdateData {
    pub role: String,
}

#[derive(Debug, Clone)]
pub struct BeforeUpdateMemberRole {
    pub organization: Organization,
    pub member: Member,
    pub new_role: String,
    pub user: User,
}

#[derive(Debug, Clone)]
pub struct AfterUpdateMemberRole {
    pub organization: Organization,
    pub member: Member,
    pub previous_role: String,
    pub user: User,
}

#[derive(Debug, Clone)]
pub struct InvitationHookData {
    pub organization_id: String,
    pub email: String,
    pub role: String,
    pub team_id: Option<String>,
    pub inviter_id: String,
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct BeforeCreateInvitation {
    pub organization: Organization,
    pub inviter: User,
    pub invitation: InvitationHookData,
}

#[derive(Debug, Clone)]
pub struct AfterCreateInvitation {
    pub organization: Organization,
    pub inviter: User,
    pub invitation: Invitation,
}

#[derive(Debug, Clone)]
pub struct BeforeAcceptInvitation {
    pub organization: Organization,
    pub invitation: Invitation,
    pub user: User,
}

#[derive(Debug, Clone)]
pub struct AfterAcceptInvitation {
    pub organization: Organization,
    pub invitation: Invitation,
    pub member: Member,
    pub user: User,
}

#[derive(Debug, Clone)]
pub struct BeforeRejectInvitation {
    pub organization: Organization,
    pub invitation: Invitation,
    pub user: User,
}

#[derive(Debug, Clone)]
pub struct AfterRejectInvitation {
    pub organization: Organization,
    pub invitation: Invitation,
    pub user: User,
}

#[derive(Debug, Clone)]
pub struct BeforeCancelInvitation {
    pub organization: Organization,
    pub invitation: Invitation,
    pub cancelled_by: User,
}

#[derive(Debug, Clone)]
pub struct AfterCancelInvitation {
    pub organization: Organization,
    pub invitation: Invitation,
    pub cancelled_by: User,
}

#[derive(Debug, Clone)]
pub struct TeamHookData {
    pub organization_id: String,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct BeforeCreateTeam {
    pub organization: Organization,
    pub team: TeamHookData,
    pub user: User,
}

#[derive(Debug, Clone)]
pub struct AfterCreateTeam {
    pub organization: Organization,
    pub team: Team,
    pub user: User,
}

#[derive(Debug, Clone)]
pub struct BeforeUpdateTeam {
    pub organization: Organization,
    pub team: Team,
    pub updates: TeamHookData,
    pub user: User,
}

#[derive(Debug, Clone)]
pub struct AfterUpdateTeam {
    pub organization: Organization,
    pub team: Option<Team>,
    pub user: User,
}

#[derive(Debug, Clone)]
pub struct BeforeDeleteTeam {
    pub organization: Organization,
    pub team: Team,
    pub user: User,
}

#[derive(Debug, Clone)]
pub struct AfterDeleteTeam {
    pub organization: Organization,
    pub team: Team,
    pub user: User,
}

#[derive(Debug, Clone)]
pub struct TeamMemberHookData {
    pub team_id: String,
    pub user_id: String,
}

#[derive(Debug, Clone)]
pub struct BeforeAddTeamMember {
    pub organization: Organization,
    pub team: Team,
    pub team_member: TeamMemberHookData,
    pub user: User,
}

#[derive(Debug, Clone)]
pub struct AfterAddTeamMember {
    pub organization: Organization,
    pub team: Team,
    pub team_member: TeamMember,
    pub user: User,
}

#[derive(Debug, Clone)]
pub struct BeforeRemoveTeamMember {
    pub organization: Organization,
    pub team: Team,
    pub team_member: TeamMember,
    pub user: User,
}

#[derive(Debug, Clone)]
pub struct AfterRemoveTeamMember {
    pub organization: Organization,
    pub team: Team,
    pub team_member: TeamMember,
    pub user: User,
}
