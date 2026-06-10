//! Organization plugin.

mod additional_fields;
mod errors;
mod hooks;
mod http;
mod limits;
mod models;
mod options;
mod permissions;
mod provisioning;
mod record;
mod routes;
mod schema;
mod store;

pub use errors::ORGANIZATION_ERROR_CODES;
pub use hooks::{
    AfterAcceptInvitation, AfterAddMember, AfterAddTeamMember, AfterCancelInvitation,
    AfterCreateInvitation, AfterCreateOrganization, AfterCreateTeam, AfterDeleteOrganization,
    AfterDeleteTeam, AfterRejectInvitation, AfterRemoveMember, AfterRemoveTeamMember,
    AfterUpdateMemberRole, AfterUpdateOrganization, AfterUpdateTeam, BeforeAcceptInvitation,
    BeforeAddMember, BeforeAddTeamMember, BeforeCancelInvitation, BeforeCreateInvitation,
    BeforeCreateOrganization, BeforeCreateTeam, BeforeDeleteOrganization, BeforeDeleteTeam,
    BeforeRejectInvitation, BeforeRemoveMember, BeforeRemoveTeamMember, BeforeUpdateMemberRole,
    BeforeUpdateOrganization, BeforeUpdateTeam, InvitationHookData, MemberHookData,
    MemberRoleUpdateData, OrganizationHookData, OrganizationHooks, OrganizationUpdateData,
    TeamHookData, TeamMemberHookData,
};
pub use limits::{
    MembershipLimit, MembershipLimitCallback, OrganizationLimit, OrganizationLimitCallback,
};
pub use models::{
    Invitation, InvitationStatus, Member, Organization, OrganizationRoleRecord, Team, TeamMember,
};
pub use options::{
    CustomCreateDefaultTeamHook, DefaultTeamSpec, DynamicAccessControlOptions, InvitationEmail,
    OrganizationOptions, OrganizationOptionsBuilder, OrganizationSchemaOptions,
    SendInvitationEmailHook, TeamOptions,
};
pub use permissions::{has_permission, OrganizationPermission, OrganizationRole};
pub use provisioning::{provision_organization_member, ProvisionOrganizationMemberInput};

use openauth_core::db::{DbFieldType, DbValue};
use openauth_core::options::SessionAdditionalField;
use openauth_core::plugin::{AuthPlugin, PluginInitOutput};

pub mod access;

pub const UPSTREAM_PLUGIN_ID: &str = "organization";

#[must_use]
pub fn organization() -> AuthPlugin {
    organization_with(OrganizationOptions::default())
}

#[must_use]
pub fn organization_with(options: OrganizationOptions) -> AuthPlugin {
    let mut plugin = AuthPlugin::new(UPSTREAM_PLUGIN_ID)
        .with_version(env!("CARGO_PKG_VERSION"))
        .with_options(options.to_metadata())
        .with_state(options.clone());

    for contribution in schema::schema_contributions(&options) {
        plugin = plugin.with_schema(contribution);
    }
    for error_code in errors::error_codes() {
        plugin = plugin.with_error_code(error_code);
    }
    for endpoint in routes::endpoints(options.clone()) {
        plugin = plugin.with_endpoint(endpoint);
    }
    plugin.with_init(move |_context| {
        let mut output = PluginInitOutput::new().session_additional_field(
            "activeOrganizationId",
            SessionAdditionalField::new(DbFieldType::String)
                .optional()
                .generated()
                .db_name("active_organization_id")
                .default_value(DbValue::Null),
        );
        if options.teams.enabled {
            output = output.session_additional_field(
                "activeTeamId",
                SessionAdditionalField::new(DbFieldType::String)
                    .optional()
                    .generated()
                    .db_name("active_team_id")
                    .default_value(DbValue::Null),
            );
        }
        Ok(output)
    })
}

pub fn organization_options_from_context(
    context: &openauth_core::context::AuthContext,
) -> Option<std::sync::Arc<OrganizationOptions>> {
    context
        .plugins
        .iter()
        .find(|plugin| plugin.id == UPSTREAM_PLUGIN_ID)
        .and_then(|plugin| plugin.state::<OrganizationOptions>())
}
