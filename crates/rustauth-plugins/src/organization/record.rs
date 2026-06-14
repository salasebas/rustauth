use rustauth_core::db::{DbRecord, DbValue};
use rustauth_core::error::RustAuthError;

use super::models::{
    optional_json, optional_string, optional_timestamp, required_string, required_timestamp,
    Invitation, InvitationStatus, Member, Organization, OrganizationRoleRecord, Team, TeamMember,
};

pub fn organization_from_record(record: &DbRecord) -> Result<Organization, RustAuthError> {
    Ok(Organization {
        id: required_string(record, "id")?,
        name: required_string(record, "name")?,
        slug: required_string(record, "slug")?,
        logo: optional_string(record, "logo")?,
        metadata: optional_json(record, "metadata")?,
        created_at: required_timestamp(record, "created_at")?,
        updated_at: optional_timestamp(record, "updated_at")?,
        additional_fields: crate::organization::additional_fields::extract_record_fields(
            record,
            &[
                "id",
                "name",
                "slug",
                "logo",
                "metadata",
                "created_at",
                "updated_at",
            ],
        )?,
    })
}

pub fn member_from_record(record: &DbRecord) -> Result<Member, RustAuthError> {
    Ok(Member {
        id: required_string(record, "id")?,
        organization_id: required_string(record, "organization_id")?,
        user_id: required_string(record, "user_id")?,
        role: required_string(record, "role")?,
        created_at: required_timestamp(record, "created_at")?,
        additional_fields: crate::organization::additional_fields::extract_record_fields(
            record,
            &["id", "organization_id", "user_id", "role", "created_at"],
        )?,
    })
}

pub fn invitation_from_record(record: &DbRecord) -> Result<Invitation, RustAuthError> {
    let status = required_string(record, "status")?;
    Ok(Invitation {
        id: required_string(record, "id")?,
        organization_id: required_string(record, "organization_id")?,
        email: required_string(record, "email")?,
        role: required_string(record, "role")?,
        status: InvitationStatus::try_from(status.as_str())?,
        team_id: optional_string(record, "team_id")?,
        expires_at: required_timestamp(record, "expires_at")?,
        created_at: required_timestamp(record, "created_at")?,
        inviter_id: required_string(record, "inviter_id")?,
        additional_fields: crate::organization::additional_fields::extract_record_fields(
            record,
            &[
                "id",
                "organization_id",
                "email",
                "role",
                "status",
                "team_id",
                "expires_at",
                "created_at",
                "inviter_id",
            ],
        )?,
    })
}

pub fn team_from_record(record: &DbRecord) -> Result<Team, RustAuthError> {
    Ok(Team {
        id: required_string(record, "id")?,
        name: required_string(record, "name")?,
        organization_id: required_string(record, "organization_id")?,
        created_at: required_timestamp(record, "created_at")?,
        updated_at: optional_timestamp(record, "updated_at")?,
        additional_fields: crate::organization::additional_fields::extract_record_fields(
            record,
            &["id", "name", "organization_id", "created_at", "updated_at"],
        )?,
    })
}

pub fn team_member_from_record(record: &DbRecord) -> Result<TeamMember, RustAuthError> {
    Ok(TeamMember {
        id: required_string(record, "id")?,
        team_id: required_string(record, "team_id")?,
        user_id: required_string(record, "user_id")?,
        created_at: required_timestamp(record, "created_at")?,
        additional_fields: crate::organization::additional_fields::extract_record_fields(
            record,
            &["id", "team_id", "user_id", "created_at"],
        )?,
    })
}

pub fn organization_role_from_record(
    record: &DbRecord,
) -> Result<OrganizationRoleRecord, RustAuthError> {
    Ok(OrganizationRoleRecord {
        id: required_string(record, "id")?,
        organization_id: required_string(record, "organization_id")?,
        role: required_string(record, "role")?,
        permission: optional_json(record, "permission")?.unwrap_or(serde_json::Value::Null),
        created_at: required_timestamp(record, "created_at")?,
        updated_at: optional_timestamp(record, "updated_at")?,
        additional_fields: crate::organization::additional_fields::extract_record_fields(
            record,
            &[
                "id",
                "organization_id",
                "role",
                "permission",
                "created_at",
                "updated_at",
            ],
        )?,
    })
}

pub fn user_from_record(record: &DbRecord) -> Result<rustauth_core::db::User, RustAuthError> {
    Ok(rustauth_core::db::User {
        id: required_string(record, "id")?,
        name: required_string(record, "name")?,
        email: required_string(record, "email")?,
        email_verified: match record.get("email_verified") {
            Some(DbValue::Boolean(value)) => *value,
            _ => false,
        },
        image: optional_string(record, "image")?,
        username: optional_string(record, "username")?,
        display_username: optional_string(record, "display_username")?,
        created_at: required_timestamp(record, "created_at")?,
        updated_at: required_timestamp(record, "updated_at")?,
    })
}
