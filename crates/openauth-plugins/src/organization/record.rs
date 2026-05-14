use openauth_core::db::{DbRecord, DbValue};
use openauth_core::error::OpenAuthError;

use super::models::{
    optional_json, optional_string, optional_timestamp, required_string, required_timestamp,
    Invitation, InvitationStatus, Member, Organization,
};

pub fn organization_from_record(record: &DbRecord) -> Result<Organization, OpenAuthError> {
    Ok(Organization {
        id: required_string(record, "id")?,
        name: required_string(record, "name")?,
        slug: required_string(record, "slug")?,
        logo: optional_string(record, "logo")?,
        metadata: optional_json(record, "metadata")?,
        created_at: required_timestamp(record, "created_at")?,
        updated_at: optional_timestamp(record, "updated_at")?,
    })
}

pub fn member_from_record(record: &DbRecord) -> Result<Member, OpenAuthError> {
    Ok(Member {
        id: required_string(record, "id")?,
        organization_id: required_string(record, "organization_id")?,
        user_id: required_string(record, "user_id")?,
        role: required_string(record, "role")?,
        created_at: required_timestamp(record, "created_at")?,
    })
}

pub fn invitation_from_record(record: &DbRecord) -> Result<Invitation, OpenAuthError> {
    let status = required_string(record, "status")?;
    Ok(Invitation {
        id: required_string(record, "id")?,
        organization_id: required_string(record, "organization_id")?,
        email: required_string(record, "email")?,
        role: required_string(record, "role")?,
        status: InvitationStatus::try_from(status.as_str())?,
        expires_at: required_timestamp(record, "expires_at")?,
        created_at: required_timestamp(record, "created_at")?,
        inviter_id: required_string(record, "inviter_id")?,
    })
}

pub fn user_from_record(record: &DbRecord) -> Result<openauth_core::db::User, OpenAuthError> {
    Ok(openauth_core::db::User {
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
