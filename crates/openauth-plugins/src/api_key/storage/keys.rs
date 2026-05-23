use std::cmp::Ordering;

use crate::api_key::models::ApiKeyRecord;

pub(super) fn storage_key_by_hash(hashed_key: &str) -> String {
    format!("api-key:{hashed_key}")
}

pub(super) fn storage_key_by_id(id: &str) -> String {
    format!("api-key:by-id:{id}")
}

pub(super) fn storage_key_by_reference(reference_id: &str) -> String {
    format!("api-key:by-ref:{reference_id}")
}

pub(super) fn compare_api_keys(left: &ApiKeyRecord, right: &ApiKeyRecord, field: &str) -> Ordering {
    match field {
        "createdAt" | "created_at" => left.created_at.cmp(&right.created_at),
        "updatedAt" | "updated_at" => left.updated_at.cmp(&right.updated_at),
        "name" => left.name.cmp(&right.name),
        "expiresAt" | "expires_at" => left.expires_at.cmp(&right.expires_at),
        _ => left.id.cmp(&right.id),
    }
}
