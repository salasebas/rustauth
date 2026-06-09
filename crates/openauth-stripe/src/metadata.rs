use std::collections::BTreeMap;

use serde_json::Value;

const USER_ID: &str = "userId";
const ORGANIZATION_ID: &str = "organizationId";
const CUSTOMER_TYPE: &str = "customerType";
const SUBSCRIPTION_ID: &str = "subscriptionId";
const REFERENCE_ID: &str = "referenceId";
const STRIPE_CUSTOMER_ID: &str = "stripeCustomerId";
const STRIPE_CUSTOMER_ID_SNAKE: &str = "stripe_customer_id";

const UNSAFE_KEYS: &[&str] = &["__proto__", "constructor", "prototype"];
/// Keys that must never be accepted from client-supplied metadata (server/Stripe only).
const USER_METADATA_DENYLIST: &[&str] = &[STRIPE_CUSTOMER_ID, STRIPE_CUSTOMER_ID_SNAKE];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomerMetadata {
    inner: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedCustomerMetadata {
    pub user_id: Option<String>,
    pub organization_id: Option<String>,
    pub customer_type: Option<String>,
}

impl CustomerMetadata {
    pub fn user(user_id: impl Into<String>) -> Self {
        let mut inner = BTreeMap::new();
        inner.insert(USER_ID.to_owned(), user_id.into());
        inner.insert(CUSTOMER_TYPE.to_owned(), "user".to_owned());
        Self { inner }
    }

    pub fn organization(organization_id: impl Into<String>) -> Self {
        let mut inner = BTreeMap::new();
        inner.insert(ORGANIZATION_ID.to_owned(), organization_id.into());
        inner.insert(CUSTOMER_TYPE.to_owned(), "organization".to_owned());
        Self { inner }
    }

    pub fn merge_user_metadata(mut self, metadata: Value) -> Self {
        merge_user_metadata(&mut self.inner, metadata);
        self
    }

    pub fn into_map(self) -> BTreeMap<String, String> {
        self.inner
    }

    #[allow(dead_code)]
    pub fn get(metadata: &BTreeMap<String, String>) -> ExtractedCustomerMetadata {
        ExtractedCustomerMetadata {
            user_id: metadata.get(USER_ID).cloned(),
            organization_id: metadata.get(ORGANIZATION_ID).cloned(),
            customer_type: metadata.get(CUSTOMER_TYPE).cloned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionMetadata {
    inner: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedSubscriptionMetadata {
    pub user_id: Option<String>,
    pub subscription_id: Option<String>,
    pub reference_id: Option<String>,
}

impl SubscriptionMetadata {
    pub fn new(
        user_id: impl Into<String>,
        subscription_id: impl Into<String>,
        reference_id: impl Into<String>,
    ) -> Self {
        let mut inner = BTreeMap::new();
        inner.insert(USER_ID.to_owned(), user_id.into());
        inner.insert(SUBSCRIPTION_ID.to_owned(), subscription_id.into());
        inner.insert(REFERENCE_ID.to_owned(), reference_id.into());
        Self { inner }
    }

    pub fn merge_user_metadata(mut self, metadata: Value) -> Self {
        merge_user_metadata(&mut self.inner, metadata);
        self
    }

    pub fn into_map(self) -> BTreeMap<String, String> {
        self.inner
    }

    pub fn get(metadata: &BTreeMap<String, String>) -> ExtractedSubscriptionMetadata {
        ExtractedSubscriptionMetadata {
            user_id: metadata.get(USER_ID).cloned(),
            subscription_id: metadata.get(SUBSCRIPTION_ID).cloned(),
            reference_id: metadata.get(REFERENCE_ID).cloned(),
        }
    }
}

fn merge_user_metadata(target: &mut BTreeMap<String, String>, metadata: Value) {
    let protected = target.clone();
    if let Value::Object(object) = metadata {
        for (key, value) in object {
            if UNSAFE_KEYS.contains(&key.as_str()) || USER_METADATA_DENYLIST.contains(&key.as_str())
            {
                continue;
            }
            if let Some(value) = metadata_value_to_string(value) {
                target.insert(key, value);
            }
        }
    }
    for (key, value) in protected {
        target.insert(key, value);
    }
}

fn metadata_value_to_string(value: Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn customer_metadata_internal_fields_take_precedence() {
        let metadata = CustomerMetadata::user("real-user")
            .merge_user_metadata(json!({
                "userId": "spoofed",
                "customerType": "organization",
                "plan": "pro"
            }))
            .into_map();

        assert_eq!(
            metadata.get("userId").map(String::as_str),
            Some("real-user")
        );
        assert_eq!(
            metadata.get("customerType").map(String::as_str),
            Some("user")
        );
        assert_eq!(metadata.get("plan").map(String::as_str), Some("pro"));
    }

    #[test]
    fn customer_metadata_get_extracts_internal_fields() {
        let metadata = CustomerMetadata::user("real-user").into_map();
        let extracted = CustomerMetadata::get(&metadata);
        assert_eq!(extracted.user_id.as_deref(), Some("real-user"));
        assert_eq!(extracted.customer_type.as_deref(), Some("user"));
    }

    #[test]
    fn subscription_metadata_internal_fields_take_precedence() {
        let metadata = SubscriptionMetadata::new("user_1", "sub_1", "ref_1")
            .merge_user_metadata(json!({
                "userId": "spoofed",
                "subscriptionId": "spoofed_sub",
                "referenceId": "spoofed_ref"
            }))
            .into_map();

        assert_eq!(metadata.get("userId").map(String::as_str), Some("user_1"));
        assert_eq!(
            metadata.get("subscriptionId").map(String::as_str),
            Some("sub_1")
        );
        assert_eq!(
            metadata.get("referenceId").map(String::as_str),
            Some("ref_1")
        );
    }
}
