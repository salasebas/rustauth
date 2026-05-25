use std::collections::BTreeMap;

use serde_json::Value;

const USER_ID: &str = "userId";
const ORGANIZATION_ID: &str = "organizationId";
const CUSTOMER_TYPE: &str = "customerType";
const SUBSCRIPTION_ID: &str = "subscriptionId";
const REFERENCE_ID: &str = "referenceId";

const UNSAFE_KEYS: &[&str] = &["__proto__", "constructor", "prototype"];

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
            if UNSAFE_KEYS.contains(&key.as_str()) {
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
