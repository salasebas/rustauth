use openauth_stripe::metadata::{CustomerMetadata, SubscriptionMetadata};
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
fn metadata_drops_prototype_pollution_keys() {
    let metadata = SubscriptionMetadata::new("user-1", "sub-1", "ref-1")
        .merge_user_metadata(json!({
            "__proto__": {"polluted": "yes"},
            "constructor": {"prototype": {"polluted": "yes"}},
            "prototype": "bad",
            "safe": "ok"
        }))
        .into_map();

    assert!(!metadata.contains_key("__proto__"));
    assert!(!metadata.contains_key("constructor"));
    assert!(!metadata.contains_key("prototype"));
    assert_eq!(metadata.get("safe").map(String::as_str), Some("ok"));
}

#[test]
fn subscription_metadata_extracts_internal_fields() {
    let metadata = SubscriptionMetadata::new("user-1", "sub-1", "ref-1").into_map();
    let extracted = SubscriptionMetadata::get(&metadata);

    assert_eq!(extracted.user_id.as_deref(), Some("user-1"));
    assert_eq!(extracted.subscription_id.as_deref(), Some("sub-1"));
    assert_eq!(extracted.reference_id.as_deref(), Some("ref-1"));
}
