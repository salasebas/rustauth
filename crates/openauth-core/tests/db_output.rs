use indexmap::IndexMap;
use openauth_core::db::{filter_output_fields, DbField, DbFieldType};

#[test]
fn filter_output_fields_removes_hidden_fields() {
    let mut data = IndexMap::new();
    data.insert("id".to_owned(), "account-id".to_owned());
    data.insert("access_token".to_owned(), "secret-access-token".to_owned());

    let mut fields = IndexMap::new();
    fields.insert("id".to_owned(), DbField::new("id", DbFieldType::String));
    fields.insert(
        "access_token".to_owned(),
        DbField::new("access_token", DbFieldType::String).hidden(),
    );

    let filtered = filter_output_fields(&data, &fields);

    assert_eq!(filtered.get("id").map(String::as_str), Some("account-id"));
    assert!(!filtered.contains_key("access_token"));
}

#[test]
fn filter_output_fields_keeps_unknown_fields() {
    let mut data = IndexMap::new();
    data.insert("custom".to_owned(), "value".to_owned());

    let filtered = filter_output_fields(&data, &IndexMap::new());

    assert_eq!(filtered.get("custom").map(String::as_str), Some("value"));
}
