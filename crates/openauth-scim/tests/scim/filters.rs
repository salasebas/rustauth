use openauth_scim::filters::{parse_user_filter, ScimFilterOperator};

#[test]
fn parses_user_name_eq_filter_case_insensitively() {
    let filters = parse_user_filter(r#"userName eq "User-A""#).expect("filter should parse");

    assert_eq!(filters.len(), 1);
    assert_eq!(filters[0].field, "email");
    assert_eq!(filters[0].value, "user-a");
    assert_eq!(filters[0].operator, ScimFilterOperator::Eq);
}

#[test]
fn rejects_unsupported_filter_operator_with_invalid_filter_type() {
    let error = parse_user_filter(r#"userName co "user""#).expect_err("operator must fail");

    assert_eq!(error.status, http::StatusCode::BAD_REQUEST);
    assert_eq!(error.scim_type.as_deref(), Some("invalidFilter"));
    assert_eq!(
        error.detail.as_deref(),
        Some(r#"The operator "co" is not supported"#)
    );
}

#[test]
fn rejects_unsupported_filter_attribute() {
    let error = parse_user_filter(r#"displayName eq "Ada""#).expect_err("attribute must fail");

    assert_eq!(error.scim_type.as_deref(), Some("invalidFilter"));
    assert_eq!(
        error.detail.as_deref(),
        Some(r#"The attribute "displayName" is not supported"#)
    );
}
