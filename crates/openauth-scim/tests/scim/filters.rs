use openauth_scim::filters::{
    list_user_filter_uses_database_pushdown, parse_filter, parse_user_filter,
    resource_matches_filter, ScimAttributePath, ScimCompareOperator, ScimFilterExpression,
    ScimFilterOperator,
};

#[test]
fn list_user_filter_pushdown_matches_upstream_user_name_eq_only() {
    assert!(list_user_filter_uses_database_pushdown(
        r#"userName eq "ada@example.com""#
    ));
    assert!(!list_user_filter_uses_database_pushdown(
        r#"userName co "ada""#
    ));
    assert!(!list_user_filter_uses_database_pushdown(
        r#"displayName eq "Ada""#
    ));
}

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

#[test]
fn parses_boolean_filter_precedence_and_parentheses() {
    let filter =
        parse_filter(r#"(userName sw "ada" or displayName co "Lovelace") and active eq true"#)
            .expect("filter should parse");

    assert_eq!(
        filter,
        ScimFilterExpression::And(
            Box::new(ScimFilterExpression::Or(
                Box::new(ScimFilterExpression::Compare {
                    path: ScimAttributePath::from("userName"),
                    operator: ScimCompareOperator::Sw,
                    value: serde_json::json!("ada"),
                }),
                Box::new(ScimFilterExpression::Compare {
                    path: ScimAttributePath::from("displayName"),
                    operator: ScimCompareOperator::Co,
                    value: serde_json::json!("Lovelace"),
                }),
            )),
            Box::new(ScimFilterExpression::Compare {
                path: ScimAttributePath::from("active"),
                operator: ScimCompareOperator::Eq,
                value: serde_json::json!(true),
            }),
        )
    );
}

#[test]
fn parses_not_and_value_path_filter() {
    let filter = parse_filter(r#"not emails[type eq "work"].value ew "@example.com""#)
        .expect("filter should parse");

    assert_eq!(
        filter,
        ScimFilterExpression::Not(Box::new(ScimFilterExpression::Compare {
            path: ScimAttributePath::value_path(
                "emails",
                ScimFilterExpression::Compare {
                    path: ScimAttributePath::from("type"),
                    operator: ScimCompareOperator::Eq,
                    value: serde_json::json!("work"),
                },
                Some("value"),
            ),
            operator: ScimCompareOperator::Ew,
            value: serde_json::json!("@example.com"),
        }))
    );
}

#[test]
fn parses_presence_and_extension_urn_paths() {
    let filter =
        parse_filter("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department pr")
            .expect("filter should parse");

    assert_eq!(
        filter,
        ScimFilterExpression::Present(ScimAttributePath::from(
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department",
        ))
    );
}

#[test]
fn evaluates_extension_urn_paths_against_nested_extension_objects() {
    let resource = serde_json::json!({
        "userName": "ada@example.com",
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
            "department": "Identity",
            "employeeNumber": "E-123"
        }
    });

    assert!(resource_matches_filter(
        &resource,
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department eq \"Identity\"",
    )
    .expect("filter should evaluate"));
    assert!(resource_matches_filter(
        &resource,
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber pr",
    )
    .expect("filter should evaluate"));
}

#[test]
fn evaluates_subattribute_and_value_path_filters() {
    let resource = serde_json::json!({
        "emails": [
            {"value": "ada@example.com", "type": "work"},
            {"value": "ada@home.example", "type": "home"}
        ]
    });

    assert!(
        resource_matches_filter(&resource, r#"emails.value co "example.com""#)
            .expect("subattribute filter should evaluate")
    );
    assert!(resource_matches_filter(
        &resource,
        r#"emails[type eq "work"].value eq "ada@example.com""#
    )
    .expect("valuePath filter should evaluate"));
    assert!(!resource_matches_filter(
        &resource,
        r#"emails[type eq "home"].value eq "ada@example.com""#
    )
    .expect("valuePath filter should evaluate"));
}

#[test]
fn resource_filter_honors_case_exact_attribute_policy() {
    let resource = serde_json::json!({
        "id": "User-123",
        "userName": "Ada@Example.com",
        "displayName": "Ada Lovelace",
        "emails": [
            {"value": "ADA@EXAMPLE.COM", "type": "work"}
        ],
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
            "department": "Identity"
        }
    });

    assert!(
        resource_matches_filter(&resource, r#"userName eq "ada@example.com""#)
            .expect("userName should match case-insensitively")
    );
    assert!(
        resource_matches_filter(&resource, r#"emails.value co "example.com""#)
            .expect("emails.value should match case-insensitively")
    );
    assert!(resource_matches_filter(
        &resource,
        r#"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department eq "identity""#,
    )
    .expect("enterprise attributes should match case-insensitively"));
    assert!(!resource_matches_filter(&resource, r#"id eq "user-123""#)
        .expect("id should remain case-exact"));
}
