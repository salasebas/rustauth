use std::sync::Arc;

use openauth_core::db::{DbAdapter, DbFieldType, DbValue, FindOne, MemoryAdapter, Where};
use openauth_core::options::{OpenAuthOptions, UserAdditionalField};
use openauth_plugins::email_otp::EmailOtpOptions;

use super::common::*;

#[tokio::test]
async fn sign_in_new_user_persists_additional_user_fields() {
    let adapter = Arc::new(MemoryAdapter::new());
    let sender = CaptureSender::default();
    let mut auth_options = OpenAuthOptions::default();
    auth_options.user.additional_fields.insert(
        "role".to_owned(),
        UserAdditionalField::new(DbFieldType::String),
    );
    let router = router_with_auth_options(
        adapter.clone(),
        sender.clone(),
        EmailOtpOptions::default(),
        auth_options,
    )
    .unwrap();
    router
        .handle_async(
            json_request(
                "/email-otp/send-verification-otp",
                r#"{"email":"new@example.com","type":"sign-in"}"#,
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();

    let response = router
        .handle_async(
            json_request(
                "/sign-in/email-otp",
                &format!(
                    r#"{{"email":"new@example.com","otp":"{}","role":"admin"}}"#,
                    sender.last_otp()
                ),
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let record = adapter
        .find_one(FindOne::new("user").where_clause(Where::new(
            "email",
            DbValue::String("new@example.com".to_owned()),
        )))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        record.get("role"),
        Some(&DbValue::String("admin".to_owned()))
    );
}
