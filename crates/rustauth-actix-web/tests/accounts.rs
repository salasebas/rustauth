mod common;

use std::sync::Arc;

use actix_web::http::{header, Method, StatusCode};
use actix_web::test;
use common::*;
use rustauth::db::MemoryAdapter;
use rustauth::db::{Create, DbAdapter, DbRecord, DbValue};
use rustauth::options::RustAuthOptions;
use rustauth_actix_web::RustAuthActixWebOptions;

#[tokio::test]
async fn account_list_unlink_and_token_routes_work_over_actix_web(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    let auth = Arc::new(
        auth_with_adapter(
            adapter.clone(),
            RustAuthOptions::default()
                .base_url("http://localhost:3000/api/auth")
                .social_provider(FakeProvider::new("github")),
        )
        .await?,
    );
    let app = mounted_app!(auth, RustAuthActixWebOptions::default());

    let sign_up = test::call_service(
        &app,
        json_test_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )
        .to_request(),
    )
    .await;
    assert_eq!(sign_up.status(), StatusCode::OK);
    let cookie = cookie_header(&sign_up).ok_or("missing sign-up cookie")?;
    insert_github_account(&adapter).await?;

    let accounts = test::call_service(
        &app,
        test_request(Method::GET, "/api/auth/list-accounts", "", Some(&cookie)).to_request(),
    )
    .await;
    assert_eq!(accounts.status(), StatusCode::OK);
    let accounts_body = body_json(accounts).await?;
    assert_eq!(accounts_body.as_array().map(Vec::len), Some(2));

    let access_token = test::call_service(
        &app,
        json_test_request(
            Method::POST,
            "/api/auth/get-access-token",
            r#"{"providerId":"github","accountId":"github_ada"}"#,
            Some(&cookie),
        )
        .insert_header((header::ORIGIN, "http://localhost:3000"))
        .to_request(),
    )
    .await;
    assert_eq!(access_token.status(), StatusCode::OK);
    let access_body = body_json(access_token).await?;
    assert_eq!(access_body["accessToken"], "stored-access-token");

    let account_info = test::call_service(
        &app,
        test_request(
            Method::GET,
            "/api/auth/account-info?accountId=github_ada",
            "",
            Some(&cookie),
        )
        .to_request(),
    )
    .await;
    assert_eq!(account_info.status(), StatusCode::OK);
    let account_info_body = body_json(account_info).await?;
    assert_eq!(account_info_body["user"]["email"], "ada@example.com");

    let refresh = test::call_service(
        &app,
        json_test_request(
            Method::POST,
            "/api/auth/refresh-token",
            r#"{"providerId":"github","accountId":"github_ada"}"#,
            Some(&cookie),
        )
        .insert_header((header::ORIGIN, "http://localhost:3000"))
        .to_request(),
    )
    .await;
    assert_eq!(refresh.status(), StatusCode::OK);
    let refresh_body = body_json(refresh).await?;
    assert_eq!(refresh_body["accessToken"], "new-access-token");
    assert_eq!(refresh_body["refreshToken"], "new-refresh-token");

    let unlink = test::call_service(
        &app,
        json_test_request(
            Method::POST,
            "/api/auth/unlink-account",
            r#"{"providerId":"github","accountId":"github_ada"}"#,
            Some(&cookie),
        )
        .insert_header((header::ORIGIN, "http://localhost:3000"))
        .to_request(),
    )
    .await;
    assert_eq!(unlink.status(), StatusCode::OK);
    let unlink_body = body_json(unlink).await?;
    assert_eq!(unlink_body["status"], true);
    assert_eq!(adapter.len("account").await, 1);
    Ok(())
}

async fn insert_github_account(adapter: &MemoryAdapter) -> Result<(), Box<dyn std::error::Error>> {
    let mut record = credential_account_record(adapter).await?;
    record.insert(
        "id".to_owned(),
        DbValue::String("github_account".to_owned()),
    );
    record.insert(
        "provider_id".to_owned(),
        DbValue::String("github".to_owned()),
    );
    record.insert(
        "account_id".to_owned(),
        DbValue::String("github_ada".to_owned()),
    );
    record.insert("password".to_owned(), DbValue::Null);
    record.insert(
        "access_token".to_owned(),
        DbValue::String("stored-access-token".to_owned()),
    );
    record.insert(
        "refresh_token".to_owned(),
        DbValue::String("stored-refresh-token".to_owned()),
    );
    record.insert(
        "id_token".to_owned(),
        DbValue::String("stored-id-token".to_owned()),
    );
    record.insert(
        "scope".to_owned(),
        DbValue::String("read:user,user:email".to_owned()),
    );
    record.insert("access_token_expires_at".to_owned(), DbValue::Null);
    record.insert("refresh_token_expires_at".to_owned(), DbValue::Null);
    adapter
        .create(Create {
            model: "account".to_owned(),
            data: record,
            select: Vec::new(),
            force_allow_id: false,
        })
        .await?;
    Ok(())
}

async fn credential_account_record(
    adapter: &MemoryAdapter,
) -> Result<DbRecord, Box<dyn std::error::Error>> {
    adapter
        .records("account")
        .await
        .into_iter()
        .find(|record| record.get("provider_id") == Some(&DbValue::String("credential".to_owned())))
        .ok_or_else(|| "missing credential account".into())
}
