mod common;

use axum::http::{header, Method, StatusCode};
use common::*;
use openauth::db::{Create, DbAdapter, DbRecord, DbValue};
use openauth::{MemoryAdapter, OpenAuthOptions};
use openauth_axum::router;
use tower::ServiceExt;

#[tokio::test]
async fn account_list_unlink_and_token_routes_work_over_axum(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    let app = router(auth_with_adapter(
        adapter.clone(),
        OpenAuthOptions::default()
            .base_url("http://localhost:3000/api/auth")
            .social_provider(FakeProvider::new("github")),
    )?)?;

    let sign_up = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    assert_eq!(sign_up.status(), StatusCode::OK);
    let cookie = cookie_header(&sign_up).ok_or("missing sign-up cookie")?;
    insert_github_account(&adapter).await?;

    let accounts = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/api/auth/list-accounts",
            "",
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(accounts.status(), StatusCode::OK);
    let accounts_body = body_json(accounts).await?;
    assert_eq!(accounts_body.as_array().map(Vec::len), Some(2));

    let access_token = app
        .clone()
        .oneshot(
            json_request(
                Method::POST,
                "/api/auth/get-access-token",
                r#"{"providerId":"github","accountId":"github_ada"}"#,
                Some(&cookie),
            )?
            .with_header(header::ORIGIN, "http://localhost:3000")?,
        )
        .await?;
    assert_eq!(access_token.status(), StatusCode::OK);
    let access_body = body_json(access_token).await?;
    assert_eq!(access_body["accessToken"], "stored-access-token");

    let account_info = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/api/auth/account-info?accountId=github_ada",
            "",
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(account_info.status(), StatusCode::OK);
    let account_info_body = body_json(account_info).await?;
    assert_eq!(account_info_body["user"]["email"], "ada@example.com");

    let refresh = app
        .clone()
        .oneshot(
            json_request(
                Method::POST,
                "/api/auth/refresh-token",
                r#"{"providerId":"github","accountId":"github_ada"}"#,
                Some(&cookie),
            )?
            .with_header(header::ORIGIN, "http://localhost:3000")?,
        )
        .await?;
    assert_eq!(refresh.status(), StatusCode::OK);
    let refresh_body = body_json(refresh).await?;
    assert_eq!(refresh_body["accessToken"], "new-access-token");
    assert_eq!(refresh_body["refreshToken"], "new-refresh-token");

    let unlink = app
        .clone()
        .oneshot(
            json_request(
                Method::POST,
                "/api/auth/unlink-account",
                r#"{"providerId":"github","accountId":"github_ada"}"#,
                Some(&cookie),
            )?
            .with_header(header::ORIGIN, "http://localhost:3000")?,
        )
        .await?;
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
