use std::sync::{Arc, Mutex};

use http::{header, Method, StatusCode};
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::error::OpenAuthError;
use openauth_core::options::OpenAuthOptions;
use openauth_plugins::anonymous::{anonymous_with, AnonymousOptions};
use serde_json::Value;

use super::helpers::{
    anonymous_user, contains_user, find_bool, find_string, json_request, request,
    response_cookie_header, router, secret, seed_session, seed_user, session,
    signed_session_cookie, TestAdapter,
};

#[tokio::test]
async fn link_hook_calls_callback_and_deletes_previous_anonymous_user(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    seed_user(&adapter, anonymous_user("anon_user", true)).await?;
    seed_session(&adapter, session("session_1", "anon_user", "old_token")).await?;
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let captured = Arc::clone(&calls);
    let plugin = anonymous_with(AnonymousOptions::default().on_link_account(move |data| {
        captured
            .lock()
            .map(|mut calls| {
                calls.push(format!(
                    "{}:{}",
                    data.anonymous_user.user.id, data.new_user.user.id
                ))
            })
            .map_err(|_| OpenAuthError::Api("lock poisoned".to_owned()))
    }));
    let hook = plugin.hooks.async_after[0].handler.clone();
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            plugins: vec![plugin],
            secret: Some(secret().to_owned()),
            ..OpenAuthOptions::default()
        },
        adapter.clone(),
    )?;
    seed_user(&adapter, anonymous_user("real_user", false)).await?;
    seed_session(&adapter, session("session_2", "real_user", "new_token")).await?;
    let new_cookie = signed_session_cookie("new_token")?;
    let response = http::Response::builder()
        .status(StatusCode::OK)
        .header(header::SET_COOKIE, new_cookie)
        .body(Vec::new())?;
    let request = request(
        Method::POST,
        "/api/auth/sign-in/email",
        Some(&signed_session_cookie("old_token")?),
    )?;

    (hook)(&context, &request, response).await?;

    assert_eq!(
        calls.lock().map_err(|_| "lock poisoned")?.as_slice(),
        ["anon_user:real_user"]
    );
    assert!(!contains_user(&adapter, "anon_user").await);
    assert!(contains_user(&adapter, "real_user").await);
    Ok(())
}

#[tokio::test]
async fn route_sign_up_links_and_deletes_previous_anonymous_user(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let captured = Arc::clone(&calls);
    let plugin = anonymous_with(
        AnonymousOptions::default().on_link_account_async(move |data| {
            let captured = Arc::clone(&captured);
            async move {
                captured
                    .lock()
                    .map(|mut calls| {
                        calls.push(format!(
                            "{}:{}",
                            data.anonymous_user.user.id, data.new_user.user.id
                        ))
                    })
                    .map_err(|_| OpenAuthError::Api("lock poisoned".to_owned()))
            }
        }),
    );
    let router = router(adapter.clone(), plugin)?;

    let anonymous_response = router
        .handle_async(request(Method::POST, "/api/auth/sign-in/anonymous", None)?)
        .await?;
    let anonymous_body: Value = serde_json::from_slice(anonymous_response.body())?;
    let anonymous_user_id = anonymous_body["user"]["id"]
        .as_str()
        .ok_or("missing anonymous user id")?
        .to_owned();
    let anonymous_cookie = response_cookie_header(&anonymous_response);

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            serde_json::json!({
                "name": "Linked User",
                "email": "linked@example.test",
                "password": "password123"
            }),
            Some(&anonymous_cookie),
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;
    let new_user_id = body["user"]["id"]
        .as_str()
        .ok_or("missing linked user id")?
        .to_owned();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        calls.lock().map_err(|_| "lock poisoned")?.as_slice(),
        [format!("{anonymous_user_id}:{new_user_id}")]
    );
    assert!(!contains_user(&adapter, &anonymous_user_id).await);
    assert_eq!(adapter.len("session").await, 1);
    let users = adapter.records("user").await;
    assert!(users.iter().any(|user| {
        find_string(user, "email") == Some("linked@example.test")
            && find_bool(user, "is_anonymous") == Some(false)
    }));
    Ok(())
}

#[tokio::test]
async fn route_sign_in_email_links_and_deletes_previous_anonymous_user(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let captured = Arc::clone(&calls);
    let plugin = anonymous_with(
        AnonymousOptions::default().on_link_account_async(move |data| {
            let captured = Arc::clone(&captured);
            async move {
                captured
                    .lock()
                    .map(|mut calls| {
                        calls.push(format!(
                            "{}:{}",
                            data.anonymous_user.user.id, data.new_user.user.id
                        ))
                    })
                    .map_err(|_| OpenAuthError::Api("lock poisoned".to_owned()))
            }
        }),
    );
    let router = router(adapter.clone(), plugin)?;

    let existing_account = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            serde_json::json!({
                "name": "Existing User",
                "email": "linked@example.test",
                "password": "password123"
            }),
            None,
        )?)
        .await?;
    assert_eq!(existing_account.status(), StatusCode::OK);
    let existing_cookie = response_cookie_header(&existing_account);
    let existing_body: Value = serde_json::from_slice(existing_account.body())?;
    let existing_user_id = existing_body["user"]["id"]
        .as_str()
        .ok_or("missing existing user id")?
        .to_owned();

    let sign_out = router
        .handle_async(request(
            Method::POST,
            "/api/auth/sign-out",
            Some(&existing_cookie),
        )?)
        .await?;
    assert_eq!(sign_out.status(), StatusCode::OK);

    let anonymous_response = router
        .handle_async(request(Method::POST, "/api/auth/sign-in/anonymous", None)?)
        .await?;
    let anonymous_body: Value = serde_json::from_slice(anonymous_response.body())?;
    let anonymous_user_id = anonymous_body["user"]["id"]
        .as_str()
        .ok_or("missing anonymous user id")?
        .to_owned();
    let anonymous_cookie = response_cookie_header(&anonymous_response);

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            serde_json::json!({
                "email": "linked@example.test",
                "password": "password123"
            }),
            Some(&anonymous_cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        calls.lock().map_err(|_| "lock poisoned")?.as_slice(),
        [format!("{anonymous_user_id}:{existing_user_id}")]
    );
    assert!(!contains_user(&adapter, &anonymous_user_id).await);
    assert_eq!(adapter.len("session").await, 1);
    let users = adapter.records("user").await;
    assert!(users.iter().any(|user| {
        find_string(user, "email") == Some("linked@example.test")
            && find_bool(user, "is_anonymous") == Some(false)
    }));
    Ok(())
}

#[tokio::test]
async fn link_hook_keeps_anonymous_user_when_new_user_is_same_anonymous_or_delete_disabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    seed_user(&adapter, anonymous_user("anon_user", true)).await?;
    seed_session(&adapter, session("session_1", "anon_user", "old_token")).await?;
    let plugin = anonymous_with(AnonymousOptions::default().disable_delete_anonymous_user(true));
    let hook = plugin.hooks.async_after[0].handler.clone();
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            plugins: vec![plugin],
            secret: Some(secret().to_owned()),
            ..OpenAuthOptions::default()
        },
        adapter.clone(),
    )?;
    let new_cookie = signed_session_cookie("new_token")?;
    seed_session(&adapter, session("session_2", "anon_user", "new_token")).await?;
    let response = http::Response::builder()
        .status(StatusCode::OK)
        .header(header::SET_COOKIE, new_cookie)
        .body(Vec::new())?;
    let request = request(
        Method::POST,
        "/api/auth/sign-in/email",
        Some(&signed_session_cookie("old_token")?),
    )?;

    (hook)(&context, &request, response).await?;

    assert_eq!(adapter.len("user").await, 1);
    Ok(())
}
