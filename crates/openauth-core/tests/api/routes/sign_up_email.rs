use super::*;
use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use openauth_core::db::DbFieldType;
use openauth_core::options::{
    EmailPasswordOptions, EmailVerificationOptions, ExistingUserSignUpPayload, SecondaryStorage,
    SecondaryStorageFuture, UserAdditionalField, UserOptions, VerificationEmail,
};

#[tokio::test]
async fn sign_up_email_route_creates_session_and_sets_cookie(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let router = router(adapter.clone())?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert!(body["session"].is_null());
    assert!(body["token"]
        .as_str()
        .is_some_and(|token| !token.is_empty()));
    assert_eq!(body["user"]["email"], "ada@example.com");
    assert_eq!(adapter.len("user").await, 1);
    assert_eq!(adapter.len("session").await, 1);
    assert!(set_cookie_values(&response)
        .iter()
        .any(|cookie| cookie.starts_with("open-auth.session_token=")));
    assert!(body["user"]["created_at"].as_str().is_some());
    assert!(body["user"]["updated_at"].as_str().is_some());
    Ok(())
}

#[tokio::test]
async fn sign_up_email_route_rejects_by_default_without_explicit_opt_in(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let router = router_with_bare_options(adapter.clone(), OpenAuthOptions::default())?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "EMAIL_PASSWORD_SIGN_UP_DISABLED");
    assert!(adapter.is_empty("user").await);
    assert!(adapter.is_empty("session").await);
    Ok(())
}

#[tokio::test]
async fn sign_up_email_route_rejects_when_email_password_is_disabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let router = router_with_bare_options(
        adapter.clone(),
        OpenAuthOptions::default().email_password(EmailPasswordOptions::new().enabled(false)),
    )?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "EMAIL_PASSWORD_SIGN_UP_DISABLED");
    assert!(adapter.is_empty("user").await);
    assert!(adapter.is_empty("session").await);
    Ok(())
}

#[tokio::test]
async fn sign_up_email_route_allows_sign_in_when_enabled_but_sign_up_disabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_account(credential_account_record(
            "user_1",
            &hash_password("secret123")?,
            now,
        ))
        .await?;
    let router = router_with_bare_options(
        adapter.clone(),
        OpenAuthOptions::default().email_password(
            EmailPasswordOptions::new()
                .enabled(true)
                .disable_sign_up(true),
        ),
    )?;

    let sign_up = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    assert_eq!(sign_up.status(), StatusCode::BAD_REQUEST);
    let sign_up_body: Value = serde_json::from_slice(sign_up.body())?;
    assert_eq!(sign_up_body["code"], "EMAIL_PASSWORD_SIGN_UP_DISABLED");

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    assert_eq!(sign_in.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn sign_up_email_route_can_skip_auto_sign_in() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let router = router_with_options(
        adapter.clone(),
        OpenAuthOptions::default().email_password(
            EmailPasswordOptions::new()
                .enabled(true)
                .auto_sign_in(false),
        ),
    )?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert!(body["token"].is_null());
    assert_eq!(body["user"]["email"], "ada@example.com");
    assert_eq!(adapter.len("user").await, 1);
    assert!(adapter.is_empty("session").await);
    assert!(set_cookie_values(&response)
        .iter()
        .all(|cookie| !cookie.starts_with("open-auth.session_token=")));
    Ok(())
}

#[tokio::test]
async fn sign_up_email_route_uses_secondary_storage_for_sessions(
) -> Result<(), Box<dyn std::error::Error>> {
    let storage = Arc::new(TestSecondaryStorage::default());
    let adapter = Arc::new(RouteAdapter::default());
    let router = router_with_options(
        adapter.clone(),
        OpenAuthOptions::default().secondary_storage(storage.clone()),
    )?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    let token = body["token"].as_str().ok_or("missing token")?;
    let user_id = body["user"]["id"].as_str().ok_or("missing user id")?;
    assert!(adapter.is_empty("session").await);
    assert!(storage.value(&format!("session:{token}"))?.is_some());
    assert!(storage.value(&format!("session:user:{user_id}"))?.is_some());

    let cookie = signed_session_cookie(token)?;
    let session_response = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/get-session",
            "",
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(session_response.status(), StatusCode::OK);
    let session_body: Value = serde_json::from_slice(session_response.body())?;
    assert_eq!(session_body["session"]["token"], token);
    assert_eq!(session_body["user"]["id"], user_id);

    let list_response = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/list-sessions",
            "",
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(list_response.status(), StatusCode::OK);
    let sessions: Value = serde_json::from_slice(list_response.body())?;
    assert_eq!(sessions.as_array().map(Vec::len), Some(1));

    let revoke_response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/revoke-sessions",
            "{}",
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(revoke_response.status(), StatusCode::OK);
    assert!(storage.value(&format!("session:{token}"))?.is_none());
    assert!(storage.value(&format!("session:user:{user_id}"))?.is_none());
    Ok(())
}

#[tokio::test]
async fn sign_up_email_route_sends_verification_and_returns_synthetic_duplicate_response_when_required(
) -> Result<(), Box<dyn std::error::Error>> {
    let sent = Arc::new(Mutex::new(Vec::<String>::new()));
    let sent_for_hook = Arc::clone(&sent);
    let adapter = Arc::new(RouteAdapter::default());
    let router = router_with_options(
        adapter.clone(),
        OpenAuthOptions::default()
            .email_password(
                EmailPasswordOptions::new()
                    .enabled(true)
                    .require_email_verification(true),
            )
            .email_verification(EmailVerificationOptions::new().send_verification_email(
                move |email: VerificationEmail, _request: Option<&http::Request<Vec<u8>>>| {
                    sent_for_hook
                        .lock()
                        .map_err(|_| {
                            OpenAuthError::Api("verification sink lock poisoned".to_owned())
                        })?
                        .push(email.url);
                    Ok(())
                },
            )),
    )?;

    let first = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ADA@EXAMPLE.COM","password":"secret123","callbackURL":"/dashboard"}"#,
            None,
        )?)
        .await?;
    assert_eq!(first.status(), StatusCode::OK);
    let first_body: Value = serde_json::from_slice(first.body())?;
    assert!(first_body["token"].is_null());
    assert_eq!(first_body["user"]["email"], "ada@example.com");
    assert!(adapter.is_empty("session").await);
    assert_eq!(
        sent.lock().map_err(|_| "verification sink poisoned")?.len(),
        1
    );
    assert!(sent
        .lock()
        .map_err(|_| "verification sink poisoned")?
        .first()
        .is_some_and(
            |url| url.contains("/verify-email?token=") && url.contains("callbackURL=%2Fdashboard")
        ));

    let duplicate = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    assert_eq!(duplicate.status(), StatusCode::OK);
    let duplicate_body: Value = serde_json::from_slice(duplicate.body())?;
    assert!(duplicate_body["token"].is_null());
    assert_eq!(duplicate_body["user"]["email"], "ada@example.com");
    assert_eq!(adapter.len("user").await, 1);
    Ok(())
}

#[tokio::test]
async fn sign_up_email_route_duplicate_returns_synthetic_user_not_persisted_values(
) -> Result<(), Box<dyn std::error::Error>> {
    let seen = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
    let seen_for_hook = Arc::clone(&seen);
    let adapter = Arc::new(RouteAdapter::default());
    let options = OpenAuthOptions {
        user: UserOptions {
            additional_fields: BTreeMap::from([(
                "role".to_owned(),
                UserAdditionalField::new(DbFieldType::String),
            )]),
            ..UserOptions::default()
        },
        ..OpenAuthOptions::default()
    }
    .email_password(
        EmailPasswordOptions::new()
            .enabled(true)
            .require_email_verification(true)
            .on_existing_user_sign_up(
                move |payload: ExistingUserSignUpPayload,
                      _request: Option<&http::Request<Vec<u8>>>| {
                    seen_for_hook
                        .lock()
                        .map_err(|_| OpenAuthError::Api("hook sink poisoned".to_owned()))?
                        .push((payload.user.name, payload.user.id));
                    Ok(())
                },
            ),
    );
    let router = router_with_options(adapter.clone(), options)?;

    let first = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123","image":"https://img/ada.png","role":"admin"}"#,
            None,
        )?)
        .await?;
    assert_eq!(first.status(), StatusCode::OK);
    let first_body: Value = serde_json::from_slice(first.body())?;
    let persisted_id = first_body["user"]["id"]
        .as_str()
        .ok_or("missing id")?
        .to_owned();
    assert_eq!(first_body["user"]["role"], "admin");

    let duplicate = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Mallory","email":"ada@example.com","password":"hunter2zzz","image":"https://img/mallory.png","role":"user"}"#,
            None,
        )?)
        .await?;
    assert_eq!(duplicate.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(duplicate.body())?;
    assert!(body["token"].is_null());
    assert_eq!(body["user"]["email"], "ada@example.com");
    // Synthetic response mirrors the request input, never the persisted account.
    assert_eq!(body["user"]["name"], "Mallory");
    assert_eq!(body["user"]["image"], "https://img/mallory.png");
    assert_eq!(body["user"]["role"], "user");
    assert_eq!(body["user"]["email_verified"], false);
    assert_ne!(body["user"]["id"].as_str(), Some(persisted_id.as_str()));
    assert_eq!(adapter.len("user").await, 1);
    assert!(adapter.is_empty("session").await);

    // The hook still receives the real persisted user, exactly once.
    let seen = seen.lock().map_err(|_| "hook sink poisoned")?;
    assert_eq!(seen.as_slice(), [("Ada".to_owned(), persisted_id)]);
    Ok(())
}

#[tokio::test]
async fn sign_up_email_route_duplicate_errors_when_auto_sign_in_disabled_without_verification(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let router = router_with_options(
        adapter.clone(),
        OpenAuthOptions::default().email_password(
            EmailPasswordOptions::new()
                .enabled(true)
                .auto_sign_in(false),
        ),
    )?;

    let first = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    assert_eq!(first.status(), StatusCode::OK);

    let duplicate = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    assert_eq!(duplicate.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(duplicate.body())?;
    assert_eq!(body["code"], "USER_ALREADY_EXISTS");
    assert_eq!(adapter.len("user").await, 1);
    Ok(())
}

#[tokio::test]
async fn sign_up_email_route_duplicate_can_use_another_email_error_code(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let router = router_with_options(
        adapter.clone(),
        OpenAuthOptions::default().email_password(
            EmailPasswordOptions::new()
                .enabled(true)
                .auto_sign_in(false)
                .another_email_error_on_duplicate(true),
        ),
    )?;

    router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;

    let duplicate = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    assert_eq!(duplicate.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(duplicate.body())?;
    assert_eq!(body["code"], "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL");
    Ok(())
}

#[derive(Default)]
struct TestSecondaryStorage {
    values: Mutex<HashMap<String, String>>,
}

impl TestSecondaryStorage {
    fn value(&self, key: &str) -> Result<Option<String>, OpenAuthError> {
        Ok(self
            .values
            .lock()
            .map_err(|_| OpenAuthError::Api("secondary storage lock poisoned".to_owned()))?
            .get(key)
            .cloned())
    }
}

impl SecondaryStorage for TestSecondaryStorage {
    fn get<'a>(&'a self, key: &'a str) -> SecondaryStorageFuture<'a, Option<String>> {
        Box::pin(async move { self.value(key) })
    }

    fn set<'a>(
        &'a self,
        key: &'a str,
        value: String,
        _ttl_seconds: Option<u64>,
    ) -> SecondaryStorageFuture<'a, ()> {
        Box::pin(async move {
            self.values
                .lock()
                .map_err(|_| OpenAuthError::Api("secondary storage lock poisoned".to_owned()))?
                .insert(key.to_owned(), value);
            Ok(())
        })
    }

    fn set_if_not_exists<'a>(
        &'a self,
        key: &'a str,
        value: String,
        _ttl_seconds: Option<u64>,
    ) -> SecondaryStorageFuture<'a, bool> {
        Box::pin(async move {
            let mut values = self
                .values
                .lock()
                .map_err(|_| OpenAuthError::Api("secondary storage lock poisoned".to_owned()))?;
            if values.contains_key(key) {
                return Ok(false);
            }
            values.insert(key.to_owned(), value);
            Ok(true)
        })
    }

    fn delete<'a>(&'a self, key: &'a str) -> SecondaryStorageFuture<'a, ()> {
        Box::pin(async move {
            self.values
                .lock()
                .map_err(|_| OpenAuthError::Api("secondary storage lock poisoned".to_owned()))?
                .remove(key);
            Ok(())
        })
    }

    fn take<'a>(&'a self, key: &'a str) -> SecondaryStorageFuture<'a, Option<String>> {
        Box::pin(async move {
            Ok(self
                .values
                .lock()
                .map_err(|_| OpenAuthError::Api("secondary storage lock poisoned".to_owned()))?
                .remove(key))
        })
    }
}

#[tokio::test]
async fn sign_up_email_route_accepts_username_fields() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let router = router(adapter.clone())?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123","username":"ada_lovelace","displayUsername":"Ada Lovelace"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["user"]["username"], "ada_lovelace");
    assert_eq!(body["user"]["display_username"], "Ada Lovelace");
    let created = record_by_string(&adapter, "user", "email", "ada@example.com")
        .await?
        .ok_or("missing user")?;
    assert_eq!(
        created.get("username"),
        Some(&DbValue::String("ada_lovelace".to_owned()))
    );
    assert_eq!(
        created.get("display_username"),
        Some(&DbValue::String("Ada Lovelace".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn sign_up_email_route_persists_and_returns_additional_user_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let router = router_with_options(adapter.clone(), user_field_options())?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123","role":"admin"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["user"]["role"], "admin");
    assert_eq!(body["user"]["timezone"], "UTC");
    assert!(body["user"]["nickname"].is_null());
    let record = record_by_string(&adapter, "user", "email", "ada@example.com")
        .await?
        .ok_or("missing user")?;
    assert_eq!(
        record.get("role"),
        Some(&DbValue::String("admin".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn sign_up_email_route_requires_additional_user_fields_without_default(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let router = router_with_options(adapter, user_field_options())?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "INVALID_REQUEST_BODY");
    Ok(())
}

#[tokio::test]
async fn sign_up_email_route_rejects_non_input_additional_user_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let mut options = user_field_options();
    options.user.additional_fields.insert(
        "internal_role".to_owned(),
        UserAdditionalField::new(DbFieldType::String).generated(),
    );
    let router = router_with_options(adapter, options)?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123","role":"admin","internal_role":"owner"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "INVALID_REQUEST_BODY");
    Ok(())
}

fn user_field_options() -> OpenAuthOptions {
    OpenAuthOptions {
        user: UserOptions {
            additional_fields: BTreeMap::from([
                (
                    "role".to_owned(),
                    UserAdditionalField::new(DbFieldType::String),
                ),
                (
                    "nickname".to_owned(),
                    UserAdditionalField::new(DbFieldType::String).optional(),
                ),
                (
                    "timezone".to_owned(),
                    UserAdditionalField::new(DbFieldType::String)
                        .default_value(DbValue::String("UTC".to_owned())),
                ),
            ]),
            ..UserOptions::default()
        },
        ..OpenAuthOptions::default()
    }
}
