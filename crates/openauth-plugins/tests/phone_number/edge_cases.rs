use super::*;

#[tokio::test]
async fn send_otp_without_sender_returns_not_implemented() -> Result<(), Box<dyn std::error::Error>>
{
    let router = router_with_options(
        PhoneNumberOptions::default(),
        Arc::new(MemoryAdapter::new()),
    )?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/phone-number/send-otp",
            &format!(r#"{{"phoneNumber":"{PHONE}"}}"#),
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "SEND_OTP_NOT_IMPLEMENTED");
    Ok(())
}

#[tokio::test]
async fn validator_rejects_invalid_phone_number() -> Result<(), Box<dyn std::error::Error>> {
    let options = PhoneNumberOptions::default().phone_number_validator(|phone| Ok(phone == PHONE));
    let adapter = Arc::new(MemoryAdapter::new());
    seed_user_with_phone(&adapter, PHONE, true).await?;
    let router = router_with_options(options, adapter)?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/phone-number",
            r#"{"phoneNumber":"bad","password":"secret123"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "INVALID_PHONE_NUMBER");
    Ok(())
}

#[tokio::test]
async fn verify_rejects_missing_and_expired_otp() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router_with_options(PhoneNumberOptions::default(), adapter.clone())?;

    let missing = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/phone-number/verify",
            &format!(r#"{{"phoneNumber":"{PHONE}","code":"123456"}}"#),
            None,
        )?)
        .await?;
    assert_eq!(missing.status(), StatusCode::BAD_REQUEST);
    let missing_body: Value = serde_json::from_slice(missing.body())?;
    assert_eq!(missing_body["code"], "OTP_NOT_FOUND");

    seed_otp(&adapter, PHONE, "123456", 0, -1).await?;
    let expired = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/phone-number/verify",
            &format!(r#"{{"phoneNumber":"{PHONE}","code":"123456"}}"#),
            None,
        )?)
        .await?;
    assert_eq!(expired.status(), StatusCode::BAD_REQUEST);
    let expired_body: Value = serde_json::from_slice(expired.body())?;
    assert_eq!(expired_body["code"], "OTP_EXPIRED");
    Ok(())
}

#[tokio::test]
async fn update_phone_number_rejects_duplicate_with_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    seed_user_with_phone(&adapter, PHONE, true).await?;
    seed_user_with_phone_id(&adapter, "user_2", NEW_PHONE, true).await?;
    seed_otp(&adapter, NEW_PHONE, "123456", 0, 300).await?;
    let session = DbSessionStore::new(adapter.as_ref())
        .create_session(CreateSessionInput::new(
            "user_1",
            OffsetDateTime::now_utc() + Duration::hours(1),
        ))
        .await?;
    let router = router_with_options(PhoneNumberOptions::default(), adapter)?;
    let cookie = signed_session_cookie(&session.token)?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/phone-number/verify",
            &format!(r#"{{"phoneNumber":"{NEW_PHONE}","code":"123456","updatePhoneNumber":true}}"#),
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "PHONE_NUMBER_EXIST");
    Ok(())
}

#[tokio::test]
async fn update_user_rejects_non_null_phone_number() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    seed_user_with_phone(&adapter, PHONE, true).await?;
    let session = DbSessionStore::new(adapter.as_ref())
        .create_session(CreateSessionInput::new(
            "user_1",
            OffsetDateTime::now_utc() + Duration::hours(1),
        ))
        .await?;
    let router = router_with_options(PhoneNumberOptions::default(), adapter)?;
    let cookie = signed_session_cookie(&session.token)?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/update-user",
            &format!(r#"{{"phoneNumber":"{NEW_PHONE}"}}"#),
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "PHONE_NUMBER_CANNOT_BE_UPDATED");
    Ok(())
}

#[tokio::test]
async fn require_verification_blocks_sign_in_and_sends_otp(
) -> Result<(), Box<dyn std::error::Error>> {
    let sent = Arc::new(Mutex::new(0));
    let adapter = Arc::new(MemoryAdapter::new());
    seed_user_with_phone(&adapter, PHONE, false).await?;
    DbUserStore::new(adapter.as_ref())
        .create_credential_account(CreateCredentialAccountInput::new(
            "user_1",
            hash_password("secret123")?,
        ))
        .await?;
    let options = PhoneNumberOptions::default()
        .require_verification(true)
        .send_otp({
            let sent = Arc::clone(&sent);
            move |_phone, _code| {
                *sent
                    .lock()
                    .map_err(|_| OpenAuthError::Api("lock poisoned".to_owned()))? += 1;
                Ok(())
            }
        });
    let router = router_with_options(options, adapter.clone())?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/phone-number",
            &format!(r#"{{"phoneNumber":"{PHONE}","password":"secret123"}}"#),
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(*sent.lock().map_err(|_| "lock poisoned")?, 1);
    assert!(find_verification(&adapter, PHONE).await?.is_some());
    Ok(())
}

#[tokio::test]
async fn callback_on_verification_receives_updated_phone_and_user_id(
) -> Result<(), Box<dyn std::error::Error>> {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let adapter = Arc::new(MemoryAdapter::new());
    seed_user_with_phone(&adapter, PHONE, true).await?;
    seed_otp(&adapter, NEW_PHONE, "123456", 0, 300).await?;
    let session = DbSessionStore::new(adapter.as_ref())
        .create_session(CreateSessionInput::new(
            "user_1",
            OffsetDateTime::now_utc() + Duration::hours(1),
        ))
        .await?;
    let options = PhoneNumberOptions::default().callback_on_verification({
        let captured = Arc::clone(&captured);
        move |phone_number, user_id| {
            captured
                .lock()
                .map_err(|_| OpenAuthError::Api("lock poisoned".to_owned()))?
                .push((phone_number.to_owned(), user_id.to_owned()));
            Ok(())
        }
    });
    let router = router_with_options(options, adapter.clone())?;
    let cookie = signed_session_cookie(&session.token)?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/phone-number/verify",
            &format!(r#"{{"phoneNumber":"{NEW_PHONE}","code":"123456","updatePhoneNumber":true}}"#),
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        captured.lock().map_err(|_| "lock poisoned")?.clone(),
        vec![(NEW_PHONE.to_owned(), "user_1".to_owned())]
    );
    Ok(())
}

#[tokio::test]
async fn update_phone_number_uses_custom_verify_otp_without_internal_record(
) -> Result<(), Box<dyn std::error::Error>> {
    let called = Arc::new(Mutex::new(false));
    let adapter = Arc::new(MemoryAdapter::new());
    seed_user_with_phone(&adapter, PHONE, true).await?;
    let session = DbSessionStore::new(adapter.as_ref())
        .create_session(CreateSessionInput::new(
            "user_1",
            OffsetDateTime::now_utc() + Duration::hours(1),
        ))
        .await?;
    let options = PhoneNumberOptions::default().verify_otp({
        let called = Arc::clone(&called);
        move |phone_number, code| {
            *called
                .lock()
                .map_err(|_| OpenAuthError::Api("lock poisoned".to_owned()))? =
                phone_number == NEW_PHONE && code == "external";
            Ok(phone_number == NEW_PHONE && code == "external")
        }
    });
    let router = router_with_options(options, adapter.clone())?;
    let cookie = signed_session_cookie(&session.token)?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/phone-number/verify",
            &format!(
                r#"{{"phoneNumber":"{NEW_PHONE}","code":"external","updatePhoneNumber":true}}"#
            ),
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(*called.lock().map_err(|_| "lock poisoned")?);
    assert!(find_user_by_phone(&adapter, NEW_PHONE).await?.is_some());
    assert!(find_verification(&adapter, NEW_PHONE).await?.is_none());
    Ok(())
}
