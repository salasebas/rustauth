use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

async fn seed_existing_saml_user_with_account(
    adapter: &MemoryAdapter,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = OffsetDateTime::now_utc();
    adapter
        .create(
            Create::new("user")
                .data("id", DbValue::String("existing_saml_user".to_owned()))
                .data("name", DbValue::String("Existing SAML User".to_owned()))
                .data("email", DbValue::String("saml-user@example.com".to_owned()))
                .data("email_verified", DbValue::Boolean(true))
                .data("image", DbValue::Null)
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Timestamp(now))
                .force_allow_id(),
        )
        .await?;
    adapter
        .create(
            Create::new("account")
                .data("id", DbValue::String("existing_saml_account".to_owned()))
                .data("account_id", DbValue::String("saml-subject-123".to_owned()))
                .data("provider_id", DbValue::String("saml-okta".to_owned()))
                .data("user_id", DbValue::String("existing_saml_user".to_owned()))
                .data("access_token", DbValue::Null)
                .data("refresh_token", DbValue::Null)
                .data("id_token", DbValue::Null)
                .data("access_token_expires_at", DbValue::Null)
                .data("refresh_token_expires_at", DbValue::Null)
                .data("scope", DbValue::Null)
                .data("password", DbValue::Null)
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Timestamp(now))
                .force_allow_id(),
        )
        .await?;
    Ok(())
}

#[tokio::test]
async fn saml_acs_skips_provision_user_for_existing_user_by_default(
) -> Result<(), Box<dyn std::error::Error>> {
    let calls = std::sync::Arc::new(AtomicUsize::new(0));
    let callback_calls = std::sync::Arc::clone(&calls);
    let (adapter, router) = router_with_options(SsoOptions::default().provision_user(move |_| {
        let callback_calls = std::sync::Arc::clone(&callback_calls);
        async move {
            callback_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }))?;
    seed_saml_provider_record(&adapter).await?;
    seed_existing_saml_user_with_account(&adapter).await?;

    let relay_state = saml_sign_in_relay_state(&router).await?;
    let first_response = valid_saml_response(&relay_state, "assertion-existing-saml-1")?;
    let first = post_saml_acs(&router, &first_response, &relay_state).await?;
    assert_eq!(first.status(), StatusCode::FOUND);

    let relay_state = saml_sign_in_relay_state(&router).await?;
    let second_response = valid_saml_response(&relay_state, "assertion-existing-saml-2")?;
    let second = post_saml_acs(&router, &second_response, &relay_state).await?;
    assert_eq!(second.status(), StatusCode::FOUND);
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    Ok(())
}

#[tokio::test]
async fn saml_acs_calls_provision_user_for_existing_user_when_enabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let calls = std::sync::Arc::new(AtomicUsize::new(0));
    let callback_calls = std::sync::Arc::clone(&calls);
    let (adapter, router) = router_with_options(
        SsoOptions::default()
            .provision_user(move |input| {
                let callback_calls = std::sync::Arc::clone(&callback_calls);
                async move {
                    assert!(!input.is_register);
                    callback_calls.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            })
            .provision_user_on_every_login(true),
    )?;
    seed_saml_provider_record(&adapter).await?;
    seed_existing_saml_user_with_account(&adapter).await?;

    let relay_state = saml_sign_in_relay_state(&router).await?;
    let saml_response = valid_saml_response(&relay_state, "assertion-existing-saml-every-1")?;
    let response = post_saml_acs(&router, &saml_response, &relay_state).await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    Ok(())
}
