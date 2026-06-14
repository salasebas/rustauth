use std::sync::Arc;

use rustauth_core::db::MemoryAdapter;
use rustauth_plugins::email_otp::EmailOtpOptions;

use super::common::*;

#[tokio::test]
async fn send_verification_on_sign_up_hook_sends_otp() {
    let adapter = Arc::new(MemoryAdapter::new());
    let sender = CaptureSender::default();
    let router = router(
        adapter.clone(),
        sender.clone(),
        EmailOtpOptions {
            send_verification_on_sign_up: true,
            ..EmailOtpOptions::default()
        },
    )
    .unwrap();

    let response = router
        .handle_async(
            json_request(
                "/sign-up/email",
                r#"{"name":"Ada","email":"ada@example.com","password":"valid-password"}"#,
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(sender.count_after_dispatch(1).await, 1);
    assert!(
        verification_value(&adapter, "email-verification-otp-ada@example.com")
            .await
            .is_some()
    );
}

#[tokio::test]
async fn send_verification_otp_returns_before_slow_sender_finishes(
) -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    struct SlowSender {
        started: Arc<AtomicUsize>,
    }

    impl rustauth_plugins::email_otp::SendEmailOtp for SlowSender {
        fn send_email_otp(
            &self,
            _payload: rustauth_plugins::email_otp::EmailOtpPayload,
            _request: Option<&http::Request<Vec<u8>>>,
        ) -> rustauth_core::outbound::OutboundSendFuture {
            let started = Arc::clone(&self.started);
            Box::pin(async move {
                started.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_secs(2)).await;
                Ok(())
            }) as rustauth_core::outbound::OutboundSendFuture
        }
    }

    let started = Arc::new(AtomicUsize::new(0));
    let adapter = Arc::new(MemoryAdapter::new());
    create_user(&adapter, "ada@example.com", false).await;
    let options = EmailOtpOptions {
        sender: Some(Arc::new(SlowSender {
            started: Arc::clone(&started),
        })),
        ..EmailOtpOptions::default()
    };
    let router = router_with_async_outbound(adapter, CaptureSender::default(), options)?;

    let request_started = Instant::now();
    let response = router
        .handle_async(json_request(
            "/email-otp/send-verification-otp",
            r#"{"email":"ada@example.com","type":"email-verification"}"#,
            None,
        )?)
        .await?;
    let elapsed = request_started.elapsed();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        elapsed < Duration::from_millis(100),
        "email-otp send took {elapsed:?}"
    );
    assert_eq!(started.load(Ordering::SeqCst), 0);

    for _ in 0..100 {
        if started.load(Ordering::SeqCst) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(started.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn override_default_send_verification_email_sends_otp() {
    let adapter = Arc::new(MemoryAdapter::new());
    create_user(&adapter, "ada@example.com", false).await;
    let sender = CaptureSender::default();
    let router = router(
        adapter.clone(),
        sender.clone(),
        EmailOtpOptions {
            override_default_email_verification: true,
            ..EmailOtpOptions::default()
        },
    )
    .unwrap();

    let response = router
        .handle_async(
            json_request(
                "/send-verification-email",
                r#"{"email":"ada@example.com"}"#,
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(sender.count_after_dispatch(1).await, 1);
    assert!(
        verification_value(&adapter, "email-verification-otp-ada@example.com")
            .await
            .is_some()
    );
}
