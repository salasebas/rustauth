use openauth_plugins::magic_link::MagicLinkOptions;

use super::support::{build_router, post_json, sender, sent_messages};

#[tokio::test]
async fn supports_custom_generate_token() -> Result<(), Box<dyn std::error::Error>> {
    let sent = sent_messages();
    let options = MagicLinkOptions::new(sender(sent.clone()))
        .generate_token(|email| Box::pin(async move { Ok(format!("{email}:custom")) }));
    let (router, _adapter) = build_router(sent.clone(), options)?;

    post_json(
        &router,
        "/api/auth/sign-in/magic-link",
        r#"{"email":"ada@example.com"}"#,
    )
    .await?;

    let token = sent
        .lock()
        .map_err(|_| "sent messages lock poisoned")?
        .last()
        .ok_or("missing sent magic link")?
        .token
        .clone();
    assert_eq!(token, "ada@example.com:custom");
    Ok(())
}
