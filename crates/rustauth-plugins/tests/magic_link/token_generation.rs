use rustauth_plugins::magic_link::MagicLinkOptions;

use super::support::{build_router, last_sent_token, post_json, sender, sent_messages};

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

    let token = last_sent_token(&sent).await?;
    assert_eq!(token, "ada@example.com:custom");
    Ok(())
}
