//! Minimal OpenAuth + Stripe server for test-mode smoke (see crates/openauth-stripe/SMOKE.md).
//!
//! Webhook signing secret comes from a local `stripe listen` child process (test mode only).
//! Other secrets still come from the environment (`STRIPE_SECRET_KEY`, prices, `OPENAUTH_SECRET`).
//!
//! ```bash
//! set -a && source .env && set +a   # optional: API key + price IDs only
//! cargo run -p openauth-example-stripe-smoke
//! ```

use std::env;
use std::process::Stdio;
use std::time::Duration;

use axum::Router;
use openauth::db::MemoryAdapter;
use openauth::AdvancedOptions;
use openauth::OpenAuth;
use openauth_axum::OpenAuthAxumExt;
use openauth_stripe::options::{StripeOptions, StripePlan, SubscriptionOptions};
use openauth_stripe::{stripe, StripeClient};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::time::timeout;

const AUTH_BASE_PATH: &str = "/api/auth";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = env::var("OPENAUTH_EXAMPLE_HOST").unwrap_or_else(|_| "127.0.0.1".to_owned());
    let secret = env::var("OPENAUTH_SECRET")
        .unwrap_or_else(|_| "secret-a-at-least-32-chars-long!!".to_owned());
    let stripe_key = env::var("STRIPE_SECRET_KEY").map_err(|_| "STRIPE_SECRET_KEY is required")?;
    let price_pro =
        env::var("STRIPE_PRICE_PRO_MONTHLY").map_err(|_| "STRIPE_PRICE_PRO_MONTHLY is required")?;

    let listener = tokio::net::TcpListener::bind(format!("{host}:0")).await?;
    let port = listener.local_addr()?.port();
    let base_url = format!("http://{host}:{port}{AUTH_BASE_PATH}");
    let webhook_url = format!("{base_url}/stripe/webhook");

    eprintln!("Stripe smoke server binding to http://{host}:{port}{AUTH_BASE_PATH}");
    eprintln!("Starting `stripe listen` (test mode signing secret, not read from .env)...");

    let mut stripe_listen = spawn_stripe_listen(&webhook_url)?;
    let webhook_secret = read_webhook_secret_from_listen(&mut stripe_listen).await?;
    eprintln!("Using webhook signing secret from Stripe CLI: {webhook_secret}");

    let plugin = stripe(
        StripeOptions::new(StripeClient::new(stripe_key), webhook_secret.clone())
            .create_customer_on_sign_up(true)
            .subscription(SubscriptionOptions::enabled(vec![
                StripePlan::new("pro").price_id(price_pro)
            ])),
    );

    let auth = OpenAuth::builder()
        .base_url(base_url.clone())
        .base_path(AUTH_BASE_PATH.to_owned())
        .secret(secret)
        .advanced(
            AdvancedOptions::builder()
                .disable_csrf_check(true)
                .disable_origin_check(true),
        )
        .plugin(plugin)
        .adapter(MemoryAdapter::new())
        .build()?;

    let app = Router::new().nest(AUTH_BASE_PATH, auth.into_routes());

    eprintln!("Webhook URL: {webhook_url}");
    eprintln!("Press Ctrl+C to stop (also stops `stripe listen`).");
    eprintln!(
        "Note: `stripe trigger` via listen may return 400 if the CLI re-encodes the body; use Checkout or the signed self-test on startup."
    );

    let serve = axum::serve(listener, app);
    let server = tokio::spawn(async move { serve.await.map_err(|error| error.to_string()) });
    tokio::time::sleep(Duration::from_millis(200)).await;
    smoke_webhook_self_test(&webhook_url, &webhook_secret).await?;

    tokio::select! {
        result = server => result.map_err(|error| error.to_string())??,
        status = stripe_listen.wait() => {
            let status = status?;
            return Err(format!("stripe listen exited unexpectedly: {status}").into());
        }
    }

    Ok(())
}

fn spawn_stripe_listen(webhook_url: &str) -> Result<Child, Box<dyn std::error::Error>> {
    let shell_command = format!(
        "stripe listen --forward-to '{webhook_url}' --events checkout.session.completed,customer.subscription.created,customer.subscription.updated,customer.subscription.deleted 2>&1"
    );
    let child = Command::new("sh")
        .arg("-c")
        .arg(shell_command)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    Ok(child)
}

async fn read_webhook_secret_from_listen(
    child: &mut Child,
) -> Result<String, Box<dyn std::error::Error>> {
    let stdout = child
        .stdout
        .take()
        .ok_or("stripe listen output was not captured")?;
    let mut lines = BufReader::new(stdout).lines();

    let secret = match timeout(Duration::from_secs(45), async {
        while let Some(line) = lines.next_line().await? {
            eprintln!("[stripe listen] {line}");
            if let Some(rest) = line.split("whsec_").nth(1) {
                let token: String = rest
                    .chars()
                    .take_while(|character| character.is_ascii_hexdigit())
                    .collect();
                if !token.is_empty() {
                    return Ok(format!("whsec_{token}"));
                }
            }
        }
        Err("stripe listen ended before printing a signing secret".into())
    })
    .await
    {
        Ok(Ok(secret)) => secret,
        Ok(Err(error)) => return Err(error),
        Err(_) => {
            return Err("timed out waiting for stripe listen signing secret".into());
        }
    };

    tokio::spawn(async move {
        while let Ok(Some(line)) = lines.next_line().await {
            eprintln!("[stripe listen] {line}");
        }
    });

    Ok(secret)
}

async fn smoke_webhook_self_test(
    webhook_url: &str,
    webhook_secret: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use time::OffsetDateTime;

    let payload = br#"{"id":"evt_smoke_self_test","type":"customer.subscription.created","data":{"object":{"id":"sub_smoke_self","customer":"cus_smoke","status":"active","metadata":{},"cancel_at_period_end":false,"items":{"data":[{"id":"si_smoke","price":{"id":"price_smoke","recurring":{"interval":"month","usage_type":"licensed"}},"quantity":1}]}}}}"#;
    let timestamp = OffsetDateTime::now_utc().unix_timestamp();
    let signing_key = openauth_stripe::stripe_api::webhook_signing_key(webhook_secret)
        .map_err(|error| error.to_string())?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&signing_key)
        .map_err(|error| format!("failed to build webhook self-test HMAC: {error}"))?;
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(payload);
    let signature = hex::encode(mac.finalize().into_bytes());
    let header = format!("t={timestamp},v1={signature}");

    let client = reqwest::Client::new();
    let response = client
        .post(webhook_url)
        .header("stripe-signature", header)
        .header("content-type", "application/json")
        .body(payload.as_ref())
        .send()
        .await?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(format!("webhook self-test failed: HTTP {status} {body}").into());
    }
    eprintln!("Webhook self-test OK (HTTP {status})");
    Ok(())
}
