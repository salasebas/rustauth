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
use std::net::SocketAddr;
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
    eprintln!("Captured webhook signing secret from Stripe CLI (value redacted).");

    let plugin = stripe(
        StripeOptions::new(StripeClient::new(stripe_key), webhook_secret.clone())
            .create_customer_on_sign_up(true)
            .subscription(SubscriptionOptions::enabled(vec![
                StripePlan::new("pro").price_id(price_pro)
            ])),
    )?;

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

    // Serve with ConnectInfo so OpenAuth rate limiting sees the real peer IP.
    // Behind a reverse proxy, configure trusted forwarding headers explicitly instead.
    let serve = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    );
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

const STRIPE_LISTEN_EVENTS: &str = "checkout.session.completed,customer.subscription.created,customer.subscription.updated,customer.subscription.deleted";

fn stripe_listen_args(webhook_url: &str) -> [&str; 5] {
    [
        "listen",
        "--forward-to",
        webhook_url,
        "--events",
        STRIPE_LISTEN_EVENTS,
    ]
}

fn spawn_stripe_listen(webhook_url: &str) -> Result<Child, Box<dyn std::error::Error>> {
    // Spawn the Stripe CLI directly (no shell) so a hostile OPENAUTH_EXAMPLE_HOST cannot
    // inject shell metacharacters. The signing secret is printed by the CLI on stderr.
    let child = Command::new("stripe")
        .args(stripe_listen_args(webhook_url))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    Ok(child)
}

async fn read_webhook_secret_from_listen(
    child: &mut Child,
) -> Result<String, Box<dyn std::error::Error>> {
    let stderr = child
        .stderr
        .take()
        .ok_or("stripe listen output was not captured")?;
    let mut lines = BufReader::new(stderr).lines();

    let secret = match timeout(Duration::from_secs(45), async {
        while let Some(line) = lines.next_line().await? {
            eprintln!("[stripe listen] {}", redact_webhook_secret(&line));
            if let Some(secret) = parse_webhook_secret(&line) {
                return Ok(secret);
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
            eprintln!("[stripe listen] {}", redact_webhook_secret(&line));
        }
    });

    Ok(secret)
}

/// Extract the full `whsec_` signing secret from a `stripe listen` output line.
///
/// Stripe's signing secret is `whsec_` followed by an alphanumeric token (with
/// letters beyond `a-f`), so this collects every alphanumeric character after the
/// prefix and stops at the first delimiter (whitespace, `(`, or an ANSI escape),
/// which also makes it resilient to terminal color codes wrapping the value.
fn parse_webhook_secret(line: &str) -> Option<String> {
    let token: String = line
        .split("whsec_")
        .nth(1)?
        .chars()
        .take_while(char::is_ascii_alphanumeric)
        .collect();
    (!token.is_empty()).then(|| format!("whsec_{token}"))
}

/// Replace any captured signing secret in a line with a placeholder so the raw
/// `whsec_` value never reaches logs.
fn redact_webhook_secret(line: &str) -> String {
    match parse_webhook_secret(line) {
        Some(secret) => line.replace(&secret, "whsec_<redacted>"),
        None => line.to_owned(),
    }
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
    let mut mac = Hmac::<Sha256>::new_from_slice(webhook_secret.as_bytes())
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

#[cfg(test)]
mod tests {
    use super::{parse_webhook_secret, redact_webhook_secret, stripe_listen_args};

    const REAL_SECRET: &str = "whsec_zGikAg19N5FOHXai7uOuzD8HHErIByOw";

    #[test]
    fn parses_full_alphanumeric_secret_beyond_hex() {
        // The old hex-only parser stopped at the first non-`a-f` char (here `z`).
        let line = format!("Ready! Your webhook signing secret is {REAL_SECRET} (^C to quit)");
        assert_eq!(parse_webhook_secret(&line).as_deref(), Some(REAL_SECRET));
    }

    #[test]
    fn parses_secret_wrapped_in_ansi_codes() {
        let line = format!("signing secret is \u{1b}[1m{REAL_SECRET}\u{1b}[0m (^C to quit)");
        assert_eq!(parse_webhook_secret(&line).as_deref(), Some(REAL_SECRET));
    }

    #[test]
    fn ignores_lines_without_a_secret() {
        assert_eq!(parse_webhook_secret("no secret on this line"), None);
        assert_eq!(parse_webhook_secret("bare whsec_ prefix only"), None);
    }

    #[test]
    fn redaction_removes_the_secret_value() {
        let line = format!("signing secret is \u{1b}[1m{REAL_SECRET}\u{1b}[0m (^C to quit)");
        let redacted = redact_webhook_secret(&line);
        assert!(!redacted.contains(REAL_SECRET));
        assert!(redacted.contains("whsec_<redacted>"));
    }

    #[test]
    fn args_pass_hostile_host_literally() {
        // A shell would split and execute this; `args()` passes it as one literal arg.
        let webhook_url = "http://x'; rm -rf ~; echo ':0/api/auth/stripe/webhook";
        let args = stripe_listen_args(webhook_url);
        assert_eq!(args[0], "listen");
        assert_eq!(args[2], webhook_url);
    }
}
