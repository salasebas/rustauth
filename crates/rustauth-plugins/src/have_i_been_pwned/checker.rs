//! Have I Been Pwned k-anonymity range checker.

use sha1::{Digest, Sha1};
use std::future::Future;
use std::pin::Pin;

const HIBP_USER_AGENT: &str = "BetterAuth Password Checker";

pub type HaveIBeenPwnedCheckFuture<'a> =
    Pin<Box<dyn Future<Output = Result<bool, HaveIBeenPwnedCheckError>> + Send + 'a>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HaveIBeenPwnedCheckError {
    HttpStatus(u16),
    Transport(String),
}

pub trait HaveIBeenPwnedChecker: Send + Sync + std::fmt::Debug {
    fn is_hash_suffix_compromised<'a>(
        &'a self,
        prefix: &'a str,
        suffix: &'a str,
    ) -> HaveIBeenPwnedCheckFuture<'a>;
}

#[derive(Debug, Clone)]
pub struct ReqwestHaveIBeenPwnedChecker {
    client: reqwest::Client,
    base_url: String,
}

impl Default for ReqwestHaveIBeenPwnedChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl ReqwestHaveIBeenPwnedChecker {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: "https://api.pwnedpasswords.com".to_owned(),
        }
    }

    #[cfg(test)]
    fn with_base_url(base_url: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.into(),
        }
    }

    fn range_request(&self, prefix: &str) -> Result<reqwest::Request, reqwest::Error> {
        let url = format!("{}/range/{prefix}", self.base_url.trim_end_matches('/'));
        self.client
            .get(url)
            .header("Add-Padding", "true")
            .header("User-Agent", HIBP_USER_AGENT)
            .build()
    }
}

impl HaveIBeenPwnedChecker for ReqwestHaveIBeenPwnedChecker {
    fn is_hash_suffix_compromised<'a>(
        &'a self,
        prefix: &'a str,
        suffix: &'a str,
    ) -> HaveIBeenPwnedCheckFuture<'a> {
        Box::pin(async move {
            let request = self
                .range_request(prefix)
                .map_err(|error| HaveIBeenPwnedCheckError::Transport(error.to_string()))?;
            let response = self
                .client
                .execute(request)
                .await
                .map_err(|error| HaveIBeenPwnedCheckError::Transport(error.to_string()))?;
            if !response.status().is_success() {
                return Err(HaveIBeenPwnedCheckError::HttpStatus(
                    response.status().as_u16(),
                ));
            }
            let body = response
                .text()
                .await
                .map_err(|error| HaveIBeenPwnedCheckError::Transport(error.to_string()))?;
            Ok(range_response_contains_suffix(&body, suffix))
        })
    }
}

pub(crate) fn sha1_prefix_suffix(password: &str) -> (String, String) {
    let digest = Sha1::digest(password.as_bytes());
    let hash = hex::encode_upper(digest);
    let prefix = hash[..5].to_owned();
    let suffix = hash[5..].to_owned();
    (prefix, suffix)
}

pub(crate) fn range_response_contains_suffix(body: &str, suffix: &str) -> bool {
    body.lines().any(|line| {
        let Some((candidate, _count)) = line.trim().split_once(':') else {
            return false;
        };
        candidate.eq_ignore_ascii_case(suffix)
    })
}

#[cfg(test)]
mod tests {
    use super::{
        range_response_contains_suffix, sha1_prefix_suffix, ReqwestHaveIBeenPwnedChecker,
        HIBP_USER_AGENT,
    };

    #[test]
    fn range_response_matches_suffix_case_insensitively_with_crlf() {
        let body = "ABCDEF:1\r\n00ff00:2\r\n";

        assert!(range_response_contains_suffix(body, "00FF00"));
    }

    #[test]
    fn range_response_ignores_non_matching_suffixes() {
        let body = "ABCDEF:1\n123456:2\n";

        assert!(!range_response_contains_suffix(body, "999999"));
    }

    #[test]
    fn sha1_prefix_suffix_uses_uppercase_hex_and_splits_after_five_chars() {
        let (prefix, suffix) = sha1_prefix_suffix("123456789");

        assert_eq!(prefix, "F7C3B");
        assert_eq!(suffix, "C1D808E04732ADF679965CCC34CA7AE3441");
    }

    #[test]
    fn reqwest_checker_uses_range_endpoint_padding_and_upstream_user_agent(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let checker = ReqwestHaveIBeenPwnedChecker::with_base_url("http://hibp.test/");

        let request = checker.range_request("ABCDE")?;

        assert!(
            request.url().as_str() == "http://hibp.test/range/ABCDE",
            "request URL should include only the k-anonymity hash prefix"
        );
        assert_eq!(
            request
                .headers()
                .get("Add-Padding")
                .and_then(|value| value.to_str().ok()),
            Some("true")
        );
        assert_eq!(
            request
                .headers()
                .get("User-Agent")
                .and_then(|value| value.to_str().ok()),
            Some(HIBP_USER_AGENT)
        );
        assert!(!request.url().as_str().contains("012345"));
        Ok(())
    }
}
