use openauth_core::db::DbAdapter;
use openauth_core::error::OpenAuthError;

use crate::consent::{find_consent, has_granted_scopes};
use crate::models::SchemaClient;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizeDecision {
    IssueCode,
    RedirectToLogin,
    RedirectToConsent,
    RedirectError {
        error: &'static str,
        description: &'static str,
    },
}

pub async fn decide_authorize(
    adapter: &dyn DbAdapter,
    client: &SchemaClient,
    session_user_id: Option<&str>,
    requested_scopes: &[String],
    prompt: Option<&str>,
) -> Result<AuthorizeDecision, OpenAuthError> {
    let prompt = PromptSet::parse(prompt);
    let prompt_none = prompt.contains("none");
    if session_user_id.is_none() || prompt.contains("login") {
        return if prompt_none {
            Ok(AuthorizeDecision::RedirectError {
                error: "login_required",
                description: "authentication required",
            })
        } else {
            Ok(AuthorizeDecision::RedirectToLogin)
        };
    }

    if prompt.contains("consent") {
        return if prompt_none {
            Ok(AuthorizeDecision::RedirectError {
                error: "consent_required",
                description: "End-User consent is required",
            })
        } else {
            Ok(AuthorizeDecision::RedirectToConsent)
        };
    }

    if client.skip_consent == Some(true) {
        return Ok(AuthorizeDecision::IssueCode);
    }

    let user_id = session_user_id.unwrap_or_default();
    let consent = find_consent(adapter, user_id, &client.client_id).await?;
    if consent
        .as_ref()
        .is_some_and(|consent| has_granted_scopes(consent, requested_scopes))
    {
        return Ok(AuthorizeDecision::IssueCode);
    }

    if prompt_none {
        Ok(AuthorizeDecision::RedirectError {
            error: "consent_required",
            description: "End-User consent is required",
        })
    } else {
        Ok(AuthorizeDecision::RedirectToConsent)
    }
}

struct PromptSet<'a> {
    values: Vec<&'a str>,
}

impl<'a> PromptSet<'a> {
    fn parse(prompt: Option<&'a str>) -> Self {
        Self {
            values: prompt
                .unwrap_or_default()
                .split_whitespace()
                .filter(|value| !value.is_empty())
                .collect(),
        }
    }

    fn contains(&self, prompt: &str) -> bool {
        self.values.iter().any(|value| value == &prompt)
    }
}
