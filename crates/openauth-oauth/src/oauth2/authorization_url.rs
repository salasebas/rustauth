use std::collections::BTreeMap;

use serde_json::json;
use url::Url;

use super::error::OAuthError;
use super::request::is_protected_oauth_param;
use super::tokens::{get_primary_client_id, ProviderOptions};
use super::utils::generate_code_challenge;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationUrlRequest {
    pub id: String,
    pub options: ProviderOptions,
    pub authorization_endpoint: String,
    pub redirect_uri: String,
    pub state: String,
    pub code_verifier: Option<String>,
    pub scopes: Vec<String>,
    pub claims: Vec<String>,
    pub duration: Option<String>,
    pub prompt: Option<String>,
    pub access_type: Option<String>,
    pub response_type: Option<String>,
    pub display: Option<String>,
    pub login_hint: Option<String>,
    pub hd: Option<String>,
    pub response_mode: Option<String>,
    pub additional_params: BTreeMap<String, String>,
    pub scope_joiner: String,
}

impl Default for AuthorizationUrlRequest {
    fn default() -> Self {
        Self {
            id: String::new(),
            options: ProviderOptions::default(),
            authorization_endpoint: String::new(),
            redirect_uri: String::new(),
            state: String::new(),
            code_verifier: None,
            scopes: Vec::new(),
            claims: Vec::new(),
            duration: None,
            prompt: None,
            access_type: None,
            response_type: None,
            display: None,
            login_hint: None,
            hd: None,
            response_mode: None,
            additional_params: BTreeMap::new(),
            scope_joiner: " ".to_owned(),
        }
    }
}

impl AuthorizationUrlRequest {
    pub fn try_new(
        id: impl Into<String>,
        options: ProviderOptions,
        authorization_endpoint: impl Into<String>,
        redirect_uri: impl Into<String>,
        state: impl Into<String>,
    ) -> Result<Self, OAuthError> {
        let authorization_endpoint = authorization_endpoint.into();
        let redirect_uri = redirect_uri.into();
        url::Url::parse(
            options
                .authorization_endpoint
                .as_deref()
                .unwrap_or(&authorization_endpoint),
        )?;
        url::Url::parse(options.redirect_uri.as_deref().unwrap_or(&redirect_uri))?;
        get_primary_client_id(&options.client_id).ok_or(OAuthError::MissingOption("client_id"))?;
        let state = state.into();
        if state.is_empty() {
            return Err(OAuthError::InvalidConfiguration(
                "authorization state cannot be empty".to_owned(),
            ));
        }
        Ok(Self {
            id: id.into(),
            options,
            authorization_endpoint,
            redirect_uri,
            state,
            ..Self::default()
        })
    }

    pub fn code_verifier(mut self, code_verifier: impl Into<String>) -> Self {
        self.code_verifier = Some(code_verifier.into());
        self
    }

    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.scopes.push(scope.into());
        self
    }

    pub fn scopes(mut self, scopes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.scopes.extend(scopes.into_iter().map(Into::into));
        self
    }

    pub fn claim(mut self, claim: impl Into<String>) -> Self {
        self.claims.push(claim.into());
        self
    }

    /// Adds a non-sensitive extension query parameter. Security-critical keys
    /// (`state`, `redirect_uri`, `response_type`, `client_id`, and PKCE
    /// challenge fields) are ignored so they cannot override validated flow
    /// invariants.
    pub fn additional_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.additional_params.insert(key.into(), value.into());
        self
    }
}

/// Validates non-empty OAuth `state` and a parseable effective `redirect_uri`.
///
/// Manual provider URL builders that do not use [`create_authorization_url`]
/// should call this before emitting redirect URLs.
pub fn validate_authorization_url_invariants(
    state: &str,
    options_redirect_uri: Option<&str>,
    request_redirect_uri: &str,
) -> Result<(), OAuthError> {
    if state.is_empty() {
        return Err(OAuthError::InvalidConfiguration(
            "authorization state cannot be empty".to_owned(),
        ));
    }
    let redirect_uri = options_redirect_uri.unwrap_or(request_redirect_uri);
    Url::parse(redirect_uri)?;
    Ok(())
}

pub fn create_authorization_url(input: AuthorizationUrlRequest) -> Result<Url, OAuthError> {
    validate_authorization_url_request(&input)?;
    let endpoint = input
        .options
        .authorization_endpoint
        .as_deref()
        .unwrap_or(&input.authorization_endpoint);
    let mut url = Url::parse(endpoint)?;
    let client_id = get_primary_client_id(&input.options.client_id)
        .ok_or(OAuthError::MissingOption("client_id"))?;
    set_query_pair(
        &mut url,
        "response_type",
        input.response_type.as_deref().unwrap_or("code"),
    );
    set_query_pair(&mut url, "client_id", client_id);
    set_query_pair(&mut url, "state", &input.state);
    if !input.scopes.is_empty() {
        set_query_pair(&mut url, "scope", &input.scopes.join(&input.scope_joiner));
    }
    set_query_pair(
        &mut url,
        "redirect_uri",
        input
            .options
            .redirect_uri
            .as_deref()
            .unwrap_or(&input.redirect_uri),
    );
    set_optional_query_pair(&mut url, "duration", input.duration.as_deref());
    set_optional_query_pair(&mut url, "display", input.display.as_deref());
    set_optional_query_pair(&mut url, "login_hint", input.login_hint.as_deref());
    set_optional_query_pair(&mut url, "prompt", input.prompt.as_deref());
    set_optional_query_pair(&mut url, "hd", input.hd.as_deref());
    set_optional_query_pair(&mut url, "access_type", input.access_type.as_deref());
    set_optional_query_pair(&mut url, "response_mode", input.response_mode.as_deref());
    if let Some(code_verifier) = input.code_verifier {
        set_query_pair(&mut url, "code_challenge_method", "S256");
        set_query_pair(
            &mut url,
            "code_challenge",
            &generate_code_challenge(&code_verifier)?,
        );
    }
    if !input.claims.is_empty() {
        let mut id_token = serde_json::Map::from_iter([
            ("email".to_owned(), serde_json::Value::Null),
            ("email_verified".to_owned(), serde_json::Value::Null),
        ]);
        for claim in input.claims {
            id_token.insert(claim, serde_json::Value::Null);
        }
        set_query_pair(
            &mut url,
            "claims",
            &json!({ "id_token": id_token }).to_string(),
        );
    }
    for (key, value) in input.additional_params {
        if is_protected_oauth_param(&key) {
            continue;
        }
        set_query_pair(&mut url, &key, &value);
    }
    Ok(url)
}

fn validate_authorization_url_request(input: &AuthorizationUrlRequest) -> Result<(), OAuthError> {
    get_primary_client_id(&input.options.client_id)
        .ok_or(OAuthError::MissingOption("client_id"))?;
    validate_authorization_url_invariants(
        &input.state,
        input.options.redirect_uri.as_deref(),
        &input.redirect_uri,
    )?;
    let endpoint = input
        .options
        .authorization_endpoint
        .as_deref()
        .unwrap_or(&input.authorization_endpoint);
    Url::parse(endpoint)?;
    Ok(())
}

fn set_optional_query_pair(url: &mut Url, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        set_query_pair(url, key, value);
    }
}

fn set_query_pair(url: &mut Url, key: &str, value: &str) {
    let mut pairs = url.query_pairs().into_owned().collect::<Vec<_>>();
    pairs.retain(|(existing, _)| existing != key);
    pairs.push((key.to_owned(), value.to_owned()));
    url.set_query(None);
    for (key, value) in pairs {
        url.query_pairs_mut().append_pair(&key, &value);
    }
}
