use josekit::jwk::Jwk;
use josekit::jws::alg::rsassa::RsassaJwsAlgorithm::Rs256;
use josekit::jws::JwsHeader;
use josekit::jwt::{self, JwtPayload};
use serde_json::json;

pub(crate) struct MockOidcServer {
    pub(crate) base_url: String,
    token_requests: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

impl MockOidcServer {
    pub(crate) async fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let base_url = format!("http://{address}");
        let token_requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        // A single signing key backs every minted ID token. The mock signs
        // tokens on demand at `/token` time so each token can echo the
        // per-flow `nonce` (which the test threads in via the authorization
        // `code`), mirroring how a real IdP binds the nonce from the
        // authorization request into the issued ID token.
        let mut default_jwk = Jwk::generate_rsa_key(2048)?;
        default_jwk.set_key_id(DEFAULT_KEY_ID);
        default_jwk.set_algorithm("RS256");
        default_jwk.set_key_use("sig");
        let mut public_jwk = default_jwk.to_public_key()?;
        public_jwk.set_key_id(DEFAULT_KEY_ID);
        public_jwk.set_algorithm("RS256");
        public_jwk.set_key_use("sig");
        let jwks_body = json!({ "keys": [public_jwk] }).to_string();
        let captured_token_requests = std::sync::Arc::clone(&token_requests);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let jwks_body = jwks_body.clone();
                let default_jwk = default_jwk.clone();
                let captured_token_requests = std::sync::Arc::clone(&captured_token_requests);
                tokio::spawn(async move {
                    let mut buffer = [0_u8; 4096];
                    let Ok(read) = tokio::io::AsyncReadExt::read(&mut stream, &mut buffer).await
                    else {
                        return;
                    };
                    let request = String::from_utf8_lossy(&buffer[..read]);
                    if request.starts_with("POST /token ") {
                        if let Ok(mut requests) = captured_token_requests.lock() {
                            requests.push(request.to_string());
                        }
                    }
                    let (status, body) = if request.starts_with("POST /token ") {
                        // The test threads the per-flow nonce by appending
                        // `.<nonce>` to the authorization `code`. Split it back
                        // out and mint a freshly signed ID token that echoes
                        // the nonce, so the callback's fail-closed nonce check
                        // can be exercised exactly as in production.
                        let code = form_field(&request, "code").unwrap_or_default();
                        let (selector, nonce) = match code.split_once('.') {
                            Some((selector, nonce)) => (selector, Some(nonce)),
                            None => (code.as_str(), None),
                        };
                        // Some providers (runtime discovery, self-hosted IdPs)
                        // register the mock's own origin as their issuer, so
                        // expose it to the minter to produce matching tokens.
                        let self_issuer = format!(
                            "http://{}",
                            stream
                                .local_addr()
                                .map(|addr| addr.to_string())
                                .unwrap_or_default()
                        );
                        if selector == "id-token-code" {
                            (
                                "200 OK",
                                r#"{"access_token":"access-token","token_type":"Bearer","scope":"openid email profile","id_token":"invalid-id-token"}"#.to_owned(),
                            )
                        } else if let Some(id_token) =
                            mint_dynamic_id_token(&default_jwk, &self_issuer, selector, nonce)
                        {
                            (
                                "200 OK",
                                format!(
                                    r#"{{"access_token":"access-token","token_type":"Bearer","scope":"openid email profile","id_token":{}}}"#,
                                    serde_json::to_string(&id_token).unwrap_or_default()
                                ),
                            )
                        } else {
                            (
                                "200 OK",
                                r#"{"access_token":"access-token","token_type":"Bearer","scope":"openid email profile"}"#.to_owned(),
                            )
                        }
                    } else if request.starts_with("GET /.well-known/openid-configuration ") {
                        let issuer = format!(
                            "http://{}",
                            stream
                                .local_addr()
                                .map(|addr| addr.to_string())
                                .unwrap_or_default()
                        );
                        let body = format!(
                            r#"{{
                                "issuer":"{issuer}",
                                "authorization_endpoint":"{issuer}/authorize",
                                "token_endpoint":"{issuer}/token",
                                "jwks_uri":"{issuer}/keys",
                                "userinfo_endpoint":"{issuer}/userinfo",
                                "revocation_endpoint":"{issuer}/revoke",
                                "end_session_endpoint":"{issuer}/endsession",
                                "introspection_endpoint":"{issuer}/introspection",
                                "token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post"],
                                "scopes_supported":["openid","email","profile"]
                            }}"#
                        );
                        ("200 OK", body)
                    } else if request.starts_with("GET /mapped-userinfo ") {
                        (
                            "200 OK",
                            r#"{"external_id":"mapped_subject","mail":"mapped-user@example.com","verified":true,"display":"Mapped User","avatar":"https://example.com/mapped.png","department":"Engineering","employee_number":"E-123"}"#.to_owned(),
                        )
                    } else if request.starts_with("GET /mixed-case-userinfo ") {
                        (
                            "200 OK",
                            r#"{"sub":"subject_123","email":"SSO-User@Example.Com","email_verified":true,"name":"SSO User","picture":"https://example.com/avatar.png"}"#.to_owned(),
                        )
                    } else if request.starts_with("GET /missing-sub-userinfo ") {
                        (
                            "200 OK",
                            r#"{"email":"missing-sub@example.com","email_verified":true,"name":"Missing Sub","picture":"https://example.com/avatar.png"}"#.to_owned(),
                        )
                    } else if request.starts_with("GET /fixtures/google/userinfo ") {
                        (
                            "200 OK",
                            r#"{"sub":"google-sub-123","email":"Google.User@Example.COM","email_verified":true,"name":"Google Workspace User","picture":"https://lh3.googleusercontent.com/a/example","hd":"example.com","locale":"en-US"}"#.to_owned(),
                        )
                    } else if request.starts_with("GET /fixtures/google/unverified-userinfo ") {
                        (
                            "200 OK",
                            r#"{"sub":"google-unverified-sub","email":"sso-user@example.com","email_verified":false,"name":"Unverified Google User","picture":"https://lh3.googleusercontent.com/a/unverified","hd":"example.com","locale":"en-US"}"#.to_owned(),
                        )
                    } else if request.starts_with("GET /fixtures/azure/userinfo ") {
                        (
                            "200 OK",
                            r#"{"sub":"azure-sub-456","oid":"azure-oid-456","tid":"tenant-123","preferred_username":"Ada@Contoso.COM","upn":"ada@contoso.com","email_verified":true,"name":"Ada Lovelace"}"#.to_owned(),
                        )
                    } else if request
                        .starts_with("GET /fixtures/azure/missing-preferred-username-userinfo ")
                    {
                        (
                            "200 OK",
                            r#"{"sub":"azure-sub-missing-email","oid":"azure-oid-missing-email","tid":"tenant-123","upn":"ada@contoso.com","email_verified":true,"name":"Ada Lovelace"}"#.to_owned(),
                        )
                    } else if request.starts_with("GET /fixtures/okta/userinfo ") {
                        (
                            "200 OK",
                            r#"{"sub":"okta-sub-789","email":"Okta.User@Example.COM","email_verified":true,"name":"Okta User","zoneinfo":"America/Monterrey","groups":["Engineering","Admins"]}"#.to_owned(),
                        )
                    } else if request.starts_with("GET /fixtures/okta/missing-sub-userinfo ") {
                        (
                            "200 OK",
                            r#"{"email":"Okta.User@Example.COM","email_verified":true,"name":"Okta User","zoneinfo":"America/Monterrey","groups":["Engineering","Admins"]}"#.to_owned(),
                        )
                    } else if request.starts_with("GET /userinfo ") {
                        (
                            "200 OK",
                            r#"{"sub":"subject_123","email":"sso-user@example.com","email_verified":true,"name":"SSO User","picture":"https://example.com/avatar.png"}"#.to_owned(),
                        )
                    } else if request.starts_with("GET /keys ") {
                        ("200 OK", jwks_body)
                    } else {
                        ("404 Not Found", r#"{"error":"not_found"}"#.to_owned())
                    };
                    let response = format!(
                        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ =
                        tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes()).await;
                });
            }
        });
        Ok(Self {
            base_url,
            token_requests,
        })
    }

    pub(crate) fn token_requests(&self) -> Vec<String> {
        self.token_requests
            .lock()
            .map(|requests| requests.clone())
            .unwrap_or_default()
    }
}

const DEFAULT_KEY_ID: &str = "sso-test-key";

/// Extracts a single field value from an `application/x-www-form-urlencoded`
/// request body. The mock only inspects unencoded fields (`code`), so parsing
/// is intentionally minimal.
fn form_field(request: &str, key: &str) -> Option<String> {
    let body = request.split("\r\n\r\n").nth(1)?;
    body.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        if name == key {
            Some(value.trim().to_owned())
        } else {
            None
        }
    })
}

/// Mints a freshly signed ID token for the given authorization `code`
/// selector, echoing `nonce` whenever the scenario expects a valid nonce.
///
/// Returns `None` for codes that do not drive the ID-token path (for example
/// the userinfo-path `auth-code`), so the caller falls back to an
/// access-token-only token response.
fn mint_dynamic_id_token(
    jwk: &Jwk,
    self_issuer: &str,
    selector: &str,
    nonce: Option<&str>,
) -> Option<String> {
    const DEFAULT_ISSUER: &str = "https://idp.example.com";
    const TENANT_ISSUER: &str =
        "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0";
    const WRONG_TENANT_ISSUER: &str =
        "https://login.microsoftonline.com/22222222-2222-2222-2222-222222222222/v2.0";
    const GOOGLE_ISSUER: &str = "https://accounts.google.com";
    const OKTA_ISSUER: &str = "https://dev-123456.okta.com/oauth2/default";
    const AUDIENCE: &str = "client_123456";

    let with_nonce = |mut options: IdTokenOptions| -> IdTokenOptions {
        if let Some(nonce) = nonce {
            options
                .extra_claims
                .push(("nonce".to_owned(), json!(nonce)));
        }
        options
    };

    let userinfo_subject = |subject: &str| -> IdTokenOptions {
        with_nonce(IdTokenOptions {
            subject: subject.to_owned(),
            ..IdTokenOptions::default()
        })
    };

    let (issuer, options) = match selector {
        "valid-id-token-code" => (DEFAULT_ISSUER, with_nonce(IdTokenOptions::default())),
        // A provider that registered the mock's own origin as its issuer (for
        // example runtime discovery). Mints a nonce-bound token whose `iss`
        // matches that origin so the UserInfo path can be validated.
        "self-issued-id-token-code" => (self_issuer, with_nonce(IdTokenOptions::default())),
        // UserInfo-path fixtures: each mints a valid, nonce-bound ID token
        // whose `iss` matches the registered provider issuer and whose `sub`
        // matches the corresponding UserInfo fixture subject, so the callback's
        // subject reconciliation succeeds.
        "google-userinfo-id-token-code" => (GOOGLE_ISSUER, userinfo_subject("google-sub-123")),
        "google-unverified-userinfo-id-token-code" => {
            (GOOGLE_ISSUER, userinfo_subject("google-unverified-sub"))
        }
        "okta-userinfo-id-token-code" => (OKTA_ISSUER, userinfo_subject("okta-sub-789")),
        "azure-userinfo-id-token-code" => (TENANT_ISSUER, userinfo_subject("azure-sub-456")),
        "missing-exp-id-token-code" => (
            DEFAULT_ISSUER,
            with_nonce(IdTokenOptions {
                include_exp: false,
                ..IdTokenOptions::default()
            }),
        ),
        "missing-sub-id-token-code" => (
            DEFAULT_ISSUER,
            with_nonce(IdTokenOptions {
                include_sub: false,
                ..IdTokenOptions::default()
            }),
        ),
        // Intentionally omit the `nonce` claim even though the flow expected
        // one: exercises the fail-closed "missing nonce" rejection.
        "id-token-missing-nonce-code" => (DEFAULT_ISSUER, IdTokenOptions::default()),
        // Echo a `nonce` that does not match the flow's nonce: exercises the
        // fail-closed "nonce mismatch" rejection.
        "id-token-wrong-nonce-code" => (
            DEFAULT_ISSUER,
            IdTokenOptions {
                extra_claims: vec![("nonce".to_owned(), json!("unexpected-nonce-value"))],
                ..IdTokenOptions::default()
            },
        ),
        "azure-id-token-code" => (TENANT_ISSUER, with_nonce(IdTokenOptions::azure())),
        "azure-wrong-issuer-id-token-code" => (
            TENANT_ISSUER,
            with_nonce(IdTokenOptions {
                issuer: Some(WRONG_TENANT_ISSUER.to_owned()),
                ..IdTokenOptions::azure()
            }),
        ),
        "multi-audience-missing-azp-code" => (
            DEFAULT_ISSUER,
            with_nonce(IdTokenOptions {
                audience_claim: Some(json!(["client_123456", "secondary-client"])),
                ..IdTokenOptions::default()
            }),
        ),
        "multi-audience-wrong-azp-code" => (
            DEFAULT_ISSUER,
            with_nonce(IdTokenOptions {
                audience_claim: Some(json!(["client_123456", "secondary-client"])),
                extra_claims: vec![("azp".to_owned(), json!("other-client"))],
                ..IdTokenOptions::default()
            }),
        ),
        "multi-audience-valid-azp-code" => (
            DEFAULT_ISSUER,
            with_nonce(IdTokenOptions {
                audience_claim: Some(json!(["client_123456", "secondary-client"])),
                extra_claims: vec![("azp".to_owned(), json!("client_123456"))],
                ..IdTokenOptions::default()
            }),
        ),
        _ => return None,
    };

    sign_id_token_with_jwk(jwk, AUDIENCE, issuer, options).ok()
}

#[derive(Debug, Clone)]
pub(crate) struct IdTokenOptions {
    pub(crate) include_sub: bool,
    pub(crate) include_exp: bool,
    pub(crate) issuer: Option<String>,
    pub(crate) subject: String,
    pub(crate) email: Option<String>,
    pub(crate) email_verified: Option<bool>,
    pub(crate) name: Option<String>,
    pub(crate) picture: Option<String>,
    pub(crate) audience_claim: Option<serde_json::Value>,
    pub(crate) extra_claims: Vec<(String, serde_json::Value)>,
}

impl Default for IdTokenOptions {
    fn default() -> Self {
        Self {
            include_sub: true,
            include_exp: true,
            issuer: None,
            subject: "subject_123".to_owned(),
            email: Some("sso-user@example.com".to_owned()),
            email_verified: Some(true),
            name: None,
            picture: None,
            audience_claim: None,
            extra_claims: Vec::new(),
        }
    }
}

impl IdTokenOptions {
    fn azure() -> Self {
        Self {
            issuer: Some(
                "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0"
                    .to_owned(),
            ),
            subject: "azure-token-sub-456".to_owned(),
            email: Some("token.user@contoso.com".to_owned()),
            email_verified: Some(true),
            name: Some("Token User".to_owned()),
            extra_claims: vec![
                ("oid".to_owned(), json!("azure-token-oid-456")),
                ("tid".to_owned(), json!("tenant-123")),
                (
                    "preferred_username".to_owned(),
                    json!("Token.User@Contoso.COM"),
                ),
            ],
            ..Self::default()
        }
    }
}

/// Signs an ID token with the provided key, deriving the JWS `kid` from the
/// key itself so every token validates against the mock's published JWKS.
fn sign_id_token_with_jwk(
    jwk: &Jwk,
    audience: &str,
    issuer: &str,
    options: IdTokenOptions,
) -> Result<String, Box<dyn std::error::Error>> {
    let signer = Rs256.signer_from_jwk(jwk)?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let mut payload = JwtPayload::new();
    payload.set_claim(
        "aud",
        Some(options.audience_claim.unwrap_or_else(|| json!(audience))),
    )?;
    payload.set_claim(
        "iss",
        Some(json!(options.issuer.as_deref().unwrap_or(issuer))),
    )?;
    if options.include_sub {
        payload.set_claim("sub", Some(json!(options.subject)))?;
    }
    if let Some(email) = options.email {
        payload.set_claim("email", Some(json!(email)))?;
    }
    if let Some(email_verified) = options.email_verified {
        payload.set_claim("email_verified", Some(json!(email_verified)))?;
    }
    if let Some(name) = options.name {
        payload.set_claim("name", Some(json!(name)))?;
    }
    if let Some(picture) = options.picture {
        payload.set_claim("picture", Some(json!(picture)))?;
    }
    for (key, value) in options.extra_claims {
        payload.set_claim(&key, Some(value))?;
    }
    payload.set_claim("iat", Some(json!(now)))?;
    if options.include_exp {
        payload.set_claim("exp", Some(json!(now + 3600)))?;
    }

    let mut header = JwsHeader::new();
    header.set_algorithm("RS256");
    header.set_key_id(jwk.key_id().unwrap_or(DEFAULT_KEY_ID));
    Ok(jwt::encode_with_signer(&payload, &header, &signer)?)
}
