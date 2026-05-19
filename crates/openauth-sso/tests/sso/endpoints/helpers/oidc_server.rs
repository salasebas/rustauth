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
        let (valid_id_token, public_jwk) =
            signed_oidc_id_token("client_123456", "https://idp.example.com")?;
        let jwks_body = json!({ "keys": [public_jwk] }).to_string();
        let captured_token_requests = std::sync::Arc::clone(&token_requests);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let valid_id_token = valid_id_token.clone();
                let jwks_body = jwks_body.clone();
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
                    let (status, body) = if request.starts_with("POST /token ")
                        && request.contains("code=id-token-code")
                    {
                        (
                            "200 OK",
                            r#"{"access_token":"access-token","token_type":"Bearer","scope":"openid email profile","id_token":"invalid-id-token"}"#.to_owned(),
                        )
                    } else if request.starts_with("POST /token ")
                        && request.contains("code=valid-id-token-code")
                    {
                        (
                            "200 OK",
                            format!(
                                r#"{{"access_token":"access-token","token_type":"Bearer","scope":"openid email profile","id_token":{}}}"#,
                                serde_json::to_string(&valid_id_token).unwrap_or_default()
                            ),
                        )
                    } else if request.starts_with("POST /token ") {
                        (
                            "200 OK",
                            r#"{"access_token":"access-token","token_type":"Bearer","scope":"openid email profile"}"#.to_owned(),
                        )
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

pub(crate) fn signed_oidc_id_token(
    audience: &str,
    issuer: &str,
) -> Result<(String, Jwk), Box<dyn std::error::Error>> {
    let kid = "sso-test-key";
    let mut jwk = Jwk::generate_rsa_key(2048)?;
    jwk.set_key_id(kid);
    jwk.set_algorithm("RS256");
    jwk.set_key_use("sig");

    let signer = Rs256.signer_from_jwk(&jwk)?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let mut payload = JwtPayload::new();
    payload.set_claim("aud", Some(json!(audience)))?;
    payload.set_claim("iss", Some(json!(issuer)))?;
    payload.set_claim("sub", Some(json!("subject_123")))?;
    payload.set_claim("email", Some(json!("sso-user@example.com")))?;
    payload.set_claim("email_verified", Some(json!(true)))?;
    payload.set_claim("iat", Some(json!(now)))?;
    payload.set_claim("exp", Some(json!(now + 3600)))?;

    let mut header = JwsHeader::new();
    header.set_algorithm("RS256");
    header.set_key_id(kid);
    let token = jwt::encode_with_signer(&payload, &header, &signer)?;
    let mut public_jwk = jwk.to_public_key()?;
    public_jwk.set_key_id(kid);
    public_jwk.set_algorithm("RS256");
    public_jwk.set_key_use("sig");
    Ok((token, public_jwk))
}
