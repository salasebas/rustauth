use http::Request;
use rustauth_core::api::{parse_request_body, ApiRequest};
use rustauth_core::error::RustAuthError;
use serde::Deserialize;

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct SignInBody {
    email: String,
    password: String,
    #[serde(rename = "rememberMe")]
    remember_me: Option<bool>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct RepeatedBody {
    resource: Vec<String>,
}

#[test]
fn parse_request_body_accepts_json_content_type_with_parameters(
) -> Result<(), Box<dyn std::error::Error>> {
    let request = request(
        "application/json; charset=utf-8",
        br#"{"email":"ada@example.com","password":"secret","rememberMe":false}"#.to_vec(),
    )?;

    let body: SignInBody = parse_request_body(&request)?;

    assert_eq!(
        body,
        SignInBody {
            email: "ada@example.com".to_owned(),
            password: "secret".to_owned(),
            remember_me: Some(false),
        }
    );
    Ok(())
}

#[test]
fn parse_request_body_accepts_urlencoded_form_values() -> Result<(), Box<dyn std::error::Error>> {
    let request = request(
        "application/x-www-form-urlencoded",
        b"email=ada%2Btest%40example.com&password=two+words&rememberMe=true".to_vec(),
    )?;

    let body: SignInBody = parse_request_body(&request)?;

    assert_eq!(
        body,
        SignInBody {
            email: "ada+test@example.com".to_owned(),
            password: "two words".to_owned(),
            remember_me: Some(true),
        }
    );
    Ok(())
}

#[test]
fn parse_request_body_collects_repeated_urlencoded_form_values(
) -> Result<(), Box<dyn std::error::Error>> {
    let request = request(
        "application/x-www-form-urlencoded",
        b"resource=https%3A%2F%2Fapi.example.com&resource=https%3A%2F%2Ffiles.example.com".to_vec(),
    )?;

    let body: RepeatedBody = parse_request_body(&request)?;

    assert_eq!(
        body,
        RepeatedBody {
            resource: vec![
                "https://api.example.com".to_owned(),
                "https://files.example.com".to_owned(),
            ],
        }
    );
    Ok(())
}

#[test]
fn parse_request_body_rejects_unsupported_content_type() -> Result<(), Box<dyn std::error::Error>> {
    let request = request("text/plain", b"email=ada@example.com".to_vec())?;

    let error = parse_request_body::<SignInBody>(&request).err();

    assert!(matches!(
        error,
        Some(RustAuthError::UnsupportedContentType { content_type }) if content_type == "text/plain"
    ));
    Ok(())
}

#[test]
fn parse_request_body_rejects_malformed_json() -> Result<(), Box<dyn std::error::Error>> {
    let request = request("application/json", b"{not-json".to_vec())?;

    let error = parse_request_body::<SignInBody>(&request).err();

    assert!(matches!(
        error,
        Some(RustAuthError::InvalidRequestBody {
            encoding: "JSON",
            ..
        })
    ));
    Ok(())
}

#[test]
fn parse_request_body_rejects_malformed_form_encoding() -> Result<(), Box<dyn std::error::Error>> {
    let request = request("application/x-www-form-urlencoded", b"email=%ZZ".to_vec())?;

    let error = parse_request_body::<SignInBody>(&request).err();

    assert!(matches!(
        error,
        Some(RustAuthError::InvalidRequestBody {
            encoding: "form",
            ..
        })
    ));
    Ok(())
}

fn request(content_type: &str, body: Vec<u8>) -> Result<ApiRequest, http::Error> {
    Request::builder()
        .method("POST")
        .uri("http://localhost:3000/api/auth/sign-in/email")
        .header(http::header::CONTENT_TYPE, content_type)
        .body(body)
}
