use serde::{Deserialize, Serialize};

use openauth_core::crypto::jwt::{sign_jwt, verify_jwt};

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Claims {
    sub: String,
}

#[test]
fn verify_jwt_accepts_token_signed_with_same_secret() -> Result<(), Box<dyn std::error::Error>> {
    let token = sign_jwt(
        &Claims {
            sub: "user_123".to_owned(),
        },
        "secret-a-at-least-32-chars-long!!",
        3600,
    )?;

    let claims = verify_jwt::<Claims>(&token, "secret-a-at-least-32-chars-long!!")?;

    assert_eq!(
        claims,
        Some(Claims {
            sub: "user_123".to_owned()
        })
    );
    Ok(())
}

#[test]
fn verify_jwt_rejects_token_signed_with_different_secret() -> Result<(), Box<dyn std::error::Error>>
{
    let token = sign_jwt(
        &Claims {
            sub: "user_123".to_owned(),
        },
        "secret-a-at-least-32-chars-long!!",
        3600,
    )?;

    let claims = verify_jwt::<Claims>(&token, "secret-b-at-least-32-chars-long!!")?;

    assert_eq!(claims, None);
    Ok(())
}

#[test]
fn verify_jwt_rejects_expired_token() -> Result<(), Box<dyn std::error::Error>> {
    let token = sign_jwt(
        &Claims {
            sub: "user_123".to_owned(),
        },
        "secret-a-at-least-32-chars-long!!",
        -1,
    )?;

    let claims = verify_jwt::<Claims>(&token, "secret-a-at-least-32-chars-long!!")?;

    assert_eq!(claims, None);
    Ok(())
}
