use openauth_core::db::User;
use serde_json::{json, Map, Value};

pub fn user_claims(user: &User, scopes: &[String]) -> Map<String, Value> {
    let mut claims = Map::new();
    claims.insert("sub".to_owned(), json!(user.id));
    if scopes.iter().any(|scope| scope == "profile") {
        let mut parts = user.name.split_whitespace();
        claims.insert("name".to_owned(), json!(user.name));
        claims.insert("given_name".to_owned(), json!(parts.next()));
        claims.insert("family_name".to_owned(), json!(parts.next()));
        claims.insert("profile".to_owned(), json!(user.image));
        claims.insert("picture".to_owned(), json!(user.image));
        claims.insert(
            "updated_at".to_owned(),
            json!(user.updated_at.unix_timestamp()),
        );
    }
    if scopes.iter().any(|scope| scope == "email") {
        claims.insert("email".to_owned(), json!(user.email));
        claims.insert("email_verified".to_owned(), json!(user.email_verified));
    }
    claims
}
