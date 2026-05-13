//! Minimal `Cookie` header parsing for locale lookup.

use openauth_core::cookies::parse_cookies;

/// Returns the value for the first cookie named `name`, if present.
pub fn cookie_value(cookie_header: Option<&str>, name: &str) -> Option<String> {
    let header = cookie_header?;
    parse_cookies(header).remove(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_named_cookie() {
        assert_eq!(
            cookie_value(Some("lang=fr; other=1"), "lang").as_deref(),
            Some("fr")
        );
    }

    #[test]
    fn missing_returns_none() {
        assert_eq!(cookie_value(Some("a=b"), "lang"), None);
    }

    #[test]
    fn preserves_values_containing_equals() {
        assert_eq!(
            cookie_value(Some("lang=fr=CA; other=1"), "lang").as_deref(),
            Some("fr=CA")
        );
    }
}
