//! Parse `Accept-Language` per Better Auth i18n (`parseAcceptLanguage`).

/// Parse `Accept-Language` and return base language tags sorted by quality (highest first).
pub fn parse_accept_language(header: Option<&str>) -> Vec<String> {
    let Some(header) = header else {
        return Vec::new();
    };
    let mut entries: Vec<(String, f32)> = Vec::new();
    for part in header.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let mut segments = part.split(';');
        let locale_str = segments.next().unwrap_or("").trim();
        let quality_part = segments.next().unwrap_or("q=1").trim();
        let q = quality_part
            .strip_prefix("q=")
            .and_then(|v| v.parse::<f32>().ok())
            .unwrap_or(1.0);
        let locale = locale_str.split('-').next().unwrap_or("").trim().to_owned();
        if !locale.is_empty() {
            entries.push((locale, q));
        }
    }
    entries.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    entries.into_iter().map(|(locale, _)| locale).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_header() {
        assert!(parse_accept_language(None).is_empty());
        assert!(parse_accept_language(Some("")).is_empty());
    }

    #[test]
    fn quality_ordering() {
        let parsed = parse_accept_language(Some("es;q=0.9, fr;q=0.8, en;q=0.7"));
        assert_eq!(parsed, vec!["es", "fr", "en"]);
    }

    #[test]
    fn base_locale_from_region() {
        let parsed = parse_accept_language(Some("fr-CA"));
        assert_eq!(parsed, vec!["fr"]);
    }

    #[test]
    fn defaults_quality_to_one() {
        let parsed = parse_accept_language(Some("de"));
        assert_eq!(parsed, vec!["de"]);
    }

    #[test]
    fn invalid_quality_defaults_to_one() {
        let parsed = parse_accept_language(Some("fr;q=bogus, de;q=0.5"));
        assert_eq!(parsed, vec!["fr", "de"]);
    }
}
