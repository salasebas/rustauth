//! Trusted origin matching.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OriginMatchSettings {
    pub allow_relative_paths: bool,
}

/// Match a URL against an origin or origin pattern.
pub fn matches_origin_pattern(
    url: &str,
    pattern: &str,
    settings: Option<OriginMatchSettings>,
) -> bool {
    if url.starts_with('/') {
        return settings
            .is_some_and(|settings| settings.allow_relative_paths && is_safe_relative_path(url));
    }

    let has_wildcard = pattern.contains('*') || pattern.contains('?');
    if has_wildcard {
        if pattern.contains("://") {
            return wildcard_match(pattern, url)
                || origin_from_url(url).is_some_and(|origin| wildcard_match(pattern, &origin));
        }
        return host_from_url(url).is_some_and(|host| wildcard_match(pattern, &host));
    }

    match protocol_from_url(url).as_deref() {
        Some("http") | Some("https") | None => {
            origin_from_url(url).is_some_and(|origin| origin == pattern)
        }
        Some(_) => url.starts_with(pattern),
    }
}

fn is_safe_relative_path(path: &str) -> bool {
    if !path.starts_with('/') || path.starts_with("//") || path.starts_with("/\\") {
        return false;
    }
    let lowercase = path.to_ascii_lowercase();
    if lowercase.contains("%2f")
        || lowercase.contains("%5c")
        || lowercase.starts_with("javascript:")
        || lowercase.starts_with("data:")
    {
        return false;
    }
    path.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'/' | b'?' | b'&' | b'=' | b'%' | b'@' | b'.' | b'-' | b'_' | b'+'
            )
    })
}

fn protocol_from_url(url: &str) -> Option<String> {
    url.split_once("://")
        .map(|(protocol, _)| protocol.to_owned())
}

fn host_from_url(url: &str) -> Option<String> {
    let (_, rest) = url.split_once("://")?;
    let host = rest.split('/').next().unwrap_or(rest);
    let host = host.split('?').next().unwrap_or(host);
    (!host.is_empty()).then(|| host.to_owned())
}

fn origin_from_url(url: &str) -> Option<String> {
    let (protocol, rest) = url.split_once("://")?;
    let host = rest.split('/').next().unwrap_or(rest);
    let host = host.split('?').next().unwrap_or(host);
    (!host.is_empty()).then(|| format!("{protocol}://{host}"))
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    wildcard_match_bytes(pattern.as_bytes(), value.as_bytes())
}

fn wildcard_match_bytes(pattern: &[u8], value: &[u8]) -> bool {
    let (mut pattern_index, mut value_index) = (0, 0);
    let mut star_index = None;
    let mut match_index = 0;

    while value_index < value.len() {
        if pattern_index < pattern.len()
            && (pattern[pattern_index] == b'?' || pattern[pattern_index] == value[value_index])
        {
            pattern_index += 1;
            value_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
            star_index = Some(pattern_index);
            match_index = value_index;
            pattern_index += 1;
        } else if let Some(star) = star_index {
            pattern_index = star + 1;
            match_index += 1;
            value_index = match_index;
        } else {
            return false;
        }
    }

    while pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
        pattern_index += 1;
    }

    pattern_index == pattern.len()
}
