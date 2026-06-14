use std::collections::BTreeMap;

use crate::utils::url::normalize_pathname;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathParams(BTreeMap<String, String>);

impl PathParams {
    pub fn new(params: BTreeMap<String, String>) -> Self {
        Self(params)
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub(super) fn match_path_pattern(pattern: &str, path: &str) -> Option<BTreeMap<String, String>> {
    if pattern == path {
        return Some(BTreeMap::new());
    }
    let pattern_segments = route_segments(pattern);
    let path_segments = route_segments(path);
    if pattern_segments.len() != path_segments.len() {
        return None;
    }
    let mut params = BTreeMap::new();
    for (pattern, value) in pattern_segments.into_iter().zip(path_segments) {
        if let Some(name) = pattern.strip_prefix(':') {
            if name.is_empty() || value.is_empty() {
                return None;
            }
            params.insert(name.to_owned(), percent_decode_path_segment(value));
        } else if pattern != value {
            return None;
        }
    }
    Some(params)
}

fn route_segments(value: &str) -> Vec<&str> {
    let value = value.strip_prefix('/').unwrap_or(value);
    if value.is_empty() {
        Vec::new()
    } else {
        value.split('/').collect()
    }
}

fn percent_decode_path_segment(value: &str) -> String {
    let mut decoded = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let high = hex_value(bytes[index + 1]);
                let low = hex_value(bytes[index + 2]);
                if let (Some(high), Some(low)) = (high, low) {
                    decoded.push((high << 4) | low);
                    index += 3;
                } else {
                    decoded.push(bytes[index]);
                    index += 1;
                }
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(decoded).unwrap_or_else(|_| value.to_owned())
}

pub(super) fn path_matches(pattern: &str, path: &str) -> bool {
    if let Some((prefix, suffix)) = pattern.split_once('*') {
        return path.starts_with(prefix) && path.ends_with(suffix);
    }
    pattern == path
}

pub(super) fn route_pathname(
    request_url: &str,
    base_path: &str,
    skip_trailing_slashes: bool,
) -> String {
    if skip_trailing_slashes {
        return normalize_pathname(request_url, base_path);
    }

    let Some(pathname) = pathname_from_url(request_url) else {
        return "/".to_owned();
    };
    let base_path = trim_trailing_slashes(base_path);

    if base_path == "/" {
        return pathname;
    }
    if pathname == base_path {
        return "/".to_owned();
    }

    let base_prefix = format!("{base_path}/");
    if let Some(without_base_path) = pathname.strip_prefix(&base_prefix) {
        format!("/{without_base_path}")
    } else {
        pathname
    }
}

fn pathname_from_url(request_url: &str) -> Option<String> {
    if request_url.starts_with('/') {
        let path = request_url
            .split_once('?')
            .map_or(request_url, |(path, _)| path);
        let path = path.split_once('#').map_or(path, |(path, _)| path);
        return Some(path.to_owned());
    }
    let (_, after_scheme) = request_url.split_once("://")?;
    let path_start = after_scheme.find('/')?;
    let path_with_query = &after_scheme[path_start..];
    let path = path_with_query
        .split_once('?')
        .map_or(path_with_query, |(path, _)| path);
    let path = path.split_once('#').map_or(path, |(path, _)| path);

    Some(path.to_owned())
}

fn trim_trailing_slashes(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_owned()
    } else if trimmed.starts_with('/') {
        trimmed.to_owned()
    } else {
        format!("/{trimmed}")
    }
}
