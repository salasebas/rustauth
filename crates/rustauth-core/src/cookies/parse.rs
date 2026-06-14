use std::collections::BTreeMap;

use super::types::{CookieOptions, ParsedCookie};

pub fn parse_cookies(cookie_header: &str) -> BTreeMap<String, String> {
    let mut cookies = BTreeMap::new();
    for pair in cookie_header.split("; ") {
        if let Some((name, value)) = pair.split_once('=') {
            cookies.insert(name.to_owned(), value.to_owned());
        }
    }
    cookies
}

/// Read the session token cookie from a request `Cookie` header.
pub fn parse_set_cookie_header(set_cookie: &str) -> BTreeMap<String, ParsedCookie> {
    let mut cookies = BTreeMap::new();
    for cookie in split_set_cookie_header(set_cookie) {
        let parts = cookie.split(';').map(str::trim).collect::<Vec<_>>();
        let Some(name_value) = parts.first() else {
            continue;
        };
        let Some((name, value)) = name_value.split_once('=') else {
            continue;
        };
        if name.is_empty() {
            continue;
        }

        let mut parsed = ParsedCookie {
            value: percent_decode(value),
            ..ParsedCookie::default()
        };
        for attribute in parts.iter().skip(1) {
            let (attribute_name, attribute_value) = attribute
                .split_once('=')
                .map_or((*attribute, ""), |(name, value)| (name, value));
            match attribute_name.trim().to_ascii_lowercase().as_str() {
                "max-age" => parsed.max_age = attribute_value.trim().parse::<u64>().ok(),
                "expires" => parsed.expires = Some(attribute_value.trim().to_owned()),
                "domain" => parsed.domain = Some(attribute_value.trim().to_owned()),
                "path" => parsed.path = Some(attribute_value.trim().to_owned()),
                "secure" => parsed.secure = Some(true),
                "httponly" => parsed.http_only = Some(true),
                "samesite" => parsed.same_site = Some(attribute_value.trim().to_ascii_lowercase()),
                "partitioned" => parsed.partitioned = Some(true),
                _ => {}
            }
        }
        cookies.insert(name.to_owned(), parsed);
    }
    cookies
}

fn split_set_cookie_header(set_cookie: &str) -> Vec<String> {
    if set_cookie.is_empty() {
        return Vec::new();
    }
    let mut result = Vec::new();
    let mut start = 0;
    let mut index = 0;
    let bytes = set_cookie.as_bytes();
    while index < bytes.len() {
        if bytes[index] == b',' {
            let mut cursor = index + 1;
            while cursor < bytes.len() && bytes[cursor] == b' ' {
                cursor += 1;
            }
            while cursor < bytes.len()
                && bytes[cursor] != b'='
                && bytes[cursor] != b';'
                && bytes[cursor] != b','
            {
                cursor += 1;
            }
            if cursor < bytes.len() && bytes[cursor] == b'=' {
                let part = set_cookie[start..index].trim();
                if !part.is_empty() {
                    result.push(part.to_owned());
                }
                start = index + 1;
                while start < bytes.len() && bytes[start] == b' ' {
                    start += 1;
                }
                index = start;
                continue;
            }
        }
        index += 1;
    }
    let last = set_cookie[start..].trim();
    if !last.is_empty() {
        result.push(last.to_owned());
    }
    result
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (from_hex(bytes[index + 1]), from_hex(bytes[index + 2])) {
                output.push((hi << 4) | lo);
                index += 3;
                continue;
            }
        }
        output.push(bytes[index]);
        index += 1;
    }
    String::from_utf8(output).unwrap_or_else(|_| value.to_owned())
}

fn from_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub fn to_cookie_options(attributes: &ParsedCookie) -> CookieOptions {
    CookieOptions {
        max_age: attributes.max_age,
        expires: attributes.expires.clone(),
        domain: attributes.domain.clone(),
        path: attributes.path.clone(),
        secure: attributes.secure,
        http_only: attributes.http_only,
        same_site: attributes.same_site.clone(),
        partitioned: attributes.partitioned,
    }
}
