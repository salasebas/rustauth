use std::collections::BTreeMap;

use super::parse::parse_cookies;
use super::types::{Cookie, CookieOptions};

const ALLOWED_COOKIE_SIZE: usize = 4096;
const ESTIMATED_EMPTY_COOKIE_SIZE: usize = 200;
const CHUNK_SIZE: usize = ALLOWED_COOKIE_SIZE - ESTIMATED_EMPTY_COOKIE_SIZE;

#[derive(Debug, Clone)]
pub struct ChunkedCookieStore {
    cookie_name: String,
    cookie_options: CookieOptions,
    chunks: BTreeMap<String, String>,
    direct_value: Option<String>,
}

impl ChunkedCookieStore {
    pub fn new(
        cookie_name: impl Into<String>,
        cookie_options: CookieOptions,
        header: &str,
    ) -> Self {
        let cookie_name = cookie_name.into();
        let parsed = parse_cookies(header);
        let direct_value = parsed.get(&cookie_name).cloned();
        let prefix = format!("{cookie_name}.");
        let chunks = parsed
            .into_iter()
            .filter(|(name, _)| name.starts_with(&prefix))
            .collect();
        Self {
            cookie_name,
            cookie_options,
            chunks,
            direct_value,
        }
    }

    pub fn value(&self) -> Option<String> {
        if let Some(value) = &self.direct_value {
            return Some(value.clone());
        }
        if self.chunks.is_empty() {
            return None;
        }
        let mut chunks = self
            .chunks
            .iter()
            .filter_map(|(name, value)| chunk_index(name).map(|index| (index, value)))
            .collect::<Vec<_>>();
        chunks.sort_by_key(|(index, _)| *index);
        Some(
            chunks
                .into_iter()
                .map(|(_, value)| value.as_str())
                .collect(),
        )
    }

    pub fn chunk(&self, value: &str) -> Vec<Cookie> {
        if value.len() <= CHUNK_SIZE {
            return vec![Cookie {
                name: self.cookie_name.clone(),
                value: value.to_owned(),
                attributes: self.cookie_options.clone(),
            }];
        }
        value
            .as_bytes()
            .chunks(CHUNK_SIZE)
            .enumerate()
            .map(|(index, chunk)| Cookie {
                name: format!("{}.{}", self.cookie_name, index),
                value: String::from_utf8_lossy(chunk).into_owned(),
                attributes: self.cookie_options.clone(),
            })
            .collect()
    }

    pub fn clean(&self) -> Vec<Cookie> {
        self.chunks
            .keys()
            .map(|name| {
                let mut attributes = self.cookie_options.clone();
                attributes.max_age = Some(0);
                Cookie {
                    name: name.clone(),
                    value: String::new(),
                    attributes,
                }
            })
            .collect()
    }
}

fn chunk_index(cookie_name: &str) -> Option<usize> {
    cookie_name.rsplit_once('.')?.1.parse().ok()
}
