//! Small shared utilities.

pub mod fetch_metadata;
pub mod host;
pub mod ip;
pub mod url;

/// Capitalize the first Unicode scalar value in a string.
pub fn capitalize_first_letter(value: &str) -> String {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return String::new();
    };

    first.to_uppercase().collect::<String>() + chars.as_str()
}
