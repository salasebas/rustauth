/// Password policy configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordOptions {
    pub min_password_length: usize,
    pub max_password_length: usize,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            min_password_length: 8,
            max_password_length: 128,
        }
    }
}
