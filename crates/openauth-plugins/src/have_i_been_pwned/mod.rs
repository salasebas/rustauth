//! Have I Been Pwned password check plugin.

mod checker;
mod error;
mod options;
mod plugin;

pub use checker::{HaveIBeenPwnedCheckError, HaveIBeenPwnedChecker, ReqwestHaveIBeenPwnedChecker};
pub use error::{PASSWORD_COMPROMISED_CODE, PASSWORD_COMPROMISED_MESSAGE};
pub use options::HaveIBeenPwnedOptions;
pub use plugin::{
    have_i_been_pwned, have_i_been_pwned_with, RUNTIME_PLUGIN_ID, UPSTREAM_PLUGIN_ID,
};
