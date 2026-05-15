use crate::error::OpenAuthError;

use super::{
    PluginDatabaseAfterInput, PluginDatabaseBeforeAction, PluginDatabaseBeforeInput,
    PluginDatabaseOperation,
};

pub(super) fn mismatched_before_input(
    expected: PluginDatabaseOperation,
    actual: PluginDatabaseBeforeInput,
) -> Result<PluginDatabaseBeforeAction, OpenAuthError> {
    Err(OpenAuthError::InvalidConfig(format!(
        "database before hook expected {expected:?} input but received {:?}",
        actual.operation()
    )))
}

pub(super) fn mismatched_after_input(
    expected: PluginDatabaseOperation,
    actual: &PluginDatabaseAfterInput,
) -> Result<(), OpenAuthError> {
    Err(OpenAuthError::InvalidConfig(format!(
        "database after hook expected {expected:?} input but received {:?}",
        actual.operation()
    )))
}
