use inquire::Confirm;

use crate::app::AppError;

pub fn confirm(message: &str, yes: bool) -> Result<bool, AppError> {
    if yes {
        return Ok(true);
    }
    Confirm::new(message)
        .with_default(false)
        .prompt()
        .map_err(|error| AppError::Message(format!("prompt failed: {error}")))
}
