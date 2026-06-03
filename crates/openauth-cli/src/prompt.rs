use inquire::Confirm;

use crate::app::AppError;

pub fn confirm(message: &str, yes: bool) -> Result<bool, AppError> {
    if yes || !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return Ok(true);
    }
    Confirm::new(message)
        .with_default(false)
        .prompt()
        .map_err(|error| AppError::Message(format!("prompt failed: {error}")))
}
