use inquire::Confirm;

use crate::app::AppError;

const NON_INTERACTIVE_YES_REQUIRED: &str =
    "Non-interactive session: pass --yes (or -y) to run this command in CI or scripts.";

pub fn confirm(message: &str, yes: bool) -> Result<bool, AppError> {
    if yes {
        return Ok(true);
    }
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return Err(AppError::Message(NON_INTERACTIVE_YES_REQUIRED.to_owned()));
    }
    Confirm::new(message)
        .with_default(false)
        .prompt()
        .map_err(|error| AppError::Message(format!("prompt failed: {error}")))
}
