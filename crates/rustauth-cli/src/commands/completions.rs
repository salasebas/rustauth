use std::io;

use clap::CommandFactory;

use crate::app::{AppError, Cli, CompletionsArgs};

pub fn run(args: CompletionsArgs) -> Result<(), AppError> {
    let mut command = Cli::command();
    let name = command.get_name().to_owned();
    clap_complete::generate(args.shell, &mut command, name, &mut io::stdout());
    Ok(())
}
