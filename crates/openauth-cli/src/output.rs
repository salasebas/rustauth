use std::process::{Command, Stdio};

use serde::Serialize;

use crate::app::AppError;

pub fn print_json<T>(value: &T) -> Result<(), AppError>
where
    T: Serialize,
{
    let rendered = serde_json::to_string_pretty(value)?;
    println!("{rendered}");
    Ok(())
}

pub fn copy_to_clipboard(text: &str) -> Result<(), AppError> {
    #[cfg(target_os = "macos")]
    {
        let mut child = Command::new("pbcopy")
            .stdin(Stdio::piped())
            .spawn()
            .map_err(|source| AppError::Io {
                context: "failed to run pbcopy".to_owned(),
                source,
            })?;
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write as _;
            stdin
                .write_all(text.as_bytes())
                .map_err(|source| AppError::Io {
                    context: "failed to write to pbcopy".to_owned(),
                    source,
                })?;
        }
        let status = child.wait().map_err(|source| AppError::Io {
            context: "failed to wait for pbcopy".to_owned(),
            source,
        })?;
        if status.success() {
            return Ok(());
        }
    }

    #[cfg(target_os = "linux")]
    {
        for (program, args) in [
            ("xclip", ["-selection", "clipboard"]),
            ("xsel", ["--clipboard", "--input"]),
        ] {
            if try_clipboard_command(program, &args, text) {
                return Ok(());
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        let mut child = Command::new("cmd")
            .args(["/C", "clip"])
            .stdin(Stdio::piped())
            .spawn()
            .map_err(|source| AppError::Io {
                context: "failed to run clip".to_owned(),
                source,
            })?;
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write as _;
            stdin
                .write_all(text.as_bytes())
                .map_err(|source| AppError::Io {
                    context: "failed to write to clip".to_owned(),
                    source,
                })?;
        }
        let status = child.wait().map_err(|source| AppError::Io {
            context: "failed to wait for clip".to_owned(),
            source,
        })?;
        if status.success() {
            return Ok(());
        }
    }

    Err(AppError::Message(
        "Could not copy to clipboard (install pbcopy, xclip, or xsel).".to_owned(),
    ))
}

#[cfg(target_os = "linux")]
fn try_clipboard_command(program: &str, args: &[&str], text: &str) -> bool {
    let Ok(mut child) = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write as _;
        if stdin.write_all(text.as_bytes()).is_err() {
            return false;
        }
    }
    child.wait().ok().is_some_and(|status| status.success())
}
