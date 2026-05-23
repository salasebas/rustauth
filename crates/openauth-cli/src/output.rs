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
