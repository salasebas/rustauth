/// Returns true for browser fetch requests with `Sec-Fetch-Mode: cors`.
pub fn is_browser_fetch_request(sec_fetch_mode: Option<&str>) -> bool {
    sec_fetch_mode.is_some_and(|mode| mode.eq_ignore_ascii_case("cors"))
}
