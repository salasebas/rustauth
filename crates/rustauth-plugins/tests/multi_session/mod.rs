mod common;
mod endpoints;
mod hooks;

use rustauth_plugins::multi_session::UPSTREAM_PLUGIN_ID;

#[test]
fn exposes_multi_session_plugin_id() {
    assert_eq!(UPSTREAM_PLUGIN_ID, "multi-session");
}
