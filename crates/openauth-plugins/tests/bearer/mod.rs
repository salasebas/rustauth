mod common;
mod flow;
mod headers;
mod options;

#[test]
fn exposes_bearer_plugin_metadata() {
    let plugin = openauth_plugins::bearer::bearer();

    assert_eq!(openauth_plugins::bearer::UPSTREAM_PLUGIN_ID, "bearer");
    assert_eq!(plugin.id, "bearer");
    assert_eq!(plugin.version.as_deref(), Some(openauth_plugins::VERSION));
}
