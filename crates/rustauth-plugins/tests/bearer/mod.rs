mod common;
mod flow;
mod headers;
mod options;

#[test]
fn exposes_bearer_plugin_metadata() {
    let plugin =
        rustauth_plugins::bearer::bearer(rustauth_plugins::bearer::BearerOptions::default());

    assert_eq!(rustauth_plugins::bearer::UPSTREAM_PLUGIN_ID, "bearer");
    assert_eq!(plugin.id, "bearer");
    assert_eq!(plugin.version.as_deref(), Some(rustauth_plugins::VERSION));
}
