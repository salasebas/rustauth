use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = rustauth_example_full_app::ExampleConfig::from_env()?;
    let addr = config.socket_addr()?;
    let app = rustauth_example_full_app::build_app(config).await?;
    let listener = TcpListener::bind(addr).await?;

    println!("RustAuth full app example listening on http://{addr}");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;

    Ok(())
}
